//! `file://` backend.
//!
//! Stores all entries as a single JSON object keyed by secret name at a
//! path the operator controls. Each value is a base64url string (so binary
//! envelopes survive JSON round-tripping).
//!
//! **Safety:** plaintext on disk by default — only sane for local dev/test
//! or as a target for envelope encryption (see Phase H — `?encrypt=1`).
//! The parent directory is created if missing; the file itself is written
//! with mode 0600 on unix to limit exposure to the owner.
//!
//! Writes replace the file atomically (temp file, `fsync`, `rename`, see
//! [`super::fs_atomic`]), so a crash mid-write leaves the previous store,
//! never a truncated one. A store file that exists but can't be read or
//! parsed fails every operation — a write never replaces it with a store
//! holding only the entry being written. File I/O runs on tokio's blocking
//! pool.
//!
//! Concurrent access: this backend assumes single-writer (per the HA
//! decision: mediator is single-writer; replicas should use a cloud
//! backend). Two processes racing on the same file risk lost writes — we
//! don't flock because file:// is dev/test territory anyway.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::secrets::backends::fs_atomic::write_atomic;
use crate::secrets::backends::run_blocking;
use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, SecretStore};
use crate::secrets::url::BackendUrl;

const BACKEND_LABEL: &str = "file";

pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    // Encrypted (`?encrypt=1`) URLs are routed by `store::open_store`
    // to `file_encrypted::open` *before* this function is called, so by
    // the time we get here `encrypted` must be false. We still match
    // exhaustively so the dispatcher contract is enforced — a future
    // mis-route would surface as a clear error rather than silently
    // bypassing encryption.
    let BackendUrl::File { path, encrypted } = url else {
        return Err(SecretStoreError::Other(
            "internal error: file backend received non-file URL".into(),
        ));
    };
    if encrypted {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file URL reached the plaintext backend".into(),
        ));
    }
    Ok(Arc::new(FileStore {
        inner: Arc::new(FileInner {
            path: PathBuf::from(path),
            state: Mutex::new(None),
        }),
    }))
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    /// Base64url-encoded entries, keyed by secret name.
    entries: BTreeMap<String, String>,
}

/// Names the entries, never their values.
impl std::fmt::Debug for StoreFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreFile")
            .field("entries", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Drop for StoreFile {
    fn drop(&mut self) {
        for value in self.entries.values_mut() {
            value.zeroize();
        }
    }
}

pub struct FileStore {
    inner: Arc<FileInner>,
}

struct FileInner {
    path: PathBuf,
    /// Cached contents from the last read/write. Rebuilt lazily on first
    /// access; kept in-memory thereafter so repeated reads don't re-hit
    /// disk.
    state: Mutex<Option<StoreFile>>,
}

impl FileInner {
    fn load_locked(&self) -> Result<StoreFile> {
        match fs::read(&self.path) {
            Ok(bytes) if bytes.is_empty() => Ok(StoreFile::default()),
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse store file {}: {e}", self.path.display()),
                ),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreFile::default()),
            Err(e) => Err(SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: e,
            }),
        }
    }

    fn save_locked(&self, file: &StoreFile) -> Result<()> {
        let body = zeroize::Zeroizing::new(serde_json::to_vec_pretty(file)?);
        write_atomic(BACKEND_LABEL, &self.path, &body)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<StoreFile>>> {
        self.state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("file store poisoned: {e}")))
    }

    /// The cached store, loading it on first use. A load error is returned
    /// (and nothing is cached), so a later write can't replace an unreadable
    /// file with a store holding only its own entry.
    fn loaded<'a>(
        &self,
        guard: &'a mut std::sync::MutexGuard<'_, Option<StoreFile>>,
    ) -> Result<&'a mut StoreFile> {
        if guard.is_none() {
            **guard = Some(self.load_locked()?);
        }
        Ok(guard.as_mut().expect("just initialised"))
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut guard = self.lock()?;
        let state = self.loaded(&mut guard)?;
        state
            .entries
            .get(key)
            .map(|b64| B64URL.decode(b64))
            .transpose()
            .map_err(|e| SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("entry '{key}' is not valid base64: {e}"),
                ),
            })
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut guard = self.lock()?;
        let state = self.loaded(&mut guard)?;
        let mut next = state.clone();
        next.entries.insert(key.to_string(), B64URL.encode(value));
        // The cache only moves once the file has.
        self.save_locked(&next)?;
        *state = next;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self.lock()?;
        let state = self.loaded(&mut guard)?;
        if !state.entries.contains_key(key) {
            return Ok(());
        }
        let mut next = state.clone();
        next.entries.remove(key);
        self.save_locked(&next)?;
        *state = next;
        Ok(())
    }

    fn probe_readonly(&self) -> Result<()> {
        // Hold the state lock across the read so the probe never races a
        // write of this process. Deliberately don't populate the cache from
        // what we read — the probe stays free of side effects.
        let _guard = self.lock()?;
        self.load_locked().map(|_| ())
    }
}

#[async_trait]
impl SecretStore for FileStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    // Every key already lives in the one store object.
    fn is_single_object(&self) -> bool {
        true
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let inner = Arc::clone(&self.inner);
        let key = key.to_string();
        run_blocking(BACKEND_LABEL, move || inner.get(&key)).await
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let key = key.to_string();
        let value = zeroize::Zeroizing::new(value.to_vec());
        run_blocking(BACKEND_LABEL, move || inner.put(&key, &value)).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let key = key.to_string();
        run_blocking(BACKEND_LABEL, move || inner.delete(&key)).await
    }

    /// Re-read the store file from disk without touching the in-memory
    /// cache, so `/readyz` reflects the live filesystem rather than the
    /// snapshot captured at `open()`. A missing file stays healthy
    /// (`load_locked` maps `NotFound` → default): first-run precedes
    /// provisioning, and setup tooling probes before writing anything,
    /// mirroring the absent-cloud-sentinel contract. Only unreadable or
    /// corrupt on-disk data returns `Err`.
    async fn probe_readonly(&self) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        run_blocking(BACKEND_LABEL, move || inner.probe_readonly()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn url_for(path: &std::path::Path) -> BackendUrl {
        BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: false,
        }
    }

    #[tokio::test]
    async fn roundtrip_survives_process_lifetime() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");

        let store = open(url_for(&path)).unwrap();
        store
            .put("mediator_admin_credential", b"hello")
            .await
            .unwrap();
        store.put("mediator_jwt_secret", b"world").await.unwrap();
        let got = store.get("mediator_admin_credential").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"hello" as &[u8]));

        // Second open on the same path sees persisted data.
        let store2 = open(url_for(&path)).unwrap();
        let got = store2.get("mediator_jwt_secret").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"world" as &[u8]));
    }

    #[tokio::test]
    async fn encrypted_url_misrouted_to_plaintext_backend_is_rejected() {
        // Sanity check on the dispatcher contract: if anything ever
        // routes an encrypted URL straight at this backend, it should
        // hard-fail rather than write plaintext to disk.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let url = BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: true,
        };
        match open(url) {
            Ok(_) => panic!("encrypted file:// must not open as plaintext"),
            Err(SecretStoreError::Other(msg)) => {
                assert!(msg.contains("encrypted file URL"), "wrong message: {msg}");
            }
            Err(other) => panic!("wrong error variant: {other}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let store = open(url_for(&path)).unwrap();
        store.put("mediator_jwt_secret", b"x").await.unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file:// must write owner-only");
    }

    #[tokio::test]
    async fn delete_of_missing_key_is_ok() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let store = open(url_for(&path)).unwrap();
        store.delete("does-not-exist").await.unwrap();
    }

    #[tokio::test]
    async fn a_write_never_replaces_an_unreadable_store() {
        // A corrupt store file (a partial write by an older release, a bad
        // hand edit) must fail the first put and delete rather than be
        // replaced by a store holding only the one entry being written,
        // which would drop the admin credential, JWT key and operating keys.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let corrupt = br#"{"entries": {"mediator_admin_credential": "abc""#;
        fs::write(&path, corrupt).unwrap();

        let store = open(url_for(&path)).unwrap();
        assert!(store.put("mediator_jwt_secret", b"x").await.is_err());
        assert!(store.delete("mediator_admin_credential").await.is_err());
        assert!(store.get("mediator_admin_credential").await.is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupt, "the file is untouched");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_write_never_replaces_a_store_it_cannot_read() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        fs::write(&path, br#"{"entries":{"a":"YQ"}}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root ignores the mode, so there is nothing to test.
        if fs::read(&path).is_ok() {
            return;
        }

        let store = open(url_for(&path)).unwrap();
        assert!(store.put("b", b"b").await.is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let store = open(url_for(&path)).unwrap();
        assert_eq!(store.get("a").await.unwrap().as_deref(), Some(&b"a"[..]));
        assert!(store.get("b").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_failed_write_leaves_the_cache_and_file_as_they_were() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("store");
        let path = dir.join("secrets.json");
        let store = open(url_for(&path)).unwrap();
        store.put("a", b"a").await.unwrap();

        // Make the next write fail: the target becomes a directory.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(store.put("b", b"b").await.is_err());
        assert!(
            store.get("b").await.unwrap().is_none(),
            "an entry whose write failed is not served from the cache"
        );
    }

    #[tokio::test]
    async fn probe_readonly_is_healthy_when_file_absent() {
        // No file on disk yet (pre-provisioning): must read as healthy.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        let store = open(url_for(&path)).unwrap();
        store.probe_readonly().await.unwrap();
    }

    #[tokio::test]
    async fn probe_readonly_fails_on_corrupt_file() {
        // A file present but unparseable must surface as Err — the probe
        // re-reads disk rather than trusting a cached snapshot.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.json");
        fs::write(&path, b"{ not json").unwrap();
        let store = open(url_for(&path)).unwrap();
        assert!(store.probe_readonly().await.is_err());
    }

    #[test]
    fn debug_never_prints_values() {
        let mut file = StoreFile::default();
        file.entries
            .insert("mediator_jwt_secret".into(), "c2VjcmV0LXZhbHVl".into());
        let printed = format!("{file:?}");
        assert!(printed.contains("mediator_jwt_secret"));
        assert!(!printed.contains("c2VjcmV0LXZhbHVl"));
    }

    #[test]
    fn probe_readonly_waits_for_an_in_flight_write() {
        // `put`/`delete` hold the state lock while they write the file. The
        // probe takes the same lock, so it waits for the writer instead of
        // judging the backend mid-write.
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(FileStore {
            inner: Arc::new(FileInner {
                path: tmp.path().join("secrets.json"),
                state: Mutex::new(None),
            }),
        });

        let guard = store.inner.state.lock().unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let probe = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(store.probe_readonly())
            })
        };
        // Unlocked, the probe would finish in microseconds.
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !probe.is_finished(),
            "probe_readonly must block while a writer holds the state lock"
        );

        drop(guard);
        probe
            .join()
            .unwrap()
            .expect("probe succeeds once the writer releases the lock");
    }
}
