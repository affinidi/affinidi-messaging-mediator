//! `file://?encrypt=1` envelope-encryption backend.
//!
//! Same on-disk shape as the plaintext [`super::file::FileStore`] — a
//! single JSON file at an operator-chosen path, owner-only `0600` on
//! unix — but every value is sealed with AES-256-GCM under a key
//! derived from a deployment-wide passphrase via Argon2id.
//!
//! Format (JSON, pretty):
//!
//! ```json
//! {
//!   "version": 2,
//!   "kdf": {
//!     "algo": "argon2id",
//!     "salt_b64": "<22-byte base64url salt>",
//!     "memory_kib": 65536,
//!     "iterations": 3,
//!     "parallelism": 4
//!   },
//!   "verifier_b64": "<AES-GCM seal of a 32-byte zero block, used as a
//!                    fast wrong-passphrase check at open time>",
//!   "verifier_nonce_b64": "<12-byte nonce for the verifier>",
//!   "entries": {
//!     "<key>": {
//!       "nonce_b64": "<12-byte base64url nonce>",
//!       "ciphertext_b64": "<AES-GCM(value || tag)>"
//!     }
//!   },
//!   "mac_b64": "<HMAC-SHA256 over everything above>"
//! }
//! ```
//!
//! Salt + KDF parameters are persisted in the file so the same
//! passphrase derives the same key on every open without round-trips.
//! Per-entry nonces are random per write — re-storing the same key
//! changes the ciphertext. The verifier lets the open path detect a
//! wrong passphrase up-front rather than on first `get` of a real
//! entry.
//!
//! **Integrity (version 2).** Each entry's AEAD binds it to its name, and
//! `mac_b64` — HMAC-SHA256 under a key derived (HKDF) from the passphrase
//! key — covers the version, the KDF parameters, the verifier and every
//! entry (name, nonce, ciphertext) in sorted order. Deleting an entry,
//! swapping in an older copy of one, or editing the header fails the open.
//! Both the verifier and entry AADs name the version, so a version 2 file
//! can't be passed off as a version 1 file (which has no MAC). Replacing
//! the *whole* file with an older copy is not detectable from the file
//! alone. Version 1 files (no MAC) are still read; they are rewritten as
//! version 2 by the next write.
//!
//! The on-disk KDF parameters are checked against fixed bounds before the
//! KDF runs, so an edited file can't make the mediator allocate gigabytes
//! at boot. The KDF and all file I/O run on tokio's blocking pool (open
//! through [`crate::secrets::store::open_store_async`]).
//!
//! Writes replace the file atomically (see [`super::fs_atomic`]). Only a
//! missing file starts a new store: an existing empty file is an error,
//! because that is what an interrupted write by an older release leaves.
//!
//! The passphrase is fetched in [`load_passphrase`] from the
//! `MEDIATOR_FILE_BACKEND_PASSPHRASE` env var (preferred for
//! containers) or the file pointed to by
//! `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE` (preferred when secrets
//! ship via a tmpfs / k8s Secret mount). The wizard's interactive
//! flow sets the env var before opening the store.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::secrets::backends::fs_atomic::write_atomic;
use crate::secrets::backends::run_blocking;
use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::{DynSecretStore, SecretStore};
use crate::secrets::url::BackendUrl;

const BACKEND_LABEL: &str = "file-encrypted";

/// Env var the mediator reads at boot to pick up the passphrase.
/// Mirror of the wizard CLI's `--passphrase-file` rendered as an env
/// var for container deployments.
pub const PASSPHRASE_ENV: &str = "MEDIATOR_FILE_BACKEND_PASSPHRASE";

/// Optional indirection for env-shy deployments — the named file is
/// read once at backend open and trimmed of trailing whitespace. Read
/// errors are surfaced verbatim so misconfigured paths are obvious.
pub const PASSPHRASE_FILE_ENV: &str = "MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE";

/// Argon2id parameters for new stores. Fixed (no auto-tuning) so an
/// operator can reproduce key derivation outside the mediator if they
/// need to recover entries by hand.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 4;
const KDF_KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const KDF_ALGO_LABEL: &str = "argon2id";

/// Bounds the on-disk KDF parameters must fall within before the KDF runs.
/// Wide enough for any store this backend has written (which all use the
/// constants above), narrow enough that an edited file can't demand
/// gigabytes of memory or minutes of CPU at boot.
const KDF_MEMORY_KIB_RANGE: std::ops::RangeInclusive<u32> = (8 * 1024)..=(1024 * 1024);
const KDF_ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = 1..=16;
const KDF_PARALLELISM_RANGE: std::ops::RangeInclusive<u32> = 1..=16;

/// The format version this build writes. Version 1 (no MAC, unversioned
/// AADs) is read and upgraded on the next write.
const CURRENT_VERSION: u32 = 2;

/// Plaintext fed through the verifier seal. 32 zero bytes — small,
/// fixed, and known to anybody who needs to recover the file by hand.
const VERIFIER_PLAINTEXT: [u8; 32] = [0u8; 32];

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::File { path, encrypted } = url else {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file backend received non-file URL".into(),
        ));
    };
    if !encrypted {
        return Err(SecretStoreError::Other(
            "internal error: encrypted file backend received plaintext URL".into(),
        ));
    }
    let passphrase = load_passphrase()?;
    let store = EncryptedFileStore::open(PathBuf::from(path), passphrase)?;
    Ok(Arc::new(store))
}

/// Read the passphrase from the standard env-var ladder. The order
/// matters: the file path wins so that a deployment can ship a
/// passphrase via tmpfs without leaking it into the process listing.
///
/// The env var is left set. Removing it (`std::env::remove_var`) is only
/// sound while no other thread reads the environment, and this runs on a
/// multi-threaded runtime (and in the wizard, which sets the variable
/// itself and may open the store more than once). Prefer
/// [`PASSPHRASE_FILE_ENV`] to keep the passphrase out of the environment.
fn load_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(path) = std::env::var(PASSPHRASE_FILE_ENV) {
        let raw = Zeroizing::new(fs::read_to_string(&path).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: std::io::Error::new(
                e.kind(),
                format!("could not read passphrase from {path}: {e}"),
            ),
        })?);
        let trimmed = Zeroizing::new(raw.trim().to_string());
        if trimmed.is_empty() {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!("{PASSPHRASE_FILE_ENV} pointed at {path}, but the file is empty"),
            });
        }
        return Ok(trimmed);
    }
    if let Ok(raw) = std::env::var(PASSPHRASE_ENV) {
        let raw = Zeroizing::new(raw);
        let trimmed = Zeroizing::new(raw.trim().to_string());
        if trimmed.is_empty() {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!("{PASSPHRASE_ENV} is set but empty"),
            });
        }
        return Ok(trimmed);
    }
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: format!(
            "file://?encrypt=1 requires a passphrase. Set {PASSPHRASE_ENV} (raw) or \
             {PASSPHRASE_FILE_ENV} (path to a file containing the passphrase). The \
             mediator-setup wizard configures one for you when you choose the encrypted \
             file backend."
        ),
    })
}

/// Persistent on-disk representation. The version field gates
/// migrations — see the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedStoreFile {
    version: u32,
    kdf: KdfParams,
    verifier_nonce_b64: String,
    verifier_b64: String,
    #[serde(default)]
    entries: BTreeMap<String, SealedEntry>,
    /// HMAC over the rest of the file (version 2 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    algo: String,
    salt_b64: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedEntry {
    nonce_b64: String,
    ciphertext_b64: String,
}

impl KdfParams {
    fn fresh() -> Result<(Self, [u8; SALT_BYTES])> {
        let mut salt = [0u8; SALT_BYTES];
        rand::rng()
            .try_fill_bytes(&mut salt)
            .map_err(|e| SecretStoreError::other(format!("salt generation failed: {e}")))?;
        Ok((
            Self {
                algo: KDF_ALGO_LABEL.into(),
                salt_b64: B64URL.encode(salt),
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
            },
            salt,
        ))
    }

    /// Refuse parameters outside the fixed bounds before running the KDF.
    fn check_bounds(&self) -> Result<()> {
        let bad = |what: &str, value: u32, range: &std::ops::RangeInclusive<u32>| {
            SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!(
                    "on-disk KDF {what} {value} is outside the accepted range {}..={}; the \
                     store file has been edited or is corrupt",
                    range.start(),
                    range.end()
                ),
            }
        };
        if !KDF_MEMORY_KIB_RANGE.contains(&self.memory_kib) {
            return Err(bad("memory_kib", self.memory_kib, &KDF_MEMORY_KIB_RANGE));
        }
        if !KDF_ITERATIONS_RANGE.contains(&self.iterations) {
            return Err(bad("iterations", self.iterations, &KDF_ITERATIONS_RANGE));
        }
        if !KDF_PARALLELISM_RANGE.contains(&self.parallelism) {
            return Err(bad("parallelism", self.parallelism, &KDF_PARALLELISM_RANGE));
        }
        Ok(())
    }

    fn salt(&self) -> Result<[u8; SALT_BYTES]> {
        if self.algo != KDF_ALGO_LABEL {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: format!(
                    "unsupported KDF algorithm '{}' on disk — only '{}' is implemented",
                    self.algo, KDF_ALGO_LABEL
                ),
            });
        }
        let raw = B64URL.decode(&self.salt_b64).map_err(|e| {
            SecretStoreError::other(format!("on-disk salt is not valid base64url: {e}"))
        })?;
        raw.try_into().map_err(|v: Vec<u8>| {
            SecretStoreError::other(format!(
                "on-disk salt is {} bytes; expected {}",
                v.len(),
                SALT_BYTES
            ))
        })
    }
}

fn derive_key(
    passphrase: &[u8],
    params: &KdfParams,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KDF_KEY_BYTES]>> {
    params.check_bounds()?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KDF_KEY_BYTES),
        )
        .map_err(|e| SecretStoreError::other(format!("invalid Argon2id params: {e}")))?,
    );
    let mut key = Zeroizing::new([0u8; KDF_KEY_BYTES]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|e| SecretStoreError::other(format!("Argon2id derivation failed: {e}")))?;
    Ok(key)
}

/// The key the file MAC is computed under: HKDF-SHA256 of the AEAD key,
/// so the two keys are independent.
fn derive_mac_key(key: &[u8; KDF_KEY_BYTES]) -> Zeroizing<[u8; 32]> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"mediator-file-encrypted-v2|file-mac", okm.as_mut_slice())
        .expect("HKDF expand into 32 bytes always succeeds");
    okm
}

fn random_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut n = [0u8; NONCE_BYTES];
    rand::rng()
        .try_fill_bytes(&mut n)
        .map_err(|e| SecretStoreError::other(format!("nonce generation failed: {e}")))?;
    Ok(n)
}

fn seal(
    key: &[u8; KDF_KEY_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_BYTES])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SecretStoreError::other(format!("AES-GCM invalid key: {e}")))?;
    let nonce_bytes = random_nonce()?;
    let nonce = Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| SecretStoreError::other(format!("AES-GCM seal failed: {e}")))?;
    Ok((ct, nonce_bytes))
}

fn open_aead(
    key: &[u8; KDF_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SecretStoreError::other(format!("AES-GCM invalid key: {e}")))?;
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| SecretStoreError::BackendUnavailable {
            backend: BACKEND_LABEL,
            reason: format!(
                "AES-GCM open failed: {e}. The on-disk file may have been written with a \
                 different passphrase, or the file has been tampered with."
            ),
        })
}

/// `mediator-file-encrypted-v1|verifier` for version 1, as before
/// versioning; each later version names itself.
fn verifier_aad(version: u32) -> Vec<u8> {
    format!("mediator-file-encrypted-v{version}|verifier").into_bytes()
}

fn entry_aad(version: u32, key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + key.len());
    aad.extend_from_slice(format!("mediator-file-encrypted-v{version}|entry|").as_bytes());
    aad.extend_from_slice(key.as_bytes());
    aad
}

fn decode_nonce(what: &str, b64: &str) -> Result<[u8; NONCE_BYTES]> {
    let raw = B64URL
        .decode(b64)
        .map_err(|e| SecretStoreError::other(format!("{what} nonce is not base64url: {e}")))?;
    raw.try_into().map_err(|v: Vec<u8>| {
        SecretStoreError::other(format!(
            "{what} nonce is {} bytes; expected {NONCE_BYTES}",
            v.len()
        ))
    })
}

/// Length-prefix `bytes` into `out`, so field boundaries can't shift.
fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl EncryptedStoreFile {
    /// Canonical bytes the file MAC covers: everything but the MAC.
    fn mac_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.entries.len() * 128);
        put_field(&mut out, b"mediator-file-encrypted|file-mac");
        out.extend_from_slice(&self.version.to_be_bytes());
        put_field(&mut out, self.kdf.algo.as_bytes());
        put_field(&mut out, self.kdf.salt_b64.as_bytes());
        out.extend_from_slice(&self.kdf.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.kdf.iterations.to_be_bytes());
        out.extend_from_slice(&self.kdf.parallelism.to_be_bytes());
        put_field(&mut out, self.verifier_nonce_b64.as_bytes());
        put_field(&mut out, self.verifier_b64.as_bytes());
        out.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        // BTreeMap iterates in sorted key order.
        for (name, entry) in &self.entries {
            put_field(&mut out, name.as_bytes());
            put_field(&mut out, entry.nonce_b64.as_bytes());
            put_field(&mut out, entry.ciphertext_b64.as_bytes());
        }
        out
    }

    fn mac(&self, mac_key: &[u8; 32]) -> HmacSha256 {
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(mac_key)
            .expect("HMAC-SHA256 accepts any 32-byte key");
        mac.update(&self.mac_input());
        mac
    }

    fn seal_mac(&mut self, mac_key: &[u8; 32]) {
        self.mac_b64 = Some(B64URL.encode(self.mac(mac_key).finalize().into_bytes()));
    }

    fn verify_mac(&self, mac_key: &[u8; 32], path: &std::path::Path) -> Result<()> {
        let tampered = |why: &str| SecretStoreError::BackendUnavailable {
            backend: BACKEND_LABEL,
            reason: format!(
                "encrypted store at {} failed its integrity check ({why}): entries were \
                 added, removed or replaced, or the header was edited, outside the mediator",
                path.display()
            ),
        };
        let Some(stored) = &self.mac_b64 else {
            return Err(tampered("the file MAC is missing"));
        };
        let stored = B64URL
            .decode(stored)
            .map_err(|_| tampered("the file MAC is not base64url"))?;
        // `verify_slice` compares in constant time.
        self.mac(mac_key)
            .verify_slice(&stored)
            .map_err(|_| tampered("the file MAC does not match"))
    }

    fn open_entry(&self, key: &[u8; KDF_KEY_BYTES], name: &str) -> Result<Option<Vec<u8>>> {
        let Some(sealed) = self.entries.get(name) else {
            return Ok(None);
        };
        let nonce = decode_nonce(&format!("entry '{name}'"), &sealed.nonce_b64)?;
        let ct = B64URL.decode(&sealed.ciphertext_b64).map_err(|e| {
            SecretStoreError::other(format!("entry '{name}' ciphertext is not b64: {e}"))
        })?;
        open_aead(key, &nonce, &ct, &entry_aad(self.version, name)).map(Some)
    }

    fn seal_entry(&mut self, key: &[u8; KDF_KEY_BYTES], name: &str, value: &[u8]) -> Result<()> {
        let (ct, nonce) = seal(key, value, &entry_aad(self.version, name))?;
        self.entries.insert(
            name.to_string(),
            SealedEntry {
                nonce_b64: B64URL.encode(nonce),
                ciphertext_b64: B64URL.encode(ct),
            },
        );
        Ok(())
    }

    /// Re-seal a version 1 store as the current version: new verifier and
    /// entries under the versioned AADs, plus the file MAC. In memory only;
    /// the next write persists it.
    fn upgraded(&self, key: &[u8; KDF_KEY_BYTES], mac_key: &[u8; 32]) -> Result<Self> {
        let (verifier_ct, verifier_nonce) =
            seal(key, &VERIFIER_PLAINTEXT, &verifier_aad(CURRENT_VERSION))?;
        let mut next = EncryptedStoreFile {
            version: CURRENT_VERSION,
            kdf: self.kdf.clone(),
            verifier_nonce_b64: B64URL.encode(verifier_nonce),
            verifier_b64: B64URL.encode(verifier_ct),
            entries: BTreeMap::new(),
            mac_b64: None,
        };
        for name in self.entries.keys() {
            let value = Zeroizing::new(
                self.open_entry(key, name)?
                    .expect("name comes from the entries map"),
            );
            next.seal_entry(key, name, &value)?;
        }
        next.seal_mac(mac_key);
        Ok(next)
    }
}

pub struct EncryptedFileStore {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    /// Cached derived key; never written to disk.
    key: Zeroizing<[u8; KDF_KEY_BYTES]>,
    /// Key for the file MAC, derived from `key`.
    mac_key: Zeroizing<[u8; 32]>,
    /// Cached on-disk state (without re-decrypting on every read). For a
    /// version 1 file this is already the upgraded form, written by the
    /// next write.
    state: Mutex<EncryptedStoreFile>,
}

impl EncryptedFileStore {
    /// Open (or, when the file is missing, create) the store. Blocking: runs
    /// the KDF and reads the file.
    fn open(path: PathBuf, passphrase: Zeroizing<String>) -> Result<Self> {
        let on_disk = match fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => {
                return Err(SecretStoreError::BackendUnavailable {
                    backend: BACKEND_LABEL,
                    reason: format!(
                        "encrypted store at {} exists but is empty. Only a missing file starts \
                         a new store: an empty one is what an interrupted write leaves, so \
                         its secrets are lost. Restore it from a backup, or delete it to \
                         start over with no secrets.",
                        path.display()
                    ),
                });
            }
            Ok(bytes) => {
                let parsed: EncryptedStoreFile =
                    serde_json::from_slice(&bytes).map_err(|e| SecretStoreError::Io {
                        backend: BACKEND_LABEL,
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to parse encrypted store {}: {e}", path.display()),
                        ),
                    })?;
                if !(1..=CURRENT_VERSION).contains(&parsed.version) {
                    return Err(SecretStoreError::BackendUnavailable {
                        backend: BACKEND_LABEL,
                        reason: format!(
                            "encrypted store at {} uses unsupported version {}; this build \
                             reads versions 1 to {CURRENT_VERSION}",
                            path.display(),
                            parsed.version
                        ),
                    });
                }
                Some(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(SecretStoreError::Io {
                    backend: BACKEND_LABEL,
                    source: e,
                });
            }
        };
        let Some(on_disk) = on_disk else {
            return init_new(path, &passphrase);
        };

        // Derive once from the on-disk salt + parameters (bounds-checked).
        let salt = on_disk.kdf.salt()?;
        let key = derive_key(passphrase.as_bytes(), &on_disk.kdf, &salt)?;
        let mac_key = derive_mac_key(&key);

        // Verifier check: a wrong passphrase derives a different key,
        // which makes the AEAD seal-of-zeros fail to open. Catch it
        // here rather than on first `get`.
        let nonce_bytes = decode_nonce("verifier", &on_disk.verifier_nonce_b64)?;
        let verifier_ct = B64URL
            .decode(&on_disk.verifier_b64)
            .map_err(|e| SecretStoreError::other(format!("verifier blob is not base64url: {e}")))?;
        let opened = open_aead(
            &key,
            &nonce_bytes,
            &verifier_ct,
            &verifier_aad(on_disk.version),
        )?;
        if opened != VERIFIER_PLAINTEXT {
            return Err(SecretStoreError::BackendUnavailable {
                backend: BACKEND_LABEL,
                reason: "verifier opened but its payload was unexpected — the on-disk file looks \
                         corrupt"
                    .into(),
            });
        }

        let state = if on_disk.version >= 2 {
            on_disk.verify_mac(&mac_key, &path)?;
            on_disk
        } else {
            tracing::info!(
                path = %path.display(),
                "encrypted store uses format version 1 (no file MAC); it is rewritten as \
                 version {CURRENT_VERSION} on the next write"
            );
            on_disk.upgraded(&key, &mac_key)?
        };

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                key,
                mac_key,
                state: Mutex::new(state),
            }),
        })
    }
}

fn init_new(path: PathBuf, passphrase: &Zeroizing<String>) -> Result<EncryptedFileStore> {
    let (kdf, salt) = KdfParams::fresh()?;
    let key = derive_key(passphrase.as_bytes(), &kdf, &salt)?;
    let mac_key = derive_mac_key(&key);
    let (verifier_ct, verifier_nonce) =
        seal(&key, &VERIFIER_PLAINTEXT, &verifier_aad(CURRENT_VERSION))?;
    let mut state = EncryptedStoreFile {
        version: CURRENT_VERSION,
        kdf,
        verifier_nonce_b64: B64URL.encode(verifier_nonce),
        verifier_b64: B64URL.encode(verifier_ct),
        entries: BTreeMap::new(),
        mac_b64: None,
    };
    state.seal_mac(&mac_key);
    // Persist immediately so subsequent opens find the same salt.
    write_atomic(BACKEND_LABEL, &path, &serde_json::to_vec_pretty(&state)?)?;
    Ok(EncryptedFileStore {
        inner: Arc::new(Inner {
            path,
            key,
            mac_key,
            state: Mutex::new(state),
        }),
    })
}

impl Inner {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, EncryptedStoreFile>> {
        self.state
            .lock()
            .map_err(|e| SecretStoreError::other(format!("encrypted file store poisoned: {e}")))
    }

    /// Write `next` and, only once that succeeded, make it the cached state.
    fn commit(&self, current: &mut EncryptedStoreFile, mut next: EncryptedStoreFile) -> Result<()> {
        next.seal_mac(&self.mac_key);
        write_atomic(
            BACKEND_LABEL,
            &self.path,
            &serde_json::to_vec_pretty(&next)?,
        )?;
        *current = next;
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.lock()?.open_entry(&self.key, key)
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut guard = self.lock()?;
        let mut next = guard.clone();
        next.seal_entry(&self.key, key, value)?;
        // Hold the lock across the write to keep the in-memory state
        // consistent with the on-disk file.
        self.commit(&mut guard, next)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self.lock()?;
        if !guard.entries.contains_key(key) {
            return Ok(());
        }
        let mut next = guard.clone();
        next.entries.remove(key);
        self.commit(&mut guard, next)
    }

    fn probe_readonly(&self) -> Result<()> {
        // Hold the state lock so the probe never races a write of this
        // process.
        let _guard = self.lock()?;
        let bytes = fs::read(&self.path).map_err(|e| SecretStoreError::Io {
            backend: BACKEND_LABEL,
            source: e,
        })?;
        let on_disk = serde_json::from_slice::<EncryptedStoreFile>(&bytes).map_err(|e| {
            SecretStoreError::Io {
                backend: BACKEND_LABEL,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse store file {}: {e}", self.path.display()),
                ),
            }
        })?;
        // The MAC check is cheap (no KDF) and catches a file edited since
        // open. A version 1 file has none until its first rewrite.
        if on_disk.version >= 2 {
            on_disk.verify_mac(&self.mac_key, &self.path)?;
        }
        Ok(())
    }
}

#[async_trait]
impl SecretStore for EncryptedFileStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    // Every key already lives in the one store object.
    fn is_single_object(&self) -> bool {
        true
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // In-memory decrypt only; no I/O, so no need for the blocking pool.
        self.inner.get(key)
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let key = key.to_string();
        let value = Zeroizing::new(value.to_vec());
        run_blocking(BACKEND_LABEL, move || inner.put(&key, &value)).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let key = key.to_string();
        run_blocking(BACKEND_LABEL, move || inner.delete(&key)).await
    }

    /// Re-read and parse the on-disk envelope so `/readyz` reflects the
    /// live file rather than the snapshot cached at `open()`, and check its
    /// MAC. This does NOT re-derive the Argon2 key or decrypt any entries —
    /// `open()` already verified the passphrase, and running the KDF on
    /// every poll would be a self-inflicted DoS. Unlike the plaintext
    /// backend, a missing file is an error here: `open()` would have
    /// created one, so its absence at runtime means the mount vanished.
    async fn probe_readonly(&self) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        run_blocking(BACKEND_LABEL, move || inner.probe_readonly()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;
    use tempfile::TempDir;

    /// Serialise env-var manipulation across the test suite. Tokio's
    /// runtime would nest if we tried to combine `#[tokio::test]` with
    /// `block_on`, so all tests are plain `#[test]` and we own a
    /// per-call current-thread runtime for the async work.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn url_for(path: &std::path::Path) -> BackendUrl {
        BackendUrl::File {
            path: path.to_string_lossy().into(),
            encrypted: true,
        }
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut)
    }

    fn pass(p: &str) -> Zeroizing<String> {
        Zeroizing::new(p.to_string())
    }

    fn read_file(path: &std::path::Path) -> EncryptedStoreFile {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_file(path: &std::path::Path, file: &EncryptedStoreFile) {
        fs::write(path, serde_json::to_vec_pretty(file).unwrap()).unwrap();
    }

    fn open_err(path: &std::path::Path, passphrase: &str) -> String {
        match EncryptedFileStore::open(path.to_path_buf(), pass(passphrase)) {
            Ok(_) => panic!("open must fail"),
            Err(e) => e.to_string(),
        }
    }

    /// A store as a release before format version 2 wrote it: unversioned
    /// AADs, no MAC.
    fn write_v1_store(path: &std::path::Path, passphrase: &str, entries: &[(&str, &[u8])]) {
        let (kdf, salt) = KdfParams::fresh().unwrap();
        let key = derive_key(passphrase.as_bytes(), &kdf, &salt).unwrap();
        let (verifier_ct, verifier_nonce) = seal(
            &key,
            &VERIFIER_PLAINTEXT,
            b"mediator-file-encrypted-v1|verifier",
        )
        .unwrap();
        let mut file = EncryptedStoreFile {
            version: 1,
            kdf,
            verifier_nonce_b64: B64URL.encode(verifier_nonce),
            verifier_b64: B64URL.encode(verifier_ct),
            entries: BTreeMap::new(),
            mac_b64: None,
        };
        for (name, value) in entries {
            let mut aad = b"mediator-file-encrypted-v1|entry|".to_vec();
            aad.extend_from_slice(name.as_bytes());
            let (ct, nonce) = seal(&key, value, &aad).unwrap();
            file.entries.insert(
                name.to_string(),
                SealedEntry {
                    nonce_b64: B64URL.encode(nonce),
                    ciphertext_b64: B64URL.encode(ct),
                },
            );
        }
        write_file(path, &file);
    }

    #[test]
    fn open_without_passphrase_errors_clearly() {
        let _g = env_lock();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let tmp = TempDir::new().unwrap();
        match open(url_for(&tmp.path().join("s.json"))) {
            Ok(_) => panic!("missing passphrase must error"),
            Err(SecretStoreError::BackendUnavailable { reason, .. }) => {
                assert!(
                    reason.contains("passphrase"),
                    "expected message to mention passphrase, got: {reason}"
                );
            }
            Err(other) => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn roundtrip_encrypts_and_persists() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple");
            std::env::remove_var(PASSPHRASE_FILE_ENV);
        }
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = open(url_for(&path)).unwrap();
        block_on(async {
            store
                .put("mediator_admin_credential", b"secret-bytes")
                .await
                .unwrap();
            let got = store.get("mediator_admin_credential").await.unwrap();
            assert_eq!(got.as_deref(), Some(&b"secret-bytes"[..]));
        });

        // Re-open with the same passphrase: data survives.
        let store2 = open(url_for(&path)).unwrap();
        block_on(async {
            let got = store2.get("mediator_admin_credential").await.unwrap();
            assert_eq!(got.as_deref(), Some(&b"secret-bytes"[..]));
        });

        // The on-disk bytes must not contain the plaintext.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("secret-bytes"),
            "plaintext leaked into the store file"
        );

        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
        }
    }

    #[test]
    fn wrong_passphrase_is_rejected_at_open_time() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("right-one")).unwrap();
        block_on(async { store.put("k", b"v").await.unwrap() });

        let err = open_err(&path, "WRONG-one");
        assert!(
            err.contains("AES-GCM open failed"),
            "expected AEAD failure, got: {err}"
        );
    }

    #[test]
    fn each_put_uses_a_fresh_nonce() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("nonce-test")).unwrap();
        block_on(async {
            store.put("k", b"same-value").await.unwrap();
            let raw1 = fs::read_to_string(&path).unwrap();
            store.put("k", b"same-value").await.unwrap();
            let raw2 = fs::read_to_string(&path).unwrap();
            assert_ne!(
                raw1, raw2,
                "rewriting the same key with the same plaintext must change the on-disk \
                 ciphertext (nonce reuse would be a critical AES-GCM bug)"
            );
        });
    }

    #[test]
    fn an_existing_empty_file_is_not_taken_for_a_new_store() {
        // A zero-length file is what an interrupted truncate-then-write left
        // behind. Treating it as a first run would mint a fresh salt and an
        // empty store over the lost one, looking like a clean start.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        fs::write(&path, b"").unwrap();
        let err = open_err(&path, "empty-file");
        assert!(err.contains("exists but is empty"), "got: {err}");
        assert_eq!(fs::read(&path).unwrap(), b"", "the file is left alone");
    }

    #[test]
    fn a_missing_file_starts_a_new_version_2_store() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("s.json");
        EncryptedFileStore::open(path.clone(), pass("fresh")).unwrap();
        let file = read_file(&path);
        assert_eq!(file.version, CURRENT_VERSION);
        assert!(file.mac_b64.is_some());
    }

    #[test]
    fn removing_an_entry_from_the_file_fails_the_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("integrity")).unwrap();
        block_on(async {
            store.put("a", b"a").await.unwrap();
            store.put("b", b"b").await.unwrap();
        });
        let mut file = read_file(&path);
        file.entries.remove("a");
        write_file(&path, &file);
        let err = open_err(&path, "integrity");
        assert!(err.contains("integrity check"), "got: {err}");
    }

    #[test]
    fn rolling_back_one_entry_fails_the_open() {
        // An older ciphertext of the same entry still decrypts under its
        // AAD; only the file MAC notices it was swapped in.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("rollback")).unwrap();
        block_on(async { store.put("jwt", b"old").await.unwrap() });
        let old = read_file(&path).entries["jwt"].clone();
        block_on(async { store.put("jwt", b"new").await.unwrap() });

        let mut file = read_file(&path);
        file.entries.insert("jwt".into(), old);
        write_file(&path, &file);
        let err = open_err(&path, "rollback");
        assert!(err.contains("integrity check"), "got: {err}");
    }

    #[test]
    fn a_version_2_file_cannot_pass_as_version_1() {
        // Stripping the MAC and claiming version 1 would skip the MAC check;
        // the versioned verifier AAD makes the open fail instead.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("downgrade")).unwrap();
        block_on(async { store.put("a", b"a").await.unwrap() });
        let mut file = read_file(&path);
        file.version = 1;
        file.mac_b64 = None;
        write_file(&path, &file);
        let err = open_err(&path, "downgrade");
        assert!(err.contains("AES-GCM open failed"), "got: {err}");
    }

    #[test]
    fn a_missing_mac_on_version_2_fails_the_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        EncryptedFileStore::open(path.clone(), pass("no-mac")).unwrap();
        let mut file = read_file(&path);
        file.mac_b64 = None;
        write_file(&path, &file);
        let err = open_err(&path, "no-mac");
        assert!(err.contains("MAC is missing"), "got: {err}");
    }

    #[test]
    fn a_version_1_store_is_read_and_upgraded_on_the_next_write() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        write_v1_store(&path, "legacy", &[("a", b"alpha"), ("b", b"beta")]);

        let store = EncryptedFileStore::open(path.clone(), pass("legacy")).unwrap();
        block_on(async {
            assert_eq!(
                store.get("a").await.unwrap().as_deref(),
                Some(&b"alpha"[..])
            );
            store.probe_readonly().await.unwrap();
        });
        assert_eq!(
            read_file(&path).version,
            1,
            "reading alone does not rewrite"
        );

        block_on(async { store.put("c", b"gamma").await.unwrap() });
        let file = read_file(&path);
        assert_eq!(file.version, CURRENT_VERSION);
        assert!(file.mac_b64.is_some());

        let reopened = EncryptedFileStore::open(path.clone(), pass("legacy")).unwrap();
        block_on(async {
            for (k, v) in [("a", &b"alpha"[..]), ("b", b"beta"), ("c", b"gamma")] {
                assert_eq!(reopened.get(k).await.unwrap().as_deref(), Some(v));
            }
        });
    }

    #[test]
    fn out_of_range_kdf_parameters_are_refused_before_the_kdf_runs() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        EncryptedFileStore::open(path.clone(), pass("kdf")).unwrap();
        let original = read_file(&path);

        for (field, value) in [
            ("memory_kib", 64 * 1024 * 1024),
            ("memory_kib", 1),
            ("iterations", 1_000_000),
            ("iterations", 0),
            ("parallelism", 4096),
        ] {
            let mut file = original.clone();
            match field {
                "memory_kib" => file.kdf.memory_kib = value,
                "iterations" => file.kdf.iterations = value,
                _ => file.kdf.parallelism = value,
            }
            write_file(&path, &file);
            let err = open_err(&path, "kdf");
            assert!(
                err.contains(field) && err.contains("outside the accepted range"),
                "{field}={value}: {err}"
            );
        }
    }

    #[test]
    fn a_failed_write_leaves_the_cached_state_unchanged() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("failed-write")).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        block_on(async {
            assert!(store.put("k", b"v").await.is_err());
            assert!(store.get("k").await.unwrap().is_none());
        });
    }

    #[test]
    fn probe_readonly_fails_when_file_vanishes_but_get_still_serves_cache() {
        // Deleting the file out from under a running store must fail the
        // read-only probe (mount lost), even though cached `get` still
        // answers from memory — that asymmetry is the whole point of the
        // override re-touching disk.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("vanish-test")).unwrap();
        block_on(async {
            store.probe_readonly().await.unwrap();
            fs::remove_file(&path).unwrap();
            assert!(
                store.probe_readonly().await.is_err(),
                "probe must fail once the on-disk file is gone"
            );
            // A never-written key still reads as absent from the cache.
            assert!(store.get("mediator_jwt_secret").await.unwrap().is_none());
        });
    }

    #[test]
    fn probe_readonly_fails_on_corrupt_or_tampered_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = EncryptedFileStore::open(path.clone(), pass("corrupt-test")).unwrap();
        block_on(async {
            store.put("a", b"a").await.unwrap();
            store.probe_readonly().await.unwrap();

            let mut file = read_file(&path);
            file.entries.clear();
            write_file(&path, &file);
            assert!(store.probe_readonly().await.is_err(), "tampered");

            fs::write(&path, b"{ not json").unwrap();
            assert!(store.probe_readonly().await.is_err(), "unparseable");
        });
    }

    #[test]
    fn probe_readonly_waits_for_an_in_flight_write() {
        // `put`/`delete` hold the state lock across the file write, and the
        // probe takes the same lock, so it waits for the writer rather than
        // judging the backend mid-write. Constructed directly (not via
        // `open`) so the test needs no env var and can reach `state` to
        // stand in for a writer.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        let store = Arc::new(EncryptedFileStore::open(path, pass("in-flight-write")).unwrap());

        let guard = store.inner.state.lock().unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let probe = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                block_on(store.probe_readonly())
            })
        };
        // The probe thread is running; without the lock it would finish in
        // microseconds, so still being unfinished after this pause is a
        // reliable signal that it is blocked on the writer.
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
