//! Crash-safe file replacement shared by the `file://` backends.
//!
//! A store file is never truncated in place. The new contents go to a
//! sibling temp file (owner-only `0600` on unix), are flushed with
//! `sync_all`, and then `rename`d over the target, after which the parent
//! directory is fsynced so the rename itself survives a crash. A crash,
//! `SIGKILL` or `ENOSPC` at any point leaves either the old file or the new
//! one, never a zero-length or half-written one.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::secrets::error::{Result, SecretStoreError};

/// The temp file a write of `path` stages its contents in.
pub(crate) fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Replace `path` with `body` atomically. See the module docs.
pub(crate) fn write_atomic(backend: &'static str, path: &Path, body: &[u8]) -> Result<()> {
    let io = |source: std::io::Error| SecretStoreError::Io { backend, source };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(io)?;
    }

    let tmp = temp_path(path);
    // A temp file left by a crashed earlier write is stale: start over.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    let mut opts = fs::OpenOptions::new();
    // `create_new` so the 0600 mode applies: a pre-existing file would keep
    // whatever mode it had.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let written = (|| {
        let mut handle = opts.open(&tmp)?;
        handle.write_all(body)?;
        handle.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(io(e));
    }

    // Persist the rename. Directories can't be opened for fsync on every
    // platform (Windows), so this is unix-only.
    #[cfg(unix)]
    {
        let dir = parent.unwrap_or_else(|| Path::new("."));
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn replaces_the_file_and_leaves_no_temp_behind() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("s.json");
        write_atomic("test", &path, b"one").unwrap();
        write_atomic("test", &path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn a_stale_temp_file_is_replaced() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        fs::write(temp_path(&path), b"left by a crash").unwrap();
        write_atomic("test", &path, b"fresh").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn a_failed_write_leaves_the_old_file_intact() {
        // The target is a directory, so the rename fails after the temp
        // file was written: the old contents (here: the directory) stay,
        // and the temp file is cleaned up.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"x").unwrap();
        assert!(write_atomic("test", &path, b"new").is_err());
        assert!(path.join("keep").exists());
        assert!(!temp_path(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("s.json");
        // An existing world-readable file is replaced, not rewritten, so it
        // does not keep its mode.
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic("test", &path, b"new").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
