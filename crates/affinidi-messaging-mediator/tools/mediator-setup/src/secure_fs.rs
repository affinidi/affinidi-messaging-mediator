//! Crash-safe file writes for the wizard's outputs.
//!
//! Every file the wizard writes goes through one of two helpers here:
//!
//! - [`write_sensitive`] — anything holding key material, secret-backend
//!   URLs or DID material (`mediator.toml`, `admin-monitor.json`,
//!   `keys/end.key`, `did.jsonl`, the build recipe, …). The new contents are
//!   written to a temporary file created `0o600` in the same directory,
//!   fsynced, and renamed over the target, so the target is never
//!   world-readable — not even when a previous run (or the operator) left it
//!   `0o644` — and never half-written.
//! - [`write_public`] — content that is public by design (`Dockerfile`,
//!   `atm-functions.lua`, `docker-compose.yml`): the same temp + fsync +
//!   rename dance, with the process umask's default mode.
//!
//! Both refuse to write through a symlink: the wizard replaces the target
//! path itself, never a file a link happens to point at.
//!
//! [`create_private_dir_all`] creates the directories the wizard writes
//! into as `0o700` (only the ones it creates; an existing directory keeps
//! its mode).
//!
//! On non-Unix targets the permission bits are not applied (Windows ACLs
//! are a different model, and the wizard's threat model there assumes the
//! operator owns the directory); the atomic replace still is.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Mode bits applied to sensitive file writes on Unix.
#[cfg(unix)]
const SENSITIVE_MODE: u32 = 0o600;

/// Mode bits for directories the wizard creates.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;

/// Atomically replace `path` with `contents`, readable by the owner only
/// (`0o600` on Unix) whatever mode the previous file had. Refuses when
/// `path` is a symlink. The parent directory must exist.
pub fn write_sensitive<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    write_atomic(path.as_ref(), contents.as_ref(), true)
}

/// Atomically replace `path` with `contents` using the default file mode.
/// Refuses when `path` is a symlink. The parent directory must exist.
pub fn write_public<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    write_atomic(path.as_ref(), contents.as_ref(), false)
}

/// `create_dir_all`, creating every missing directory `0o700` on Unix.
/// Directories that already exist are left as they are.
pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(dir)
}

fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to write {}: it is a symbolic link. Remove the link (or point the \
                 wizard at the real path) and re-run",
                path.display()
            ),
        )),
        _ => Ok(()),
    }
}

fn temp_path_for(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".tmp-{}", std::process::id()));
    Ok(path.with_file_name(tmp))
}

fn write_atomic(path: &Path, contents: &[u8], sensitive: bool) -> io::Result<()> {
    refuse_symlink(path)?;
    let tmp = temp_path_for(path)?;
    // A stale temp file from a crashed run would make `create_new` fail.
    let _ = fs::remove_file(&tmp);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if sensitive {
            options.mode(SENSITIVE_MODE);
        }
        // Never follow a link someone planted at the temp name.
        options.custom_flags(libc_o_nofollow());
    }
    #[cfg(not(unix))]
    let _ = sensitive;

    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        // Make the rename itself durable.
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `O_NOFOLLOW` without a `libc` dependency: the value is fixed per
/// platform family.
#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        0o400000
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // macOS / iOS / the BSDs.
        0x0100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn write_sensitive_creates_file_with_0o600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        write_sensitive(&path, b"hello").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "wizard's sensitive writes must be owner-only readable"
        );
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn write_sensitive_replaces_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        write_sensitive(&path, b"long original contents").unwrap();
        write_sensitive(&path, b"short").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"short");
        // No temp file left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn write_sensitive_tightens_a_loose_existing_file() {
        // A re-run over a file left `0o644` (by an older wizard or by hand)
        // must not write new key material world-readable.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admin-monitor.json");
        fs::write(&path, b"v1").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_sensitive(&path, b"v2").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"v2");
    }

    #[cfg(unix)]
    #[test]
    fn writes_refuse_a_symlinked_target() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.txt");
        fs::write(&real, b"untouched").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(write_sensitive(&link, b"key").is_err());
        assert!(write_public(&link, b"x").is_err());
        assert_eq!(fs::read(&real).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_all_makes_new_dirs_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b");
        create_private_dir_all(&nested).unwrap();
        for d in [dir.path().join("a"), nested] {
            let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
    }
}
