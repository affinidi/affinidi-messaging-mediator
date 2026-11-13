//! Backend implementations.

pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod file;
pub(crate) mod file_encrypted;
pub(crate) mod fs_atomic;
pub(crate) mod gcp;
pub(crate) mod k8s;
pub(crate) mod keyring;
pub(crate) mod memory;
pub(crate) mod vault;

pub use file_encrypted::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

pub use memory::MemoryStore;

use crate::secrets::error::{Result, SecretStoreError};

/// Run blocking work (file I/O, a KDF, an OS keychain call) on tokio's
/// blocking pool so it never stalls an async worker. A panic in `f`
/// surfaces as an error rather than tearing down the caller.
pub(crate) async fn run_blocking<T, F>(backend: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| {
        SecretStoreError::other(format!("{backend} backend: blocking task failed: {e}"))
    })?
}
