//! Who the console connects as.
//!
//! The console never finds keys on its own. An [`IdentitySource`] offers the
//! identities a host can use and hands one over, secrets and all, when the user
//! picks it: a file for the standalone console ([`ProfileFileSource`]), a fixed
//! list for an embedding application or a test ([`StaticIdentities`]), or — in
//! `pnm` — the DIDs a Verifiable Trust Agent manages, fetched on demand so no
//! secret is written to disk.
//!
//! This crate deliberately has no dependency on the VTA SDK: the VTA side
//! implements this trait, so the dependency points from the VTA to here.

use std::path::{Path, PathBuf};

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use async_trait::async_trait;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};

/// A DID the console can act as, with the secrets that prove it.
///
/// Secrets are held only as long as the console needs them and are dropped
/// with it; nothing here persists them.
#[derive(Clone)]
pub struct Identity {
    /// A human name for the identity, shown in the console.
    pub alias: String,
    /// The DID the console authenticates and signs as.
    pub did: String,
    /// The DID's private keys: an Ed25519 key to authenticate and sign Trust
    /// Tasks, and a key-agreement key (X25519 / P-256) to receive replies.
    pub secrets: Vec<Secret>,
    /// The mediator to connect to. `None` finds it from the DID's
    /// `DIDCommMessaging` service.
    pub mediator_did: Option<String>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("alias", &self.alias)
            .field("did", &self.did)
            .field("secrets", &format_args!("<{} hidden>", self.secrets.len()))
            .field("mediator_did", &self.mediator_did)
            .finish()
    }
}

/// One entry in an identity picker — enough to choose by, no secrets yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityChoice {
    /// Opaque key the source uses to load the identity.
    pub id: String,
    /// What the user sees.
    pub label: String,
    /// The DID, when the source knows it before loading.
    pub did: Option<String>,
    /// A second line: a context, a file path, a role.
    pub detail: Option<String>,
}

/// Somewhere identities come from.
#[async_trait]
pub trait IdentitySource: Send + Sync {
    /// The identities available to choose from.
    async fn list(&self) -> Result<Vec<IdentityChoice>>;

    /// Load one — fetching its secrets if they are not already at hand.
    async fn load(&self, choice: &IdentityChoice) -> Result<Identity>;
}

/// A fixed set of identities already in memory.
pub struct StaticIdentities(Vec<Identity>);

impl StaticIdentities {
    pub fn new(identities: Vec<Identity>) -> Self {
        Self(identities)
    }
}

#[async_trait]
impl IdentitySource for StaticIdentities {
    async fn list(&self) -> Result<Vec<IdentityChoice>> {
        Ok(self
            .0
            .iter()
            .map(|i| IdentityChoice {
                id: i.did.clone(),
                label: i.alias.clone(),
                did: Some(i.did.clone()),
                detail: i.mediator_did.clone(),
            })
            .collect())
    }

    async fn load(&self, choice: &IdentityChoice) -> Result<Identity> {
        self.0
            .iter()
            .find(|i| i.did == choice.id)
            .cloned()
            .ok_or_else(|| ConsoleError::Identity(format!("no identity {}", choice.id)))
    }
}

/// TDK profile JSON files — `{ alias, did, mediator, secrets }`, the format
/// `mediator-setup` writes for its administrator (`admin-monitor.json`, at
/// mode `0600`).
///
/// A profile holds private keys, so on Unix [`IdentitySource::load`] refuses
/// one that its group or other users can read or write (any of mode `0o077`),
/// as `ssh` does with a private key: `chmod 600` it. The bytes read are wiped
/// once parsed. [`IdentitySource::list`] reads only the alias and DID.
pub struct ProfileFileSource {
    paths: Vec<PathBuf>,
}

/// The part of a profile the picker shows: no secrets.
#[derive(Deserialize)]
struct ProfileSummary {
    alias: String,
    did: String,
}

impl ProfileFileSource {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    /// The file's bytes, wiped from memory when dropped.
    fn read_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        std::fs::read(path)
            .map(Zeroizing::new)
            .map_err(|e| ConsoleError::Identity(format!("{}: {e}", path.display())))
    }

    /// The full profile, secrets included, from a file only its owner can
    /// read.
    fn read(path: &Path) -> Result<TDKProfile> {
        check_private(path)?;
        let bytes = Self::read_bytes(path)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            ConsoleError::Identity(format!("{} is not a profile: {e}", path.display()))
        })
    }

    /// Alias and DID only, for the picker.
    fn summary(path: &Path) -> Result<ProfileSummary> {
        let bytes = Self::read_bytes(path)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            ConsoleError::Identity(format!("{} is not a profile: {e}", path.display()))
        })
    }
}

/// Refuse a key file that anyone but its owner may read or write.
#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .map_err(|e| ConsoleError::Identity(format!("{}: {e}", path.display())))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(ConsoleError::Identity(format!(
            "{} holds private keys but is accessible to other users (mode {:04o}); \
             run `chmod 600 {}`",
            path.display(),
            mode & 0o7777,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<()> {
    Ok(())
}

#[async_trait]
impl IdentitySource for ProfileFileSource {
    async fn list(&self) -> Result<Vec<IdentityChoice>> {
        self.paths
            .iter()
            .map(|path| {
                let profile = Self::summary(path)?;
                Ok(IdentityChoice {
                    id: path.display().to_string(),
                    label: profile.alias,
                    did: Some(profile.did),
                    detail: Some(path.display().to_string()),
                })
            })
            .collect()
    }

    async fn load(&self, choice: &IdentityChoice) -> Result<Identity> {
        let path = self
            .paths
            .iter()
            .find(|p| p.display().to_string() == choice.id)
            .ok_or_else(|| ConsoleError::Identity(format!("no profile {}", choice.id)))?;
        let mut profile = Self::read(path)?;
        let secrets = profile.take_secrets();
        if secrets.is_empty() {
            return Err(ConsoleError::Identity(format!(
                "{} carries no secrets",
                path.display()
            )));
        }
        Ok(Identity {
            alias: profile.alias.clone(),
            did: profile.did.clone(),
            secrets,
            mediator_did: profile.mediator.clone(),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PROFILE: &str =
        r#"{"alias":"admin","did":"did:example:admin","mediator":null,"secrets":[]}"#;

    #[tokio::test]
    async fn a_profile_others_can_read_is_listed_but_not_loaded() {
        let dir = std::env::temp_dir().join(format!("profile-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin-monitor.json");
        std::fs::write(&path, PROFILE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let source = ProfileFileSource::new(vec![path.clone()]);

        // The picker needs no secrets, so it reads the file regardless.
        let choices = source.list().await.unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].label, "admin");
        assert_eq!(choices[0].did.as_deref(), Some("did:example:admin"));

        let refused = source.load(&choices[0]).await.unwrap_err().to_string();
        assert!(refused.contains("chmod 600"), "{refused}");

        // Owner-only passes the check (and then fails for want of secrets).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let empty = source.load(&choices[0]).await.unwrap_err().to_string();
        assert!(empty.contains("carries no secrets"), "{empty}");

        let _ = std::fs::remove_dir_all(dir);
    }
}
