//! The account a DID names, and the hash the mediator keys it by.
//!
//! Accounts, sessions, ACLs, routing and queues are keyed by the SHA-256 of a
//! DID. A `did:scid` identity is the DID `did:scid:vh:1:<scid>`; the `src`
//! query of `did:scid:vh:1:<scid>?src=example.com/alice` only says where its
//! log is published, and changes when the log moves (VTI-KEY-160). So the
//! locator is removed before hashing: every DID URL of one did:scid identity
//! is one account.
//!
//! Every other DID — and a did:scid query carrying anything but `src` — is
//! hashed exactly as written, so no existing account's hash changes.

use std::borrow::Cow;

/// The DID an account is held under: `did` with any did:scid `src` locator
/// removed. Anything else is returned unchanged.
pub fn account_did(did: &str) -> Cow<'_, str> {
    affinidi_did_common::scid::strip_scid_src(did)
}

/// The hash the mediator keys a DID's account by: the SHA-256 (lowercase hex)
/// of [`account_did`].
pub fn did_hash(did: impl AsRef<str>) -> String {
    sha256::digest(account_did(did.as_ref()).as_bytes())
}

/// Whether two DIDs name the same account: equal once any did:scid `src`
/// locator is removed. Use this, not `==`, wherever a DID a party presents is
/// checked against one the mediator holds (a session, its own DID, a sender).
pub fn same_account(a: impl AsRef<str>, b: impl AsRef<str>) -> bool {
    let (a, b) = (a.as_ref(), b.as_ref());
    a == b || account_did(a) == account_did(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_dids_hash_as_before() {
        for did in [
            "did:webvh:QmScid:example.com:alice",
            "did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:example:alice",
            "did:scid:vh:1:QmScid",
            "did:scid:vh:1:QmScid?versionId=2",
        ] {
            assert_eq!(did_hash(did), sha256::digest(did), "{did}");
        }
    }

    #[test]
    fn a_did_scid_locator_is_not_part_of_the_account() {
        let bare = did_hash("did:scid:vh:1:QmScid");
        assert_eq!(did_hash("did:scid:vh:1:QmScid?src=example.com/alice"), bare);
        assert_eq!(did_hash("did:scid:vh:1:QmScid?src=other.example"), bare);
        assert_ne!(did_hash("did:webvh:QmScid:example.com:alice"), bare);
    }

    #[test]
    fn accounts_compare_by_did() {
        assert!(same_account(
            "did:scid:vh:1:QmScid?src=example.com/alice",
            "did:scid:vh:1:QmScid"
        ));
        assert!(same_account("did:key:z6Mk", "did:key:z6Mk"));
        assert!(!same_account(
            "did:scid:vh:1:QmScid",
            "did:webvh:QmScid:example.com:alice"
        ));
        assert!(!same_account("did:key:z6Mk", "did:key:z6Mj"));
    }
}
