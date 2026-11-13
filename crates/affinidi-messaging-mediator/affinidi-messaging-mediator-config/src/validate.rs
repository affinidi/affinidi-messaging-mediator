//! Boot-time configuration invariant checks.
//!
//! Small, pure helpers — each rejects one hard misconfiguration (returning an
//! error message) or flags one legal-but-suspicious combination (returning a
//! warning message). They operate on already-parsed primitives so they can be
//! unit-tested in isolation and reused by any config consumer (the mediator
//! binary and the `mediator-setup` wizard).
//!
//! The mediator wires these into its `validate_config(&Config)` orchestrator,
//! which maps hard failures to `MediatorError` and logs the warnings.

use affinidi_messaging_mediator_common::types::acls::{AccessListModeType, MediatorACLSet};

/// Warn when this mediator relays inter-mediator forwards *implicitly* — i.e.
/// `global_acl_default` grants `SEND_FORWARDED` (so anonymous `/inbound`
/// forwards are accepted) but the operator hasn't set the explicit
/// `security.enable_inter_mediator_relay` flag.
///
/// This is the deprecation half of the explicit-relay rollout: today the
/// implicit configuration still works, but a future release will require the
/// flag, so we surface it loudly now. Setting the flag (or removing
/// `SEND_FORWARDED` from the global default) silences the warning.
pub fn warn_implicit_relay(
    enable_relay_flag: bool,
    global_acl_default: &MediatorACLSet,
) -> Option<String> {
    // `get_send_forwarded().0` is the SEND_FORWARDED bit — the same thing the
    // mediator's `authz::grants(.., Capability::SendForwarded)` checks, inlined
    // here so the schema crate doesn't depend on the binary's authz module.
    if !enable_relay_flag && global_acl_default.get_send_forwarded().0 {
        return Some(
            "inter-mediator relay is enabled implicitly: global_acl_default grants SEND_FORWARDED \
             but security.enable_inter_mediator_relay is not set. This still works today, but a \
             future release will require the explicit flag — set \
             security.enable_inter_mediator_relay = \"true\" to opt in (or drop SEND_FORWARDED from \
             the global default if this mediator should not relay)."
                .to_string(),
        );
    }
    None
}

/// The account a configured DID names, for comparing two of them: the
/// `did://` loader prefix, any query (including a did:scid `src` locator)
/// and any fragment removed, and the `did` scheme and method lowercased. The
/// method-specific id keeps its case, which its method defines.
fn did_account_form(did: &str) -> String {
    let did = did.trim();
    let did = did.strip_prefix("did://").unwrap_or(did);
    let did = affinidi_messaging_mediator_common::did_identity::account_did(did);
    let end = did.find(['?', '#']).unwrap_or(did.len());
    let did = &did[..end];
    let mut parts = did.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(scheme), Some(method), Some(id)) => format!(
            "{}:{}:{id}",
            scheme.to_ascii_lowercase(),
            method.to_ascii_lowercase()
        ),
        _ => did.to_string(),
    }
}

/// Refuse an `admin_did` that names the mediator's own DID. The admin is the
/// root administrator; the mediator's DID is its operating identity, whose
/// keys sit on the server. One account would hold both roles, so whoever
/// holds the mediator's operating keys could administer every account.
///
/// Compared as accounts (see `did_account_form`), so a fragment, a did:scid
/// `src` locator or the case of `did:` and the method do not hide a match.
/// Refused in every build.
pub fn check_admin_not_mediator(admin_did: &str, mediator_did: &str) -> Result<(), String> {
    if admin_did.trim().is_empty() || mediator_did.trim().is_empty() {
        return Ok(());
    }
    if did_account_form(admin_did) == did_account_form(mediator_did) {
        return Err(format!(
            "admin_did names the mediator's own DID ('{}'). The admin must be a separate \
             identity: set [server] admin_did (env ADMIN_DID) to a DID of its own. \
             `mediator-setup` creates one (Admin step: \"Generate did:key\"); see \"Run the \
             setup wizard\" in the mediator README.",
            admin_did.trim()
        ));
    }
    Ok(())
}

/// Environment variable that lets a release build start with one of the
/// identities in [`SAMPLE_DID_KEYS`] or [`SAMPLE_JWT_PUBLIC_KEYS`]. Set it to
/// `true` only for a test deployment such as `docker-compose.test.yml`.
pub const ALLOW_SAMPLE_IDENTITY_ENV: &str = "MEDIATOR_ALLOW_TEST_IDENTITY";

/// Public keys (multibase) of the sample and test DIDs committed to this
/// repository: the example in `conf/mediator.toml` and the fixed identity in
/// `docker/test/conf`. Their private keys are public, so a deployment that
/// names one of them as its mediator or admin DID, or loads one as an
/// operating key, hands that role to anyone.
pub const SAMPLE_DID_KEYS: &[&str] = &[
    // Example DID formerly in conf/mediator.toml (mediator_did and admin_did).
    "z6MkksX9huJxJwvLtj9vc3gXbT2m1WVy4Uoi3ssEiSSH2ZYJ",
    "zQ3shVZJV9gKezYsvy5tC1LCwjjWSms2zCfZhvnRK48BNoHH3",
    // docker/test/conf mediator DID (signing and key-agreement keys).
    "z6Mksfa1ijceFf8yFmTSdRha6Ha2Lzzfuc68UyRAdpsC5pr6",
    "z6LShyV6x81XmxvpyDpgwaXo27783iBBJPTeUtDgcvyKLDXP",
    // docker/test/conf admin DID.
    "z6MkhnJYiMpUGjvedv1eXZziYsFoi6WYRiidWx6EEwvxy3Ed",
];

/// Ed25519 public keys (hex) of the JWT signing keys committed to this
/// repository (`docker/test/conf/secrets.json`). Tokens signed with one of
/// them can be minted by anyone.
pub const SAMPLE_JWT_PUBLIC_KEYS: &[&str] =
    &["8813a35c3f5b86539604dc5937c6fac5b8331c0964b8f1f6fbd05fb406ec6b65"];

/// `did` must not be one of the sample or test DIDs committed to this
/// repository (matched on the key it carries, so a re-encoded `did:peer`
/// with other services is still caught).
pub fn check_not_sample_did(field: &str, did: &str) -> Result<(), String> {
    match SAMPLE_DID_KEYS.iter().find(|key| did.contains(*key)) {
        Some(key) => Err(format!(
            "{field} uses a sample/test identity whose private key is published in this \
             repository (key {key}). Generate your own identity with mediator-setup."
        )),
        None => Ok(()),
    }
}

/// An operating key (its public key as multibase) must not be one of
/// [`SAMPLE_DID_KEYS`]. Catches a deployment that publishes its own
/// `did:web` / `did:webvh` document but loads the committed test keys.
pub fn check_not_sample_operating_key(key_id: &str, public_multibase: &str) -> Result<(), String> {
    if SAMPLE_DID_KEYS.contains(&public_multibase) {
        return Err(format!(
            "operating key '{key_id}' is a sample/test key whose private key is published in \
             this repository ({public_multibase}). Generate your own keys with mediator-setup."
        ));
    }
    Ok(())
}

/// The JWT signing key must not be one committed to this repository.
/// `public_key` is the raw 32-byte Ed25519 public key.
pub fn check_not_sample_jwt_key(public_key: &[u8]) -> Result<(), String> {
    let hex: String = public_key.iter().map(|b| format!("{b:02x}")).collect();
    if SAMPLE_JWT_PUBLIC_KEYS.contains(&hex.as_str()) {
        return Err(
            "the JWT signing key is a sample/test key published in this repository; anyone \
             can sign session tokens with it. Generate a new one with mediator-setup."
                .to_string(),
        );
    }
    Ok(())
}

/// Minimal DID syntax check: `did:<method>:<method-specific-id>`, with a
/// non-empty lowercase-alphanumeric method and a non-empty id. Not a full
/// DID-spec parser — just enough to catch a fat-fingered or empty value
/// before it fails opaquely at resolve time.
pub fn check_did_syntax(field: &str, did: &str) -> Result<(), String> {
    let invalid = |why: &str| {
        Err(format!(
            "{field} is not a valid DID ('{did}'): {why}. Expected 'did:<method>:<id>'"
        ))
    };
    let Some(rest) = did.strip_prefix("did:") else {
        return invalid("must start with 'did:'");
    };
    let Some((method, id)) = rest.split_once(':') else {
        return invalid("missing the method or method-specific id");
    };
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return invalid("method must be non-empty lowercase alphanumeric");
    }
    if id.is_empty() {
        return invalid("method-specific id is empty");
    }
    Ok(())
}

/// The least `security.jwt_access_expiry` accepted, in seconds. A shorter
/// token expires before a client can use it.
pub const MIN_JWT_ACCESS_EXPIRY_SECS: u64 = 10;

/// JWT access tokens must last at least [`MIN_JWT_ACCESS_EXPIRY_SECS`] and
/// expire before refresh tokens, otherwise refresh is pointless and the access
/// token outlives its refresh window.
pub fn check_jwt_expiry(access: u64, refresh: u64) -> Result<(), String> {
    if access < MIN_JWT_ACCESS_EXPIRY_SECS {
        return Err(format!(
            "security.jwt_access_expiry ({access}s) must be at least \
             {MIN_JWT_ACCESS_EXPIRY_SECS}s"
        ));
    }
    if access >= refresh {
        return Err(format!(
            "jwt_access_expiry ({access}s) must be less than jwt_refresh_expiry ({refresh}s)"
        ));
    }
    Ok(())
}

/// The secret backends `[secrets] backend` may name, with what each is for.
/// Shown when none is set, so the operator chooses rather than inheriting a
/// default that may not survive their platform (`keyring://` on Linux does
/// not survive a reboot).
pub const SECRETS_BACKEND_CHOICES: &[(&str, &str)] = &[
    (
        "aws_secrets://<region>/<prefix>",
        "AWS Secrets Manager (feature secrets-aws)",
    ),
    (
        "gcp_secrets://<project>/<prefix>",
        "GCP Secret Manager (feature secrets-gcp)",
    ),
    (
        "vault://<endpoint>/<mount>[/<prefix>]",
        "HashiCorp Vault KV v2 (feature secrets-vault)",
    ),
    (
        "k8s://[<namespace>/]<secret-name>",
        "Kubernetes Secret (feature secrets-k8s)",
    ),
    (
        "file:///<absolute-path>?encrypt=1",
        "passphrase-encrypted file (built in)",
    ),
    (
        "file:///<absolute-path>",
        "plaintext file, development only (built in)",
    ),
    (
        "keyring://<service>",
        "OS keychain; on Linux the kernel keyring, lost on reboot (feature secrets-keyring)",
    ),
    (
        "azure_keyvault://<vault>",
        "Azure Key Vault via the Azure CLI login: wizard/development only (feature secrets-azure)",
    ),
];

/// `[secrets] backend` must be set. The shipped template leaves it commented
/// out so that every deployment picks its own; the error lists the choices.
pub fn check_secrets_backend(backend: &str) -> Result<(), String> {
    if !backend.trim().is_empty() {
        return Ok(());
    }
    let choices = SECRETS_BACKEND_CHOICES
        .iter()
        .map(|(url, what)| format!("  {url}  — {what}"))
        .collect::<Vec<_>>()
        .join("\n");
    Err(format!(
        "no secrets backend is configured: set [secrets] backend in the configuration \
         file (or MEDIATOR_SECRETS_BACKEND). The template leaves it unset on purpose so \
         that you choose one; `mediator-setup` sets it for you. Choices:\n{choices}\n\
         See docs/secrets-backend.md."
    ))
}

/// When `use_ssl` is set, both the certificate and key must be configured
/// and readable. Catches the misconfiguration at load time rather than at
/// the TLS handshake. A no-op when `use_ssl` is false.
pub fn check_tls(use_ssl: bool, cert: Option<&str>, key: Option<&str>) -> Result<(), String> {
    if !use_ssl {
        return Ok(());
    }
    // Check both are configured before touching the filesystem, so a missing
    // path is reported as "not set" rather than masked by a readability error
    // on the other file.
    let cert = require_path("ssl_certificate_file", cert)?;
    let key = require_path("ssl_key_file", key)?;
    for (label, path) in [("ssl_certificate_file", cert), ("ssl_key_file", key)] {
        std::fs::File::open(path)
            .map_err(|e| format!("use_ssl is true but {label} ('{path}') is not readable: {e}"))?;
    }
    Ok(())
}

/// A configured TLS path must be present and non-empty.
fn require_path<'a>(label: &str, path: Option<&'a str>) -> Result<&'a str, String> {
    match path {
        None => Err(format!("use_ssl is true but {label} is not set")),
        Some("") => Err(format!("use_ssl is true but {label} is empty")),
        Some(p) => Ok(p),
    }
}

/// `server.trust_xff_cidrs` must not contain a catch-all range (`0.0.0.0/0`,
/// `::/0`).
///
/// Such a range trusts every peer, so any client that can reach the listener
/// sets its own rate-limit key with `X-Forwarded-For` — and, because every hop
/// in the chain is then "trusted" too, IPv4 clients behind a real proxy are
/// still all charged to the proxy. It is never what an operator meant, and
/// the rate limiter refuses it as well; this catches it at load time with the
/// field named.
pub fn check_trust_xff_cidrs(cidrs: &[ipnet::IpNet]) -> Result<(), String> {
    match cidrs.iter().find(|cidr| cidr.prefix_len() == 0) {
        Some(cidr) => Err(format!(
            "server.trust_xff_cidrs entry '{cidr}' trusts every address, which lets any \
             client choose its own rate-limit key; list only your reverse proxies' ranges"
        )),
        None => Ok(()),
    }
}

/// Warn when the mediator runs a permissive denylist mode
/// (`ExplicitDeny`) *and* hands new DIDs an `ALLOW_ALL` default — together
/// these mean every new account accepts everything from everyone, which is
/// rarely intended for a deployment that bothered to set a mode.
pub fn warn_permissive_default_with_denylist_mode(
    mode: &AccessListModeType,
    global_acl_default: &MediatorACLSet,
) -> Option<String> {
    let allow_all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").ok()?;
    if *mode == AccessListModeType::ExplicitDeny
        && global_acl_default.to_u64() == allow_all.to_u64()
    {
        return Some(
            "mediator_acl_mode is ExplicitDeny (denylist) and global_acl_default grants ALLOW_ALL \
             — every new DID will accept messages from anyone. Confirm this is intended."
                .to_string(),
        );
    }
    None
}

/// Warn when one sender's per-relationship allowance is not strictly below a
/// recipient's total inbox allowance — the condition under which a single
/// sender can fill a recipient's inbox on its own.
///
/// The per-relationship cap exists so that one stuck or hostile sender cannot
/// monopolise a recipient. That only holds while it is *smaller* than the
/// recipient's total: at `per_peer >= receive`, one sender reaches the
/// recipient's whole allowance before its own per-relationship gate ever
/// refuses it, and every other sender is then refused by the recipient-total
/// gate for traffic it did not cause.
///
/// `-1` on either side is unlimited. An unlimited `per_peer` removes the
/// protection outright; an unlimited receive limit means no total to be
/// monopolised, so there is nothing to warn about.
///
/// A warning rather than an error: it is a legal configuration, and an operator
/// running a single trusted sender per recipient may genuinely want it.
pub fn warn_per_peer_not_below_receive_limit(
    per_peer: i32,
    receive_limit: i32,
    scope: &str,
) -> Option<String> {
    // Unlimited recipient total: nothing to monopolise.
    if receive_limit < 0 {
        return None;
    }
    if per_peer < 0 {
        return Some(format!(
            "queued_send_messages_per_peer is unlimited (-1) for {scope}, so one sender can fill              the recipient's entire inbox allowance of {receive_limit} on its own. The              per-relationship cap exists to prevent exactly that; unlimited disables it."
        ));
    }
    if per_peer >= receive_limit {
        return Some(format!(
            "queued_send_messages_per_peer ({per_peer}) is not below the receive limit              ({receive_limit}) for {scope} — one sender can reach the recipient's whole              allowance before its own per-relationship gate refuses it, and every other sender              is then refused for traffic it did not cause. Set per_peer strictly below the              smallest receive limit any account may be granted."
        ));
    }
    None
}

/// Warn when remote (non-local) DIDs may send admin-protocol messages.
/// The secure posture restricts admin messaging to locally-registered
/// DIDs; disabling that widens the admin attack surface.
pub fn warn_remote_admin_allowed(block_remote_admin_msgs: bool) -> Option<String> {
    if !block_remote_admin_msgs {
        return Some(
            "block_remote_admin_msgs is false — remote DIDs may send admin-protocol messages. \
             This widens the admin attack surface; enable it unless you specifically need remote \
             administration."
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn trust_xff_cidrs_rejects_catch_all_ranges() {
        let cidrs = |nets: &[&str]| -> Vec<ipnet::IpNet> {
            nets.iter().map(|n| n.parse().unwrap()).collect()
        };
        assert!(super::check_trust_xff_cidrs(&[]).is_ok());
        assert!(super::check_trust_xff_cidrs(&cidrs(&["10.0.0.0/8", "::1/128"])).is_ok());
        for net in ["0.0.0.0/0", "::/0"] {
            let err = super::check_trust_xff_cidrs(&cidrs(&["10.0.0.0/8", net])).unwrap_err();
            assert!(err.contains(net), "{err}");
        }
    }

    use super::*;

    #[test]
    fn an_admin_did_naming_the_mediator_is_refused() {
        let mediator = "did:peer:2.Ez6LSmediator.Vz6Mkmediator";
        assert!(check_admin_not_mediator("did:key:z6MkAdmin", mediator).is_ok());
        for admin in [
            mediator.to_string(),
            format!("did://{mediator}"),
            format!("{mediator}#key-1"),
            format!("  {mediator} "),
            "DID:PEER:2.Ez6LSmediator.Vz6Mkmediator".to_string(),
        ] {
            let err = check_admin_not_mediator(&admin, mediator).expect_err(&admin);
            assert!(
                err.contains("admin_did names the mediator's own DID"),
                "{err}"
            );
            assert!(err.contains("mediator-setup"), "says how to fix it: {err}");
        }
        // A did:scid `src` locator does not change the account.
        assert!(
            check_admin_not_mediator(
                "did:scid:vh:1:QmScid?src=example.com",
                "did:scid:vh:1:QmScid"
            )
            .is_err()
        );
        // The method-specific id keeps its case.
        assert!(check_admin_not_mediator("did:example:ABC", "did:example:abc").is_ok());
        // Unset on either side is checked elsewhere.
        assert!(check_admin_not_mediator("", "").is_ok());
        assert!(check_admin_not_mediator("", mediator).is_ok());
    }

    #[test]
    fn implicit_relay_warning_fires_only_for_acl_without_flag() {
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let no_relay =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();

        // ACL grants SEND_FORWARDED but flag off → deprecation warning.
        let msg = warn_implicit_relay(false, &relay).expect("implicit relay should warn");
        assert!(
            msg.contains("enable_inter_mediator_relay"),
            "msg was: {msg}"
        );

        // Flag explicitly set → no warning (operator opted in).
        assert!(warn_implicit_relay(true, &relay).is_none());
        // ACL doesn't grant SEND_FORWARDED → not relaying, no warning.
        assert!(warn_implicit_relay(false, &no_relay).is_none());
        assert!(warn_implicit_relay(true, &no_relay).is_none());
    }

    #[test]
    fn did_syntax_accepts_real_methods() {
        for did in [
            "did:key:z6MkABC",
            "did:peer:2.Vz6Mk.Ez6LS.SeyJ",
            "did:web:mediator.example.com",
            "did:webvh:scid:mediator.example.com:path",
        ] {
            assert!(
                check_did_syntax("mediator_did", did).is_ok(),
                "{did} should be valid"
            );
        }
    }

    #[test]
    fn did_syntax_rejects_garbage() {
        for bad in [
            "",
            "notadid",
            "did:",
            "did:key",
            "did::id",
            "did:KEY:z6",
            "did:key:",
        ] {
            assert!(
                check_did_syntax("admin_did", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn the_secrets_backend_must_be_chosen() {
        assert!(check_secrets_backend("file:///var/lib/m/secrets.json").is_ok());
        for unset in ["", "   "] {
            let err = check_secrets_backend(unset).unwrap_err();
            assert!(err.contains("[secrets] backend"), "{err}");
            assert!(err.contains("MEDIATOR_SECRETS_BACKEND"), "{err}");
            for (url, _) in SECRETS_BACKEND_CHOICES {
                assert!(err.contains(url), "{err}");
            }
        }
    }

    #[test]
    fn a_jwt_access_expiry_below_the_minimum_is_refused() {
        assert!(check_jwt_expiry(10, 86_400).is_ok());
        for short in [0, 9] {
            let err = check_jwt_expiry(short, 86_400).unwrap_err();
            assert!(err.contains("jwt_access_expiry"), "{err}");
        }
    }

    #[test]
    fn jwt_expiry_ordering() {
        assert!(check_jwt_expiry(900, 86_400).is_ok());
        assert!(check_jwt_expiry(86_400, 86_400).is_err(), "equal must fail");
        assert!(
            check_jwt_expiry(90_000, 86_400).is_err(),
            "access > refresh must fail"
        );
    }

    #[test]
    fn tls_noop_when_disabled() {
        assert!(check_tls(false, None, None).is_ok());
    }

    #[test]
    fn tls_requires_both_files_when_enabled() {
        assert!(
            check_tls(true, None, Some("/x/key.pem"))
                .unwrap_err()
                .contains("ssl_certificate_file")
        );
        assert!(
            check_tls(true, Some("/x/cert.pem"), None)
                .unwrap_err()
                .contains("ssl_key_file")
        );
        assert!(
            check_tls(true, Some(""), Some("/x/key.pem"))
                .unwrap_err()
                .contains("empty")
        );
    }

    #[test]
    fn tls_checks_readability_when_enabled() {
        let cert = tempfile::NamedTempFile::new().expect("cert temp");
        let key = tempfile::NamedTempFile::new().expect("key temp");
        // Both present + readable → ok.
        assert!(
            check_tls(
                true,
                Some(cert.path().to_str().unwrap()),
                Some(key.path().to_str().unwrap()),
            )
            .is_ok()
        );
        // A non-existent path → unreadable error.
        let err = check_tls(
            true,
            Some(cert.path().to_str().unwrap()),
            Some("/definitely/not/here/key.pem"),
        )
        .unwrap_err();
        assert!(err.contains("not readable"), "msg was: {err}");
    }

    #[test]
    fn warns_only_on_denylist_mode_plus_allow_all_default() {
        let allow_all = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        let default = MediatorACLSet::default();

        // The flagged combination.
        assert!(
            warn_permissive_default_with_denylist_mode(
                &AccessListModeType::ExplicitDeny,
                &allow_all
            )
            .is_some()
        );
        // Allowlist mode with ALLOW_ALL default → not flagged.
        assert!(
            warn_permissive_default_with_denylist_mode(
                &AccessListModeType::ExplicitAllow,
                &allow_all
            )
            .is_none()
        );
        // Denylist mode but restrictive default → not flagged.
        assert!(
            warn_permissive_default_with_denylist_mode(&AccessListModeType::ExplicitDeny, &default)
                .is_none()
        );
    }

    #[test]
    fn warns_only_when_remote_admin_unblocked() {
        assert!(warn_remote_admin_allowed(false).is_some());
        assert!(warn_remote_admin_allowed(true).is_none());
    }

    #[test]
    fn sample_dids_are_recognised_by_their_key() {
        let template = "did:peer:2.Vz6MkksX9huJxJwvLtj9vc3gXbT2m1WVy4Uoi3ssEiSSH2ZYJ.EzQ3shVZJV9gKezYsvy5tC1LCwjjWSms2zCfZhvnRK48BNoHH3";
        let err = check_not_sample_did("admin_did", template).unwrap_err();
        assert!(err.contains("admin_did"));
        // Same key, different service section.
        assert!(
            check_not_sample_did(
                "mediator_did",
                "did:peer:2.Vz6Mksfa1ijceFf8yFmTSdRha6Ha2Lzzfuc68UyRAdpsC5pr6.SeyJ0IjoiZG0ifQ"
            )
            .is_err()
        );
        assert!(
            check_not_sample_did(
                "admin_did",
                "did:key:z6MkhnJYiMpUGjvedv1eXZziYsFoi6WYRiidWx6EEwvxy3Ed"
            )
            .is_err()
        );
        assert!(check_not_sample_did("admin_did", "did:key:z6MkOther").is_ok());
        assert!(check_not_sample_did("mediator_did", "did:web:example.com").is_ok());
    }

    #[test]
    fn sample_operating_keys_are_recognised() {
        assert!(
            check_not_sample_operating_key(
                "did:web:example.com#key-2",
                "z6LShyV6x81XmxvpyDpgwaXo27783iBBJPTeUtDgcvyKLDXP"
            )
            .is_err()
        );
        assert!(check_not_sample_operating_key("k", "z6MkOther").is_ok());
    }

    #[test]
    fn sample_jwt_keys_are_recognised() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&SAMPLE_JWT_PUBLIC_KEYS[0][i * 2..i * 2 + 2], 16).unwrap();
        }
        assert!(check_not_sample_jwt_key(&key).is_err());
        assert!(check_not_sample_jwt_key(&[7u8; 32]).is_ok());
    }

    #[test]
    fn per_peer_must_be_strictly_below_the_receive_limit() {
        // Healthy: the per-relationship cap bites well before the total.
        assert!(warn_per_peer_not_below_receive_limit(50, 200, "defaults").is_none());

        // Equal is not enough: one sender reaches the whole allowance exactly
        // as its own gate would first refuse it.
        assert!(warn_per_peer_not_below_receive_limit(200, 200, "defaults").is_some());
        assert!(warn_per_peer_not_below_receive_limit(201, 200, "defaults").is_some());
    }

    #[test]
    fn an_unlimited_per_peer_removes_the_protection_and_says_so() {
        let msg = warn_per_peer_not_below_receive_limit(-1, 200, "defaults")
            .expect("unlimited per_peer disables the gate");
        assert!(msg.contains("unlimited"));
    }

    /// No total to monopolise means nothing to warn about — including when
    /// both are unlimited, which is a deliberate opt-out of limits rather than
    /// a misconfiguration.
    #[test]
    fn an_unlimited_receive_limit_has_nothing_to_monopolise() {
        assert!(warn_per_peer_not_below_receive_limit(50, -1, "account x").is_none());
        assert!(warn_per_peer_not_below_receive_limit(-1, -1, "account x").is_none());
    }
}
