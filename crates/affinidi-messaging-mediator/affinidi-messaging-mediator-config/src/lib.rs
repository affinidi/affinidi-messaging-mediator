//! Raw TOML configuration schema for the Affinidi Messaging Mediator.
//!
//! This crate holds the on-disk shape of `mediator.toml` and the logic that
//! needs nothing beyond it:
//!
//! - the serde deserialization types: the `*ConfigRaw` structs and their
//!   plain-serde sub-structs, mostly `String` fields parsed into runtime
//!   values later;
//! - [`env`](mod@env): reading the file, unknown-key reporting and the environment
//!   variable overrides named in the shipped template's `### Env:` labels;
//! - [`validate`]: boot-time checks on raw values, with a crate-local
//!   [`ConfigError`];
//! - [`values`]: the strict readers every string-typed setting goes through
//!   (an unreadable value is an error naming `section.key`, never a default).
//!
//! It is intentionally dependency-light: serde, plus the lean tier of
//! `affinidi-messaging-mediator-common` for the ACL types validation uses. The
//! **resolved** runtime `Config` (opened secret backends, JWT keys, the
//! DID-resolver client, the VTA refresher) and all `ConfigRaw → Config`
//! conversions stay in the mediator, which re-exports these types so
//! `crate::common::config::*` paths keep resolving.
//!
//! One schema, two consumers: the mediator, and the `mediator-setup` wizard,
//! which applies the same checks to recipe values.

pub mod env;
pub mod error;
mod limits;
mod processors;
mod schema;
mod security;
pub mod validate;
pub mod values;

pub use error::ConfigError;
pub use limits::*;
pub use processors::*;
pub use schema::*;
pub use security::*;

#[cfg(test)]
mod golden {
    use super::ConfigRaw;

    /// The shipped `mediator.toml` must still deserialize into `ConfigRaw`
    /// after the schema relocation — a structural guard that the moved types
    /// stay byte-compatible with the real config the mediator parses.
    #[test]
    fn shipped_mediator_toml_parses() {
        let toml = include_str!("../../conf/mediator.toml");
        let raw: ConfigRaw =
            ::toml::from_str(toml).expect("conf/mediator.toml parses as ConfigRaw");

        // Spot-check a field from a few different sections so an accidental
        // rename or moved field is caught, not just "it deserialized".
        // The template names no identity: an operator supplies their own.
        assert!(raw.mediator_did.is_empty());
        assert!(raw.server.admin_did.is_empty());
        assert!(!raw.server.listen_address.is_empty());
        assert!(!raw.security.global_acl_default.is_empty());
        assert!(!raw.limits.message_size.is_empty());
        assert!(!raw.processors.forwarding.enabled.is_empty());
        // No secrets backend is chosen for the operator: the template lists
        // the choices commented out, and startup refuses until one is set.
        assert!(raw.secrets.backend.is_empty());
        assert!(crate::validate::check_secrets_backend(&raw.secrets.backend).is_err());
    }
}
