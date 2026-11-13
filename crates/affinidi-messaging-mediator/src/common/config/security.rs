use crate::error_codes;
use affinidi_messaging_mediator_common::{MediatorSecrets, errors::MediatorError};
// `SecurityConfigRaw` (the raw TOML schema) now lives in the config crate; the
// conversion to the runtime `SecurityConfig` stays here as an extension trait
// (inherent impls must live in the type's crate, but this conversion loads
// secrets and builds runtime objects the schema crate avoids).
use affinidi_messaging_mediator_config::{SecurityConfigRaw, values};
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use async_trait::async_trait;
use http::{
    HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::{
    collections::HashSet,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// One operating key handed to the mediator by an external key authority.
///
/// Deliberately mediator-local rather than `vta_sdk::did_secrets::SecretEntry`,
/// even though today's only producer is a VTA `DidSecretsBundle`. This type is
/// the seam that lets `vta-sdk` be an optional dependency: everything below it
/// — the conversion to `Secret`, the resolver population, the self-hosted
/// fallback — compiles identically with or without the `vta` feature, so none
/// of it needs `cfg`. The mapping from the SDK's bundle lives at the single
/// call site in `config/mod.rs`, which is already `vta`-gated.
pub(crate) struct OperatingSecret {
    /// Key id the secret is filed under (becomes the `Secret`'s id).
    pub key_id: String,
    /// Multibase-encoded private key material. Wiped on drop.
    pub private_key_multibase: String,
}

impl Drop for OperatingSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key_multibase);
    }
}

/// Resolved cross-origin policy for browser clients.
///
/// Built from the `security.cors_allow_origin` config value. Held
/// alongside the pre-built [`CorsLayer`] so the WebSocket handler can
/// apply the *same* allowlist as a defence-in-depth `Origin` check
/// (WebSocket upgrades aren't subject to CORS, but browsers still send
/// an `Origin` header on them).
#[derive(Clone, Debug)]
pub enum CorsOriginPolicy {
    /// No cross-origin browser access (the default — `cors_allow_origin`
    /// unset). Browser requests/upgrades carrying an `Origin` are
    /// refused; header-less native clients are unaffected.
    None,
    /// Any origin (`cors_allow_origin = "*"`). Defensible here because
    /// these endpoints authenticate with a bearer token in the
    /// `Authorization` header, not an ambient cookie — a wildcard does
    /// not expose them to CSRF, since a cross-origin page would still
    /// need a valid token to do anything. Emits `Access-Control-Allow-
    /// Origin: *` and never sets `allow_credentials`.
    Any,
    /// An explicit allowlist of origin matchers. Each entry is either an
    /// exact, scheme-qualified origin or a `scheme://*.suffix` wildcard
    /// (see [`OriginMatcher`]). A request `Origin` is permitted iff it
    /// matches at least one entry; the matched origin is echoed back, so
    /// the response stays CORS-spec compliant (one exact origin, never a
    /// literal `*.…`).
    List(Vec<OriginMatcher>),
}

/// A single entry in a [`CorsOriginPolicy::List`] allowlist.
///
/// The CORS spec's `Access-Control-Allow-Origin` header only carries a
/// bare `*`, a single exact origin, or `null` — there is no
/// wildcard-subdomain token. We support `*.suffix` patterns by matching
/// the *request* `Origin` against the pattern and echoing back the exact
/// origin that matched (which is what [`AllowOrigin::predicate`] does).
#[derive(Clone, Debug)]
pub enum OriginMatcher {
    /// An exact, scheme-qualified origin, compared byte-for-byte against
    /// the request `Origin` (e.g. `https://app.affinidi.com`).
    Exact(HeaderValue),
    /// A `scheme://*.suffix[:port]` wildcard (e.g. `https://*.affinidi.com`).
    ///
    /// Matches a request origin iff the scheme and port match exactly and
    /// the request host is a sub-domain of `suffix` — i.e. it ends with
    /// `.suffix` and has at least one label in front of that boundary
    /// dot. The boundary dot is mandatory, so `https://*.affinidi.com`
    /// matches `https://app.affinidi.com` and `https://a.b.affinidi.com`
    /// but NOT the apex `https://affinidi.com` (add it explicitly) nor a
    /// look-alike like `https://evilaffinidi.com`.
    WildcardSubdomain {
        /// Lower-cased scheme, e.g. `https`.
        scheme: String,
        /// Lower-cased registrable suffix the sub-domain must sit under,
        /// e.g. `affinidi.com`.
        suffix: String,
        /// Explicit port the request origin must carry, if the pattern
        /// pinned one (`https://*.x.com:8443`). `None` means the origin
        /// must carry no port either.
        port: Option<u16>,
    },
}

/// A request `Origin` decomposed into the three parts that matter for
/// matching: scheme (lower-cased), host (lower-cased), optional port.
/// Origins are serialised without a path/query, so this is a total parse
/// of a well-formed `Origin` header; anything that doesn't fit the
/// `scheme://host[:port]` shape returns `None` and never matches.
struct ParsedOrigin<'a> {
    scheme: String,
    host: String,
    port: Option<&'a str>,
}

impl<'a> ParsedOrigin<'a> {
    fn parse(origin: &'a str) -> Option<Self> {
        let (scheme, rest) = origin.split_once("://")?;
        if scheme.is_empty() || rest.is_empty() {
            return None;
        }
        // An Origin carries no path/userinfo/query. Reject anything that
        // smuggles one in rather than silently matching on a prefix.
        if rest.contains(['/', '?', '#', '@', '\\']) {
            return None;
        }
        let (host, port) = match rest.rsplit_once(':') {
            // A ':' that isn't followed by an all-digit port isn't a port
            // separator (defensive — Origin hosts are never IPv6-bracketed
            // here, but treat a non-numeric tail as "no port" so it can't
            // masquerade as one).
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
            _ => (rest, None),
        };
        if host.is_empty() {
            return None;
        }
        Some(ParsedOrigin {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl OriginMatcher {
    /// Whether this matcher admits the given request `Origin` header.
    fn matches(&self, origin: &HeaderValue) -> bool {
        match self {
            // Exact origins are compared byte-for-byte, exactly as the
            // previous `AllowOrigin::list` did — no normalisation.
            OriginMatcher::Exact(expected) => expected == origin,
            OriginMatcher::WildcardSubdomain {
                scheme,
                suffix,
                port,
            } => {
                let Ok(origin) = origin.to_str() else {
                    return false;
                };
                let Some(parsed) = ParsedOrigin::parse(origin) else {
                    return false;
                };
                // Scheme and port must match exactly — a wildcard widens
                // only the host, never the scheme/port. Compare ports by
                // their string form so `:08443` can't slip past `:8443`.
                if &parsed.scheme != scheme
                    || parsed.port.map(str::to_string) != port.as_ref().map(u16::to_string)
                {
                    return false;
                }
                // Sub-domain check with a mandatory boundary dot: the host
                // must end with ".<suffix>" and have ≥1 label in front, so
                // neither the apex (`suffix`) nor a look-alike
                // (`evil<suffix>`) can match.
                parsed
                    .host
                    .strip_suffix(suffix)
                    .and_then(|head| head.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty())
            }
        }
    }
}

/// Whether `origin` is admitted by any matcher in `matchers`.
///
/// Shared by the REST [`CorsLayer`] predicate and the WebSocket
/// defence-in-depth `Origin` check so the two enforcement points can
/// never drift apart.
pub fn origin_matches(matchers: &[OriginMatcher], origin: &HeaderValue) -> bool {
    matchers.iter().any(|m| m.matches(origin))
}

/// How many distinct refused origins to name in the log before going quiet.
///
/// Refusals are logged so an operator can see *which* origin they are missing
/// from the allowlist, but the origin is attacker-controlled: an unbounded
/// record of it is a log-flooding and memory-growth primitive for anyone who
/// can reach the port. A misconfigured deployment has one or two distinct
/// origins to report, so a small cap loses nothing real.
const MAX_LOGGED_REFUSED_ORIGINS: usize = 32;

/// Log a refused origin once, then never again for that origin.
///
/// Why this exists: a CORS refusal is invisible from both ends. The browser
/// gets an opaque `TypeError` with the reason confined to its devtools
/// console, and the mediator's own logs show a clean `200` — the `CorsLayer`
/// simply omits a header. Operator and user are left staring at each other,
/// which is exactly how one deployment spent a day on this. The WebSocket path
/// has always logged its equivalent refusal; the REST path did not.
fn note_refused_origin(seen: &Mutex<HashSet<String>>, origin: &HeaderValue) {
    let Ok(origin) = origin.to_str() else { return };
    let Ok(mut seen) = seen.lock() else { return };
    if seen.contains(origin) {
        return;
    }
    if seen.len() >= MAX_LOGGED_REFUSED_ORIGINS {
        return;
    }
    seen.insert(origin.to_string());
    tracing::warn!(
        "CORS: refused origin '{origin}' — it is not in security.cors_allow_origin. \
         Browser clients from this origin (including browser extensions) cannot use \
         the REST API or open a WebSocket. Add it to the allowlist and restart if \
         this origin is expected."
    );
}

/// Build the mediator's [`CorsLayer`] for the given origin policy. The
/// allowed methods/headers are fixed; only the origin matching varies.
/// Public so an embedding harness can set the same policy a `mediator.toml`
/// would, without parsing one.
pub fn build_cors_layer(policy: &CorsOriginPolicy) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
            Method::DELETE,
            Method::PATCH,
            Method::PUT,
        ]);

    match policy {
        // Default-closed: an empty allowlist never echoes an origin.
        CorsOriginPolicy::None => base,
        CorsOriginPolicy::Any => base.allow_origin(AllowOrigin::any()),
        // A predicate (rather than `AllowOrigin::list`) so `*.suffix`
        // wildcards can match; `AllowOrigin::predicate` echoes back the
        // exact request origin on a match and sets `Vary: Origin`.
        CorsOriginPolicy::List(matchers) => {
            let matchers = matchers.clone();
            // Bounded, de-duplicated: see `note_refused_origin`.
            let refused: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
            base.allow_origin(AllowOrigin::predicate(move |origin, _parts| {
                let allowed = origin_matches(&matchers, origin);
                if !allowed {
                    note_refused_origin(&refused, origin);
                }
                allowed
            }))
        }
    }
}

#[derive(Clone, Serialize)]
pub struct SecurityConfig {
    pub mediator_acl_mode: AccessListModeType,
    pub global_acl_default: MediatorACLSet,
    pub local_direct_delivery_allowed: bool,
    pub local_direct_delivery_allow_anon: bool,
    #[serde(skip_serializing)]
    pub mediator_secrets: Arc<ThreadedSecretsResolver>,
    pub use_ssl: bool,
    pub ssl_certificate_file: Option<String>,
    #[serde(skip_serializing)]
    pub ssl_key_file: Option<String>,
    // Private on purpose. These are `jsonwebtoken` types, and while they were
    // `pub` that crate was a *public dependency* of this one: a consumer
    // constructing a `SecurityConfig` had to name `EncodingKey`/`DecodingKey`,
    // so it had to compile against the same `jsonwebtoken` major we did. Bumping
    // it was then source-breaking for consumers rather than routine currency,
    // which is how mediator 0.20.11 nearly shipped a break as a patch (#770).
    //
    // Build them with [`SecurityConfig::set_jwt_keys_from_pkcs8`] instead, which
    // takes bytes and keeps the dependency private.
    #[serde(skip_serializing)]
    jwt_encoding_key: EncodingKey,
    #[serde(skip_serializing)]
    jwt_decoding_key: DecodingKey,
    pub jwt_access_expiry: u64,
    /// A refresh token is valid for `jwt_refresh_expiry - jwt_access_expiry`
    /// seconds from when it is issued, not `jwt_refresh_expiry`.
    pub jwt_refresh_expiry: u64,
    #[serde(skip_serializing)]
    pub cors_allow_origin: CorsLayer,
    /// The same origin policy the `cors_allow_origin` layer enforces,
    /// kept in an inspectable form for the WebSocket `Origin` check.
    #[serde(skip_serializing)]
    pub cors_origins: CorsOriginPolicy,
    pub block_anonymous_outer_envelope: bool,
    pub force_session_did_match: bool,
    pub block_remote_admin_msgs: bool,
    /// When `true`, this mediator explicitly acts as an inter-mediator relay
    /// (accepts anonymous `/inbound` forwards). Defaults to `false`. Today
    /// relay is still permitted when `global_acl_default` grants
    /// `SEND_FORWARDED` even without this flag (with a deprecation warning at
    /// boot); a future release will require the flag.
    pub enable_inter_mediator_relay: bool,
    /// Whether a Trust Task failing its acceptance checks is refused or only
    /// logged. See [`TrustTaskVerification`].
    pub trust_task_verification: TrustTaskVerification,
    /// Unix time (seconds) until which `POST /tsp/authenticate` also accepts
    /// the older request that signs only the challenge string, for clients
    /// built before `affinidi-messaging-sdk` 0.45.16. `None` (the default)
    /// accepts only the signed statement naming this mediator; so does any
    /// time at or after the deadline. A transition setting: it is logged at
    /// boot and on every login that uses it.
    pub tsp_auth_accept_unbound_until: Option<u64>,
}

/// What the mediator does with a Trust Task that fails its acceptance checks —
/// a missing or invalid `proof`, a stale or missing `issuedAt`, or an in-band
/// `issuer` that is not the authenticated sender.
///
/// `Warn` is the transition setting: the failure is logged and counted
/// (`trust_task_acceptance_failures_total`) and the task still runs, so clients
/// that do not sign yet keep working. `Enforce` refuses it with a problem
/// report. `Warn` is the default for now because every client built before
/// `affinidi-messaging-sdk` 0.26.13 sends unsigned tasks; it will become
/// `Enforce` in a later release.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTaskVerification {
    #[default]
    Warn,
    Enforce,
}

/// Parse `security.tsp_auth_accept_unbound_until`: empty is `None` (only the
/// signed statement naming this mediator is accepted); otherwise an RFC 3339
/// time such as `2027-03-01T00:00:00Z`, as Unix seconds.
pub(crate) fn parse_accept_until(raw: &str) -> Result<Option<u64>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let at = humantime::parse_rfc3339_weak(raw).map_err(|e| {
        format!(
            "security.tsp_auth_accept_unbound_until must be empty or an RFC 3339 time \
             (e.g. \"2027-03-01T00:00:00Z\"), not {raw:?}: {e}"
        )
    })?;
    let secs = at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| format!("security.tsp_auth_accept_unbound_until is before 1970: {raw:?}"))?
        .as_secs();
    Ok(Some(secs))
}

impl std::str::FromStr for TrustTaskVerification {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "warn" => Ok(Self::Warn),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "security.trust_task_verification must be \"warn\" or \"enforce\", not {other:?}"
            )),
        }
    }
}

impl Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("mediator_acl_mode", &self.mediator_acl_mode)
            .field("global_acl_default", &self.global_acl_default)
            .field(
                "local_direct_delivery_allowed",
                &self.local_direct_delivery_allowed,
            )
            .field(
                "local_direct_delivery_allow_anon",
                &self.local_direct_delivery_allow_anon,
            )
            .field("use_ssl", &self.use_ssl)
            .field("ssl_certificate_file", &self.ssl_certificate_file)
            .field("ssl_key_file", &self.ssl_key_file)
            .field("jwt_encoding_key?", &"<hidden>".to_string())
            .field("jwt_decoding_key?", &"<hidden>".to_string())
            .field("jwt_access_expiry", &self.jwt_access_expiry)
            .field("jwt_refresh_expiry", &self.jwt_refresh_expiry)
            .field("cors_allow_origin", &self.cors_allow_origin)
            .field("cors_origins", &self.cors_origins)
            .field(
                "block_anonymous_outer_envelope",
                &self.block_anonymous_outer_envelope,
            )
            .field("force_session_did_match", &self.force_session_did_match)
            .field("block_remote_admin_msgs", &self.block_remote_admin_msgs)
            .field("trust_task_verification", &self.trust_task_verification)
            .field(
                "tsp_auth_accept_unbound_until",
                &self.tsp_auth_accept_unbound_until,
            )
            .field(
                "enable_inter_mediator_relay",
                &self.enable_inter_mediator_relay,
            )
            .finish()
    }
}

/// See [`SecurityConfig::refresh_token_lifetime`].
fn refresh_token_lifetime(jwt_access_expiry: u64, jwt_refresh_expiry: u64) -> u64 {
    jwt_refresh_expiry.saturating_sub(jwt_access_expiry)
}

impl SecurityConfig {
    /// Seconds a refresh token is valid for from when it is issued:
    /// `jwt_refresh_expiry - jwt_access_expiry`, which is what
    /// `conf/mediator.toml` documents. Startup validation keeps
    /// `jwt_refresh_expiry` above `jwt_access_expiry`.
    pub fn refresh_token_lifetime(&self) -> u64 {
        refresh_token_lifetime(self.jwt_access_expiry, self.jwt_refresh_expiry)
    }

    /// Derive and install the JWT signing and verification keys from an Ed25519
    /// **PKCS#8** document — the same bytes the production path reads from the
    /// `JWT_SECRET` well-known entry.
    ///
    /// This is the only way to set them, and deliberately so: the keys are
    /// `jsonwebtoken` types, and taking bytes here keeps that crate a *private*
    /// dependency of this one. While the fields were public a consumer had to
    /// name `EncodingKey`/`DecodingKey` to build a `SecurityConfig`, which made
    /// every `jsonwebtoken` major bump source-breaking for consumers (#770).
    ///
    /// Both keys come from the one document: the signing key is the PKCS#8
    /// itself, the verification key is the public half derived from it, so they
    /// cannot drift apart.
    pub fn set_jwt_keys_from_pkcs8(&mut self, pkcs8: &[u8]) -> Result<(), MediatorError> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|err| {
            tracing::error!("Could not create JWT key pair. {err}");
            MediatorError::ConfigError(
                error_codes::CONFIG_ERROR,
                "NA".into(),
                format!("Could not create JWT key pair. {err}"),
            )
        })?;
        self.jwt_encoding_key = EncodingKey::from_ed_der(pkcs8);
        self.jwt_decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());
        Ok(())
    }

    /// The JWT signing key, for this crate's authentication handlers.
    pub(crate) fn jwt_encoding_key(&self) -> &EncodingKey {
        &self.jwt_encoding_key
    }

    /// The JWT verification key, for this crate's authentication handlers.
    pub(crate) fn jwt_decoding_key(&self) -> &DecodingKey {
        &self.jwt_decoding_key
    }

    /// Construct a baseline `SecurityConfig` with conservative defaults
    /// and a JWT key pair generated for this process. Used by
    /// [`Config::headless`] and the `MediatorBuilder` as a starting point.
    /// Sessions signed with the generated key end when the process
    /// restarts, and other instances cannot verify them: a deployment sets
    /// its own key with [`Self::set_jwt_keys_from_pkcs8`].
    ///
    /// [`Config::headless`]: crate::common::config::Config::headless
    pub fn headless(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        Self::default(secrets_resolver)
    }

    pub(crate) fn default(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        let (jwt_encoding_key, jwt_decoding_key) = ephemeral_jwt_keys();
        SecurityConfig {
            mediator_acl_mode: AccessListModeType::ExplicitDeny,
            global_acl_default: MediatorACLSet::default(),
            local_direct_delivery_allowed: false,
            local_direct_delivery_allow_anon: false,
            mediator_secrets: secrets_resolver,
            use_ssl: true,
            ssl_certificate_file: None,
            ssl_key_file: None,
            jwt_encoding_key,
            jwt_decoding_key,
            jwt_access_expiry: 900,
            jwt_refresh_expiry: 86_400,
            cors_allow_origin: build_cors_layer(&CorsOriginPolicy::None),
            cors_origins: CorsOriginPolicy::None,
            block_anonymous_outer_envelope: true,
            force_session_did_match: true,
            block_remote_admin_msgs: true,
            trust_task_verification: TrustTaskVerification::Warn,
            enable_inter_mediator_relay: false,
            tsp_auth_accept_unbound_until: None,
        }
    }
}

/// Every `[security]` value that is read from the file alone (no secrets), each
/// read strictly. Produced by [`SecurityConfigRawExt::values`] at startup and
/// on `config/reload`, so a value that does not read fails both.
pub(crate) struct SecurityValues {
    pub mediator_acl_mode: AccessListModeType,
    pub global_acl_default: MediatorACLSet,
    pub local_direct_delivery_allowed: bool,
    pub local_direct_delivery_allow_anon: bool,
    pub use_ssl: bool,
    pub jwt_access_expiry: u64,
    pub jwt_refresh_expiry: u64,
    pub cors: Option<CorsOriginPolicy>,
    pub block_anonymous_outer_envelope: bool,
    pub force_session_did_match: bool,
    pub block_remote_admin_msgs: bool,
    pub enable_inter_mediator_relay: bool,
    pub trust_task_verification: TrustTaskVerification,
    pub tsp_auth_accept_unbound_until: Option<u64>,
}

/// The legal `security.mediator_acl_mode` values.
const ACL_MODES: &[&str] = &["explicit_allow", "explicit_deny"];

/// Conversion + parsing helpers for the (now foreign) [`SecurityConfigRaw`].
/// An extension trait because inherent impls must live in the type's crate, but
/// this logic loads secrets and builds runtime objects the schema crate avoids.
#[async_trait]
pub(crate) trait SecurityConfigRawExt {
    fn parse_cors_origins(cors_allow_origin: &str) -> Result<CorsOriginPolicy, MediatorError>;
    fn parse_origin_matcher(token: &str) -> Result<OriginMatcher, MediatorError>;
    /// Read every file-only `[security]` value strictly, and check the ones
    /// that must agree.
    fn values(&self) -> Result<SecurityValues, MediatorError>;
    async fn convert(
        &self,
        secrets_resolver: Arc<ThreadedSecretsResolver>,
        secrets: &MediatorSecrets,
        vta_bundle: Option<&[OperatingSecret]>,
    ) -> Result<SecurityConfig, MediatorError>;
}

#[async_trait]
impl SecurityConfigRawExt for SecurityConfigRaw {
    /// Parse the raw `cors_allow_origin` config value into a
    /// [`CorsOriginPolicy`].
    ///
    /// - empty / whitespace-only ⇒ [`CorsOriginPolicy::None`]
    /// - a bare `*` token ⇒ [`CorsOriginPolicy::Any`] (`tower_http`'s
    ///   origin list would otherwise *panic* on `*`). If `*` is mixed
    ///   with explicit origins the explicit entries are redundant and a
    ///   warning is logged.
    /// - otherwise ⇒ [`CorsOriginPolicy::List`] of matchers, each an
    ///   exact origin or a `scheme://*.suffix[:port]` wildcard.
    fn parse_cors_origins(cors_allow_origin: &str) -> Result<CorsOriginPolicy, MediatorError> {
        let tokens: Vec<&str> = cors_allow_origin
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            return Ok(CorsOriginPolicy::None);
        }

        if tokens.contains(&"*") {
            if tokens.len() > 1 {
                tracing::warn!(
                    "security.cors_allow_origin contains '*' alongside explicit origins; \
                     treating as allow-any (the explicit entries are redundant)"
                );
            }
            return Ok(CorsOriginPolicy::Any);
        }

        let matchers = tokens
            .iter()
            .map(|o| Self::parse_origin_matcher(o))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CorsOriginPolicy::List(matchers))
    }

    /// Parse a single allowlist entry into an [`OriginMatcher`].
    ///
    /// Wildcard entries have the shape `scheme://*.suffix[:port]` — the
    /// `*` must be the entire leftmost host label (i.e. immediately
    /// followed by `.`) and is the only `*` allowed. Everything *without*
    /// a `*` is treated as an exact origin and parsed as a [`HeaderValue`]
    /// exactly as before this matcher existed (so existing exact-origin
    /// configs are unaffected).
    fn parse_origin_matcher(token: &str) -> Result<OriginMatcher, MediatorError> {
        let config_err =
            |msg: String| MediatorError::ConfigError(error_codes::CONFIG_ERROR, "NA".into(), msg);

        // No '*' ⇒ an exact origin. It must be what a browser sends in
        // `Origin` — `scheme://host[:port]`, nothing after it — or it could
        // never match, and nothing would say why (an entry such as
        // `app.example.com` or `https://app.example.com/` used to be taken
        // and then silently refuse every browser). Scheme and host are
        // lowercased, as browsers send them.
        if !token.contains('*') {
            let parsed = ParsedOrigin::parse(token)
                .filter(|o| {
                    o.scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                })
                .ok_or_else(|| {
                    config_err(format!(
                        "security.cors_allow_origin entry '{token}' is not an origin: write \
                         it as scheme://host[:port], with no path or trailing slash (e.g. \
                         'https://app.example.com')"
                    ))
                })?;
            let normalised = match parsed.port {
                Some(port) => format!("{}://{}:{port}", parsed.scheme, parsed.host),
                None => format!("{}://{}", parsed.scheme, parsed.host),
            };
            let value = normalised.parse::<HeaderValue>().map_err(|err| {
                config_err(format!(
                    "security.cors_allow_origin entry '{token}' is not valid: {err}"
                ))
            })?;
            return Ok(OriginMatcher::Exact(value));
        }

        // Wildcard form: must be exactly `scheme://*.suffix[:port]`.
        let Some((scheme, rest)) = token.split_once("://") else {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '*' is only supported as a leftmost \
                 sub-domain wildcard, e.g. 'https://*.example.com'"
            )));
        };
        let Some(suffix) = rest.strip_prefix("*.") else {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '*' is only allowed as the leftmost host \
                 label, written as '{scheme}://*.suffix'"
            )));
        };
        if scheme.is_empty() {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': missing scheme before '://'"
            )));
        }
        // Only the single leftmost `*` is permitted.
        if suffix.contains('*') {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': only one leftmost '*' wildcard is allowed"
            )));
        }
        // Split an optional :port off the suffix.
        let (host_suffix, port) = match suffix.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| {
                    config_err(format!("Invalid CORS origin '{token}': bad port '{p}'"))
                })?;
                (h, Some(port))
            }
            None => (suffix, None),
        };
        if host_suffix.is_empty()
            || host_suffix.starts_with('.')
            || host_suffix.contains(['/', '?', '#', '@', '\\'])
        {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '{host_suffix}' is not a valid wildcard \
                 suffix (expected e.g. 'https://*.example.com')"
            )));
        }
        Ok(OriginMatcher::WildcardSubdomain {
            scheme: scheme.to_ascii_lowercase(),
            suffix: host_suffix.to_ascii_lowercase(),
            port,
        })
    }

    fn values(&self) -> Result<SecurityValues, MediatorError> {
        let err = |e: affinidi_messaging_mediator_config::ConfigError| {
            let msg = e.to_string();
            tracing::error!("{msg}");
            MediatorError::ConfigError(12, "NA".into(), msg)
        };
        let msg_err = |msg: String| {
            tracing::error!("{msg}");
            MediatorError::ConfigError(12, "NA".into(), msg)
        };
        let flag = |field: &str, value: &str| {
            values::boolean(&format!("security.{field}"), value).map_err(err)
        };

        // A typo here used to select `explicit_deny`, the OPEN mode, so a
        // mediator its operator believed closed accepted any DID (#105).
        let mediator_acl_mode = match values::one_of(
            "security.mediator_acl_mode",
            &self.mediator_acl_mode,
            ACL_MODES,
        )
        .map_err(err)?
        {
            "explicit_allow" => AccessListModeType::ExplicitAllow,
            _ => AccessListModeType::ExplicitDeny,
        };

        let global_acl_default = MediatorACLSet::from_string_ruleset(&self.global_acl_default)
            .map_err(|e| {
                msg_err(format!(
                    "security.global_acl_default = {:?} is not valid: {e}",
                    self.global_acl_default
                ))
            })?;

        let jwt_access_expiry =
            values::number("security.jwt_access_expiry", &self.jwt_access_expiry).map_err(err)?;
        let jwt_refresh_expiry =
            values::number("security.jwt_refresh_expiry", &self.jwt_refresh_expiry).map_err(err)?;
        affinidi_messaging_mediator_config::validate::check_jwt_expiry(
            jwt_access_expiry,
            jwt_refresh_expiry,
        )
        .map_err(msg_err)?;

        let block_anonymous_outer_envelope = flag(
            "block_anonymous_outer_envelope",
            &self.block_anonymous_outer_envelope,
        )?;
        let force_session_did_match =
            flag("force_session_did_match", &self.force_session_did_match)?;
        if !block_anonymous_outer_envelope && force_session_did_match {
            return Err(msg_err(
                "Conflicting configuration: security.force_session_did_match can not be true \
                 when security.block_anonymous_outer_envelope is false"
                    .into(),
            ));
        }

        let cors = match &self.cors_allow_origin {
            Some(cors_allow_origin) => Some(Self::parse_cors_origins(cors_allow_origin)?),
            None => None,
        };

        Ok(SecurityValues {
            mediator_acl_mode,
            global_acl_default,
            local_direct_delivery_allowed: flag(
                "local_direct_delivery_allowed",
                &self.local_direct_delivery_allowed,
            )?,
            local_direct_delivery_allow_anon: flag(
                "local_direct_delivery_allow_anon",
                &self.local_direct_delivery_allow_anon,
            )?,
            use_ssl: flag("use_ssl", &self.use_ssl)?,
            jwt_access_expiry,
            jwt_refresh_expiry,
            cors,
            block_anonymous_outer_envelope,
            force_session_did_match,
            block_remote_admin_msgs: flag(
                "block_remote_admin_msgs",
                &self.block_remote_admin_msgs,
            )?,
            // Absent (configs that predate it) is false.
            enable_inter_mediator_relay: values::boolean_or(
                "security.enable_inter_mediator_relay",
                &self.enable_inter_mediator_relay,
                false,
            )
            .map_err(err)?,
            // A security setting that doesn't parse is a hard error, not a
            // silent default — a typo must not quietly pick the weaker mode.
            trust_task_verification: self.trust_task_verification.parse().map_err(msg_err)?,
            // Also a hard error: a deadline that doesn't parse must not
            // quietly become "no deadline" or "accept for ever".
            tsp_auth_accept_unbound_until: parse_accept_until(&self.tsp_auth_accept_unbound_until)
                .map_err(msg_err)?,
        })
    }

    /// Build the runtime `SecurityConfig` from the raw TOML values.
    ///
    /// Operating keys and the JWT signing secret are loaded from the
    /// unified secret backend:
    /// - **VTA mode** (admin credential present in the backend):
    ///   `vta_bundle` is the freshly-fetched [`DidSecretsBundle`] (or the
    ///   cached copy if the VTA was unreachable). Secrets are inserted
    ///   into the resolver directly.
    /// - **Self-hosted mode** (no admin credential, no VTA bundle):
    ///   operating secrets come from the well-known
    ///   [`OPERATING_SECRETS`](affinidi_messaging_mediator_common::OPERATING_SECRETS)
    ///   key in the backend.
    ///
    /// The JWT secret is always loaded from the backend's `JWT_SECRET`
    /// well-known entry — no inline `string://` path.
    async fn convert(
        &self,
        secrets_resolver: Arc<ThreadedSecretsResolver>,
        secrets: &MediatorSecrets,
        vta_bundle: Option<&[OperatingSecret]>,
    ) -> Result<SecurityConfig, MediatorError> {
        let values = self.values()?;
        let mut config = SecurityConfig {
            mediator_acl_mode: values.mediator_acl_mode,
            global_acl_default: values.global_acl_default,
            local_direct_delivery_allowed: values.local_direct_delivery_allowed,
            local_direct_delivery_allow_anon: values.local_direct_delivery_allow_anon,
            use_ssl: values.use_ssl,
            ssl_certificate_file: self.ssl_certificate_file.clone(),
            ssl_key_file: self.ssl_key_file.clone(),
            jwt_access_expiry: values.jwt_access_expiry,
            jwt_refresh_expiry: values.jwt_refresh_expiry,
            block_anonymous_outer_envelope: values.block_anonymous_outer_envelope,
            force_session_did_match: values.force_session_did_match,
            block_remote_admin_msgs: values.block_remote_admin_msgs,
            enable_inter_mediator_relay: values.enable_inter_mediator_relay,
            trust_task_verification: values.trust_task_verification,
            tsp_auth_accept_unbound_until: values.tsp_auth_accept_unbound_until,
            ..SecurityConfig::default(secrets_resolver)
        };

        if let Some(policy) = values.cors {
            config.cors_allow_origin = build_cors_layer(&policy);
            config.cors_origins = policy;
        }
        // State the effective policy at boot. The default-closed case has no
        // per-request hook to log from — `CorsOriginPolicy::None` installs no
        // predicate, it simply never emits the header — so without this line a
        // mediator that refuses every browser client says so nowhere at all,
        // and the operator's first sight of it is a user reporting an error
        // the server logs as a clean 200.
        match &config.cors_origins {
            CorsOriginPolicy::None => tracing::info!(
                "CORS: disabled (security.cors_allow_origin unset). Browser clients \
                 carrying an Origin header are refused on both the REST API and the \
                 WebSocket upgrade; native clients are unaffected."
            ),
            CorsOriginPolicy::Any => {
                tracing::info!("CORS: any origin allowed (security.cors_allow_origin = \"*\")")
            }
            CorsOriginPolicy::List(matchers) => tracing::info!(
                "CORS: {} allowed origin(s) configured; all others refused",
                matchers.len()
            ),
        }

        // ── Populate the DIDComm secrets resolver ────────────────────────
        if let Some(bundle) = vta_bundle {
            // VTA mode: operating keys arrived via integration::startup.
            tracing::info!(
                "Loading {} operating secret(s) from VTA DidSecretsBundle",
                bundle.len()
            );
            let converted = bundle
                .iter()
                .map(|entry| {
                    Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id))
                        .map_err(|e| {
                            MediatorError::ConfigError(
                                error_codes::CONFIG_ERROR,
                                "NA".into(),
                                format!(
                                    "Could not decode VTA operating secret '{}': {e}",
                                    entry.key_id
                                ),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            super::validate::refuse_sample_operating_keys(&converted)?;
            config.mediator_secrets.insert_vec(&converted).await;
        } else {
            // Self-hosted mode: operating keys come from the well-known
            // OPERATING_SECRETS entry in the backend.
            match secrets
                .load_entry::<Vec<Secret>>(
                    affinidi_messaging_mediator_common::OPERATING_SECRETS,
                    "operating-secrets",
                )
                .await
            {
                Ok(Some(secrets_vec)) => {
                    tracing::info!(
                        "Loading {} operating secret(s) from unified secret backend",
                        secrets_vec.len()
                    );
                    super::validate::refuse_sample_operating_keys(&secrets_vec)?;
                    config.mediator_secrets.insert_vec(&secrets_vec).await;
                }
                Ok(None) => {
                    return Err(MediatorError::ConfigError(
                        error_codes::CONFIG_ERROR,
                        "NA".into(),
                        format!(
                            "No operating secrets found. In self-hosted mode, the backend must \
                             contain the well-known entry '{}'. Run `mediator-setup` to \
                             provision, or enable VTA integration.",
                            affinidi_messaging_mediator_common::OPERATING_SECRETS
                        ),
                    ));
                }
                Err(err) => {
                    tracing::error!("Could not load operating secrets: {err}");
                    return Err(MediatorError::ConfigError(
                        error_codes::CONFIG_ERROR,
                        "NA".into(),
                        format!("Could not load operating secrets: {err}"),
                    ));
                }
            }
        }

        // ── JWT signing secret ───────────────────────────────────────────
        let jwt_bytes = match secrets.load_jwt_secret().await {
            Ok(Some(bytes)) => zeroize::Zeroizing::new(bytes),
            Ok(None) => {
                return Err(MediatorError::ConfigError(
                    error_codes::CONFIG_ERROR,
                    "NA".into(),
                    format!(
                        "JWT signing secret is missing from the backend (well-known key \
                         '{}'). Re-run `mediator-setup` to provision.",
                        affinidi_messaging_mediator_common::JWT_SECRET
                    ),
                ));
            }
            Err(err) => {
                return Err(MediatorError::ConfigError(
                    error_codes::CONFIG_ERROR,
                    "NA".into(),
                    format!("Could not load JWT signing secret: {err}"),
                ));
            }
        };

        config.set_jwt_keys_from_pkcs8(&jwt_bytes)?;
        if let Ok(pair) = Ed25519KeyPair::from_pkcs8(&jwt_bytes) {
            super::validate::sample_identity_guard(
                affinidi_messaging_mediator_config::validate::check_not_sample_jwt_key(
                    pair.public_key().as_ref(),
                ),
            )?;
        }

        Ok(config)
    }
}

/// A JWT key pair generated for this process. The default until a real key
/// is set with [`SecurityConfig::set_jwt_keys_from_pkcs8`]: tokens it signs
/// verify only in this process, and stop verifying when it restarts.
fn ephemeral_jwt_keys() -> (EncodingKey, DecodingKey) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("the system random number generator is available");
    let pair =
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a freshly generated key pair parses");
    (
        EncodingKey::from_ed_der(pkcs8.as_ref()),
        DecodingKey::from_ed_der(pair.public_key().as_ref()),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CorsOriginPolicy, MAX_LOGGED_REFUSED_ORIGINS, OriginMatcher, SecurityConfigRaw,
        SecurityConfigRawExt, note_refused_origin, origin_matches,
    };
    use http::HeaderValue;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Parse `spec` into a `List` policy and return its matchers, or panic
    /// with the actual variant for a clearer failure than `unwrap`.
    fn matchers(spec: &str) -> Vec<OriginMatcher> {
        match SecurityConfigRaw::parse_cors_origins(spec).unwrap() {
            CorsOriginPolicy::List(m) => m,
            other => panic!("expected List for {spec:?}, got {other:?}"),
        }
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    /// Does `spec`'s allowlist admit request origin `origin`?
    fn allows(spec: &str, origin: &str) -> bool {
        origin_matches(&matchers(spec), &hv(origin))
    }

    /// `jwt_refresh_expiry` is documented (conf/mediator.toml) as the refresh
    /// lifetime less the access lifetime, which is what is issued.
    #[test]
    fn a_refresh_token_lives_refresh_expiry_less_access_expiry() {
        assert_eq!(super::refresh_token_lifetime(900, 86_400), 85_500);
    }

    /// The default JWT key signs tokens that verify with its own public key,
    /// and each process (here, each call) gets a different one.
    #[test]
    fn the_default_jwt_key_is_generated_and_distinct() {
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Claims {
            sub: String,
            exp: u64,
        }
        let claims = Claims {
            sub: "did:example:alice".into(),
            exp: u64::MAX / 2,
        };
        let (enc, dec) = super::ephemeral_jwt_keys();
        let (_, other_dec) = super::ephemeral_jwt_keys();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &enc).expect("signs");
        let validation = Validation::new(Algorithm::EdDSA);
        assert!(decode::<Claims>(&token, &dec, &validation).is_ok());
        assert!(
            decode::<Claims>(&token, &other_dec, &validation).is_err(),
            "another generated key must not verify it"
        );
    }

    #[test]
    fn empty_origins_parse_to_none() {
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("").unwrap(),
            CorsOriginPolicy::None
        ));
        // Whitespace / stray commas collapse to nothing.
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("  ,  ").unwrap(),
            CorsOriginPolicy::None
        ));
    }

    #[test]
    fn bare_wildcard_parses_to_any() {
        // A literal "*" must NOT reach tower_http's origin list (which
        // panics on it) — it maps to the allow-any policy instead.
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("*").unwrap(),
            CorsOriginPolicy::Any
        ));
    }

    #[test]
    fn wildcard_mixed_with_origins_is_any() {
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("https://a.example,*").unwrap(),
            CorsOriginPolicy::Any
        ));
    }

    #[test]
    fn explicit_origins_parse_to_list() {
        let origins = matchers("https://a.example, https://b.example");
        assert_eq!(origins.len(), 2);
        assert!(matches!(&origins[0], OriginMatcher::Exact(v) if v == "https://a.example"));
        assert!(matches!(&origins[1], OriginMatcher::Exact(v) if v == "https://b.example"));
    }

    #[test]
    fn exact_origin_matches_byte_for_byte() {
        assert!(allows("https://a.example", "https://a.example"));
        // No normalisation — a trailing slash, differing case in the
        // host, or an extra port are all distinct origins.
        assert!(!allows("https://a.example", "https://a.example/"));
        assert!(!allows("https://a.example", "https://a.example:443"));
        assert!(!allows("https://a.example", "http://a.example"));
    }

    #[test]
    fn wildcard_parses_and_lowercases() {
        let m = matchers("HTTPS://*.Affinidi.COM");
        assert_eq!(m.len(), 1);
        match &m[0] {
            OriginMatcher::WildcardSubdomain {
                scheme,
                suffix,
                port,
            } => {
                assert_eq!(scheme, "https");
                assert_eq!(suffix, "affinidi.com");
                assert_eq!(*port, None);
            }
            other => panic!("expected WildcardSubdomain, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_matches_subdomains_at_any_depth() {
        assert!(allows("https://*.affinidi.com", "https://app.affinidi.com"));
        assert!(allows("https://*.affinidi.com", "https://a.b.affinidi.com"));
        // Case-insensitive host comparison.
        assert!(allows("https://*.affinidi.com", "https://App.Affinidi.Com"));
    }

    #[test]
    fn wildcard_rejects_apex_and_lookalikes() {
        // The boundary dot is mandatory: the apex needs an explicit entry.
        assert!(!allows("https://*.affinidi.com", "https://affinidi.com"));
        // A look-alike registrable domain must not slip through.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://evilaffinidi.com"
        ));
        assert!(!allows(
            "https://*.affinidi.com",
            "https://affinidi.com.evil.com"
        ));
        // An empty leftmost label ("https://.affinidi.com") isn't a
        // sub-domain.
        assert!(!allows("https://*.affinidi.com", "https://.affinidi.com"));
    }

    #[test]
    fn wildcard_requires_exact_scheme_and_port() {
        assert!(!allows("https://*.affinidi.com", "http://app.affinidi.com"));
        // Pattern pins no port → an origin carrying one is rejected.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://app.affinidi.com:8443"
        ));
        // Pattern pins a port → it must match exactly.
        assert!(allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com:8443"
        ));
        assert!(!allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com:8444"
        ));
        assert!(!allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com"
        ));
    }

    #[test]
    fn wildcard_rejects_path_smuggling_in_request_origin() {
        // A malformed Origin that smuggles a path/userinfo must never
        // match — these aren't valid serialised origins.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://app.affinidi.com/../evil.com"
        ));
        assert!(!allows(
            "https://*.affinidi.com",
            "https://evil.com@app.affinidi.com"
        ));
    }

    #[test]
    fn exact_and_wildcard_entries_coexist() {
        let spec = "https://*.affinidi.com, https://affinidi.com";
        assert!(allows(spec, "https://app.affinidi.com")); // wildcard
        assert!(allows(spec, "https://affinidi.com")); // exact apex
        assert!(!allows(spec, "https://other.com"));
    }

    /// Issue #146: an exact entry that could never match a browser `Origin`
    /// is refused at startup, naming the entry.
    #[test]
    fn an_exact_entry_that_is_not_an_origin_is_refused() {
        for bad in [
            "app.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://",
            "null",
            "https://user@app.example.com",
        ] {
            let err = SecurityConfigRaw::parse_cors_origins(bad)
                .expect_err(bad)
                .to_string();
            assert!(err.contains("security.cors_allow_origin"), "{bad}: {err}");
            assert!(err.contains(bad), "{bad}: {err}");
        }
        // Scheme and host are lowercased, so the entry matches what a browser
        // sends.
        assert!(allows("HTTPS://App.Example.com", "https://app.example.com"));
        assert!(allows("http://localhost:3000", "http://localhost:3000"));
    }

    #[test]
    fn invalid_entries_are_rejected_at_parse_time() {
        // Wildcard not in the leftmost-label position.
        assert!(SecurityConfigRaw::parse_cors_origins("https://app.*.com").is_err());
        // More than one wildcard.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.*.com").is_err());
        // Bad port on a wildcard.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.affinidi.com:notaport").is_err());
        // Empty suffix.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.").is_err());
    }

    // ─── Refused-origin logging ───
    //
    // The record is bounded because the origin is attacker-controlled: an
    // unbounded set of it is a memory-growth and log-flooding primitive for
    // anyone who can reach the port.

    #[test]
    fn refused_origin_is_recorded_once() {
        let seen = Mutex::new(HashSet::new());
        let origin = HeaderValue::from_static("https://app.example.com");
        note_refused_origin(&seen, &origin);
        note_refused_origin(&seen, &origin);
        note_refused_origin(&seen, &origin);
        assert_eq!(seen.lock().unwrap().len(), 1, "a repeated origin logs once");
    }

    #[test]
    fn distinct_refused_origins_are_each_recorded() {
        let seen = Mutex::new(HashSet::new());
        note_refused_origin(&seen, &HeaderValue::from_static("https://a.example"));
        note_refused_origin(&seen, &HeaderValue::from_static("https://b.example"));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn refused_origin_record_is_bounded() {
        let seen = Mutex::new(HashSet::new());
        for i in 0..(MAX_LOGGED_REFUSED_ORIGINS * 4) {
            let origin = HeaderValue::from_str(&format!("https://host{i}.example")).unwrap();
            note_refused_origin(&seen, &origin);
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            MAX_LOGGED_REFUSED_ORIGINS,
            "an unbounded caller must not be able to grow the record without limit"
        );
    }

    #[test]
    fn a_non_utf8_origin_is_ignored_rather_than_panicking() {
        // `HeaderValue` admits bytes that are not valid UTF-8; the logger must
        // decline them, not unwrap.
        let seen = Mutex::new(HashSet::new());
        let origin = HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
        note_refused_origin(&seen, &origin);
        assert!(seen.lock().unwrap().is_empty());
    }

    fn raw_security(acl_mode: &str) -> SecurityConfigRaw {
        SecurityConfigRaw {
            mediator_acl_mode: acl_mode.into(),
            global_acl_default: "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES".into(),
            local_direct_delivery_allowed: "true".into(),
            local_direct_delivery_allow_anon: "false".into(),
            use_ssl: "false".into(),
            ssl_certificate_file: None,
            ssl_key_file: None,
            jwt_access_expiry: "900".into(),
            jwt_refresh_expiry: "86400".into(),
            cors_allow_origin: None,
            block_anonymous_outer_envelope: "true".into(),
            block_remote_admin_msgs: "true".into(),
            force_session_did_match: "true".into(),
            enable_inter_mediator_relay: String::new(),
            trust_task_verification: String::new(),
            tsp_auth_accept_unbound_until: String::new(),
        }
    }

    /// Issue #105: an unrecognised `mediator_acl_mode` used to select the OPEN
    /// mode. It is now refused, naming the legal values; case and surrounding
    /// whitespace are ignored.
    #[test]
    fn an_unknown_acl_mode_is_refused_not_opened() {
        use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
        for (given, mode) in [
            ("explicit_allow", AccessListModeType::ExplicitAllow),
            ("EXPLICIT_ALLOW", AccessListModeType::ExplicitAllow),
            ("explicit_allow ", AccessListModeType::ExplicitAllow),
            (" Explicit_Deny", AccessListModeType::ExplicitDeny),
        ] {
            let values = raw_security(given).values().expect(given);
            assert_eq!(values.mediator_acl_mode, mode, "{given:?}");
        }
        for bad in ["explicit-allow", "ExplicitAllow", "allow", "", "closed"] {
            let err = raw_security(bad).values().err().expect(bad).to_string();
            assert!(err.contains("security.mediator_acl_mode"), "{bad}: {err}");
            assert!(
                err.contains("\"explicit_allow\", \"explicit_deny\""),
                "{bad}: {err}"
            );
        }
    }

    /// Issue #112: a `[security]` boolean or number that does not read is
    /// refused, naming the key — `use_ssl = "ture"` used to quietly mean true.
    #[test]
    fn an_unreadable_security_value_is_refused() {
        type Set = fn(&mut SecurityConfigRaw);
        let cases: [(&str, Set); 6] = [
            ("security.use_ssl", |r| r.use_ssl = "ture".into()),
            ("security.jwt_access_expiry", |r| {
                r.jwt_access_expiry = "15m".into()
            }),
            ("security.jwt_access_expiry", |r| {
                r.jwt_access_expiry = "5".into()
            }),
            ("security.block_remote_admin_msgs", |r| {
                r.block_remote_admin_msgs = "1".into()
            }),
            ("security.enable_inter_mediator_relay", |r| {
                r.enable_inter_mediator_relay = "yes".into()
            }),
            ("security.global_acl_default", |r| {
                r.global_acl_default = "ALLOW_EVERYTHING".into()
            }),
        ];
        for (key, set) in cases {
            let mut raw = raw_security("explicit_deny");
            set(&mut raw);
            let err = raw.values().err().expect(key).to_string();
            assert!(err.contains(key), "{key}: {err}");
        }
        assert!(raw_security("explicit_deny").values().is_ok());
    }

    /// The older TSP login form is accepted only under an explicit, dated
    /// opt-in: empty means never, and a value that doesn't parse is refused
    /// rather than read as "no deadline".
    #[test]
    fn tsp_auth_accept_unbound_until_parses_strictly() {
        use super::parse_accept_until;
        assert_eq!(parse_accept_until("").unwrap(), None);
        assert_eq!(parse_accept_until("   ").unwrap(), None);
        assert_eq!(
            parse_accept_until("2027-03-01T00:00:00Z").unwrap(),
            Some(1_803_859_200)
        );
        for bad in ["true", "yes", "1803772800", "2027-03-01", "next month"] {
            assert!(parse_accept_until(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
