//! AWS Secrets Manager backend (feature `secrets-aws`).
//!
//! Every secret `key` is stored as an AWS secret named
//! `<namespace><key>`. Both binary and string-form secrets live in the
//! `SecretString` field (base64url encoded) so everything round-trips
//! identically across backends.
//!
//! Calls go through [`super::super::retry::with_retry`] with
//! [`AwsRetryPolicy`]: ThrottlingException / TooManyRequestsException /
//! InternalServiceError / RequestTimeout / connection-level failures
//! retry; ResourceNotFoundException, validation, and access-denied
//! errors short-circuit so the caller's error path runs unchanged.
//!
//! A write after a read is conditional, like Vault's `cas`: a read can lag
//! a write, and an unconditional write would drop what it did not see.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-aws")]
use crate::secrets::retry::{RetryPolicy, Retryable, with_retry};
#[cfg(feature = "secrets-aws")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-aws")]
use async_trait::async_trait;

const BACKEND_LABEL: &str = "aws_secrets";

#[cfg(feature = "secrets-aws")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Aws { region, namespace } = url else {
        return Err(SecretStoreError::Other(
            "internal error: aws backend received non-aws URL".into(),
        ));
    };
    Ok(std::sync::Arc::new(AwsStore {
        region,
        namespace,
        client: tokio::sync::OnceCell::new(),
        seen: Default::default(),
    }))
}

#[cfg(not(feature = "secrets-aws"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-aws' feature; rebuild with \
                 `cargo build --features secrets-aws` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-aws")]
pub struct AwsStore {
    region: String,
    namespace: String,
    /// Built on first use and kept: loading the config runs the credential
    /// provider chain (IMDS / STS on IRSA and ECS roles), and the client
    /// owns the connection pool and credential cache.
    client: tokio::sync::OnceCell<aws_sdk_secretsmanager::Client>,
    /// Per secret name, the condition for the next write; none: unconditional.
    seen: std::sync::Mutex<std::collections::HashMap<String, Seen>>,
}

#[cfg(feature = "secrets-aws")]
#[derive(Clone, Debug)]
enum Seen {
    /// Read with no current value.
    Absent,
    /// Read or written at this `VersionId`.
    Version(String),
}

#[cfg(feature = "secrets-aws")]
const AWSCURRENT: &str = "AWSCURRENT";

#[cfg(feature = "secrets-aws")]
impl AwsStore {
    fn secret_name(&self, key: &str) -> String {
        format!("{}{}", self.namespace, key)
    }

    fn seen(&self, name: &str) -> Option<Seen> {
        self.seen.lock().ok()?.get(name).cloned()
    }

    fn remember(&self, name: &str, seen: Option<Seen>) {
        if let Ok(mut map) = self.seen.lock() {
            match seen {
                Some(seen) => map.insert(name.to_string(), seen),
                None => map.remove(name),
            };
        }
    }

    fn conflict(key: &str) -> SecretStoreError {
        SecretStoreError::Conflict {
            backend: BACKEND_LABEL,
            key: key.to_string(),
        }
    }

    fn failed(call: &str, name: &str, err: &(dyn std::error::Error + 'static)) -> SecretStoreError {
        SecretStoreError::Unreachable {
            backend: BACKEND_LABEL,
            reason: format!("{call}({name}) failed: {}", format_error_chain(err)),
        }
    }

    /// `CreateSecret`; a name created meanwhile is a conflict.
    async fn create(
        &self,
        key: &str,
        name: &str,
        encoded: &str,
        token: &str,
    ) -> Result<Option<String>> {
        let client = self.client().await;
        let created = with_retry(&format!("CreateSecret({name})"), &AwsRetryPolicy, || {
            let client = client.clone();
            async move {
                client
                    .create_secret()
                    .name(name)
                    .secret_string(encoded)
                    .client_request_token(token)
                    .send()
                    .await
            }
        })
        .await;
        match created {
            Ok(r) => Ok(r.version_id),
            Err(err) if format_error_chain(&err).contains("ResourceExistsException") => {
                Err(Self::conflict(key))
            }
            Err(err) => Err(Self::failed("CreateSecret", name, &err)),
        }
    }

    /// Writes `encoded` as current if `seen` still holds; returns the new `VersionId`.
    async fn write(
        &self,
        key: &str,
        name: &str,
        encoded: &str,
        seen: Option<Seen>,
    ) -> Result<Option<String>> {
        let client = self.client().await;
        // One token per write, reused by its retries: no duplicate version.
        let token = uuid::Uuid::new_v4().to_string();
        let staged = with_retry(&format!("PutSecretValue({name})"), &AwsRetryPolicy, || {
            let client = client.clone();
            let mut put = client
                .put_secret_value()
                .secret_id(name)
                .secret_string(encoded)
                .client_request_token(&token);
            if seen.is_some() {
                put = put.version_stages("AWSPENDING");
            }
            async move { put.send().await }
        })
        .await;
        let staged = match staged {
            Ok(r) => r,
            Err(err) if format_error_chain(&err).contains("ResourceNotFoundException") => {
                return match seen {
                    // Deleted since it was read.
                    Some(Seen::Version(_)) => Err(Self::conflict(key)),
                    None | Some(Seen::Absent) => self.create(key, name, encoded, &token).await,
                };
            }
            Err(err) => return Err(Self::failed("PutSecretValue", name, &err)),
        };
        let current = staged
            .version_stages
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|stage| stage == AWSCURRENT);
        let last = match after_stage(seen.as_ref(), current) {
            Next::Done => return Ok(staged.version_id),
            Next::Conflict => return Err(Self::conflict(key)),
            Next::Move(last) => last.to_string(),
        };
        let moved = with_retry(
            &format!("UpdateSecretVersionStage({name})"),
            &AwsRetryPolicy,
            || {
                let client = client.clone();
                let token = token.clone();
                let last = last.clone();
                async move {
                    client
                        .update_secret_version_stage()
                        .secret_id(name)
                        .version_stage(AWSCURRENT)
                        .move_to_version_id(token)
                        .remove_from_version_id(last)
                        .send()
                        .await
                }
            },
        )
        .await;
        let err = match moved {
            Ok(_) => return Ok(staged.version_id),
            Err(err) => err,
        };
        let msg = format_error_chain(&err);
        if !is_stale_label_move(&msg) {
            return Err(Self::failed("UpdateSecretVersionStage", name, &err));
        }
        // The refusal names the current version: ours if only a retry's reply was lost.
        if msg.to_ascii_lowercase().contains(&token) {
            Ok(staged.version_id)
        } else {
            Err(Self::conflict(key))
        }
    }

    /// The shared client (cheap to clone: internally `Arc`-wrapped).
    async fn client(&self) -> aws_sdk_secretsmanager::Client {
        self.client
            .get_or_init(|| async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_sdk_secretsmanager::config::Region::new(
                        self.region.clone(),
                    ))
                    .load()
                    .await;
                aws_sdk_secretsmanager::Client::new(&config)
            })
            .await
            .clone()
    }
}

/// `RetryPolicy` for AWS Secrets Manager. Pure string match on the
/// SDK error display because the typed `*Error` enums sit behind
/// `#[non_exhaustive]` wrappers; touching specific variants ties
/// us to a specific SDK minor.
#[cfg(feature = "secrets-aws")]
pub(crate) struct AwsRetryPolicy;

/// Join the `Display` form of `err` with every `source()` in its chain.
/// `SdkError::Display` only emits the kind ("service error"); the actual
/// AWS reason (`ResourceNotFoundException: ...`, `AccessDeniedException:
/// User ... is not authorized`, etc.) lives inside `source()`. Without
/// this both the retry classifier and the surfaced error message are
/// blind to anything past the wrapper.
#[cfg(feature = "secrets-aws")]
fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur = err.source();
    while let Some(src) = cur {
        parts.push(src.to_string());
        cur = src.source();
    }
    parts.join(" | ")
}

/// What a staged write still needs, given what was seen before it.
#[cfg(feature = "secrets-aws")]
#[derive(Debug, PartialEq, Eq)]
enum Next<'a> {
    Done,
    Conflict,
    Move(&'a str),
}

#[cfg(feature = "secrets-aws")]
fn after_stage(seen: Option<&Seen>, current: bool) -> Next<'_> {
    match seen {
        None => Next::Done,
        // A secret's first version is made current whatever stage is asked.
        Some(_) if current => Next::Done,
        // Read as absent, but it has a value now.
        Some(Seen::Absent) => Next::Conflict,
        Some(Seen::Version(last)) => Next::Move(last),
    }
}

/// Whether moving `AWSCURRENT` was refused because `RemoveFromVersionId` is stale.
#[cfg(feature = "secrets-aws")]
fn is_stale_label_move(msg: &str) -> bool {
    msg.contains("InvalidParameterException") && msg.contains("RemoveFromVersionId")
}

#[cfg(feature = "secrets-aws")]
impl<E: std::error::Error + 'static> RetryPolicy<E> for AwsRetryPolicy {
    fn classify(&self, err: &E) -> Retryable {
        let msg = format_error_chain(err);
        // Hard "do not retry" cases first — these are deterministic
        // misconfigurations, not transient failures. Retrying them
        // wastes time and clutters the audit log with bogus retries.
        const TERMINAL: &[&str] = &[
            "ResourceNotFoundException",
            "AccessDeniedException",
            "ValidationException",
            "InvalidParameterException",
            "InvalidRequestException",
            "DecryptionFailure",
            "EncryptionFailure",
        ];
        if TERMINAL.iter().any(|t| msg.contains(t)) {
            return Retryable::No;
        }
        // Transient failures we should retry. Throttling, internal,
        // request-timeout, dns / TCP errors all fall through here.
        const TRANSIENT: &[&str] = &[
            "ThrottlingException",
            "TooManyRequestsException",
            "InternalServiceError",
            "InternalServerError",
            "ServiceUnavailable",
            "RequestTimeout",
            "RequestTimeoutException",
            "dispatch failure",
            "io error",
            "timeout",
            "connection reset",
            "connection closed",
        ];
        if TRANSIENT.iter().any(|t| msg.contains(t)) {
            return Retryable::Yes { retry_after: None };
        }
        // Default: don't retry. Better to surface an unknown error
        // immediately than to mask a real bug under three identical
        // SDK calls.
        Retryable::No
    }
}

#[cfg(feature = "secrets-aws")]
#[async_trait]
impl SecretStore for AwsStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let name = self.secret_name(key);
        let client = self.client().await;
        let label = format!("GetSecretValue({name})");
        // The retry helper takes a closure returning a fresh future
        // each attempt; we re-issue the SDK call (the cloned client
        // is cheap — internally `Arc`-wrapped) and translate the
        // outcome at the call site.
        let response = with_retry(&label, &AwsRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move { client.get_secret_value().secret_id(&name).send().await }
        })
        .await;
        let response = match response {
            Ok(r) => r,
            Err(sdk_err) => {
                let msg = format_error_chain(&sdk_err);
                if msg.contains("ResourceNotFoundException") {
                    self.remember(&name, Some(Seen::Absent));
                    return Ok(None);
                }
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("GetSecretValue({name}) failed: {msg}"),
                });
            }
        };
        self.remember(&name, response.version_id.clone().map(Seen::Version));
        let Some(encoded) = response.secret_string else {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "AWS secret has no SecretString (binary-only secrets not supported)".into(),
            });
        };
        let bytes =
            B64URL
                .decode(encoded.as_bytes())
                .map_err(|e| SecretStoreError::InvalidShape {
                    key: key.to_string(),
                    reason: format!("AWS SecretString is not valid base64: {e}"),
                })?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let name = self.secret_name(key);
        let written = self
            .write(key, &name, &B64URL.encode(value), self.seen(&name))
            .await;
        let seen = match &written {
            Ok(Some(version)) => Some(Seen::Version(version.clone())),
            _ => None,
        };
        self.remember(&name, seen);
        written.map(|_| ())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let name = self.secret_name(key);
        self.remember(&name, None);
        let client = self.client().await;
        let label = format!("DeleteSecret({name})");
        let result = with_retry(&label, &AwsRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move {
                client
                    .delete_secret()
                    .secret_id(&name)
                    .force_delete_without_recovery(true)
                    .send()
                    .await
            }
        })
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(err) if format_error_chain(&err).contains("ResourceNotFoundException") => Ok(()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("DeleteSecret({name}) failed: {}", format_error_chain(&err)),
            }),
        }
    }

    /// Walks `ListSecrets` pages until exhausted and returns the full
    /// secret names (region-wide — the configured `namespace` is *not*
    /// applied as a server-side filter, because the wizard's discovery
    /// flow wants to surface every name already in use, not just the
    /// ones inside the operator's chosen namespace). Each retry batch
    /// is its own `with_retry` invocation so a transient throttle on
    /// page N doesn't lose pages 1..N-1.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        let client = self.client().await;
        let mut names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let token_for_label = next_token
                .as_deref()
                .map(|t| format!("...{}", &t[t.len().saturating_sub(8)..]))
                .unwrap_or_else(|| "first".into());
            let label = format!("ListSecrets({token_for_label})");
            let response = with_retry(&label, &AwsRetryPolicy, || {
                let client = client.clone();
                let token = next_token.clone();
                async move {
                    let mut req = client.list_secrets();
                    if let Some(t) = token {
                        req = req.next_token(t);
                    }
                    req.send().await
                }
            })
            .await
            .map_err(|err| SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("ListSecrets failed: {}", format_error_chain(&err)),
            })?;

            if let Some(entries) = response.secret_list {
                for entry in entries {
                    if let Some(name) = entry.name {
                        names.push(name);
                    }
                }
            }
            match response.next_token {
                Some(t) if !t.is_empty() => next_token = Some(t),
                _ => break,
            }
        }
        Ok(names)
    }

    /// The region-wide listing narrowed to this store's namespace, with
    /// the namespace stripped back off.
    async fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self
            .list_namespace()
            .await?
            .into_iter()
            .filter_map(|name| name.strip_prefix(&self.namespace).map(str::to_string))
            .collect())
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-aws")]
mod policy_tests {
    use super::*;

    /// Minimal stand-in error type for testing the policy's classifier
    /// without a live AWS SDK error to construct. Optionally chains a
    /// `source` so we can exercise the `format_error_chain` walker that
    /// the classifier and surfaced error messages now rely on.
    #[derive(Debug)]
    struct StubErr {
        msg: &'static str,
        source: Option<Box<StubErr>>,
    }
    impl StubErr {
        fn new(msg: &'static str) -> Self {
            Self { msg, source: None }
        }
        fn with_source(msg: &'static str, source: StubErr) -> Self {
            Self {
                msg,
                source: Some(Box::new(source)),
            }
        }
    }
    impl std::fmt::Display for StubErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.msg)
        }
    }
    impl std::error::Error for StubErr {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_deref()
                .map(|s| s as &(dyn std::error::Error + 'static))
        }
    }

    fn classify(msg: &'static str) -> Retryable {
        AwsRetryPolicy.classify(&StubErr::new(msg))
    }

    #[tokio::test]
    async fn the_client_is_built_once_and_reused() {
        // Loading the config does no network I/O (credentials resolve
        // lazily), so this runs offline.
        let store = AwsStore {
            region: "us-east-1".into(),
            namespace: String::new(),
            client: tokio::sync::OnceCell::new(),
            seen: Default::default(),
        };
        assert!(!store.client.initialized());
        let first = store.client().await;
        assert!(store.client.initialized());
        let cached = store.client.get().unwrap() as *const _;
        let second = store.client().await;
        assert_eq!(
            store.client.get().unwrap() as *const _,
            cached,
            "the second call reuses the cached client"
        );
        assert_eq!(
            first.config().region().map(|r| r.as_ref().to_string()),
            Some("us-east-1".to_string())
        );
        drop(second);
    }

    #[test]
    fn not_found_is_terminal() {
        assert!(matches!(
            classify("service error: ResourceNotFoundException: secret does not exist"),
            Retryable::No
        ));
    }

    #[test]
    fn access_denied_is_terminal() {
        assert!(matches!(
            classify("AccessDeniedException: User is not authorized"),
            Retryable::No
        ));
    }

    #[test]
    fn throttling_is_retryable() {
        match classify("ThrottlingException: Rate exceeded") {
            Retryable::Yes { retry_after: None } => {}
            other => panic!(
                "expected retryable without retry_after, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn dispatch_failure_is_retryable() {
        // Network-level error — the SDK wraps these as "dispatch
        // failure" with the underlying I/O error inside.
        assert!(matches!(
            classify("dispatch failure: io error: connection reset"),
            Retryable::Yes { .. }
        ));
    }

    #[test]
    fn unknown_error_is_terminal_by_default() {
        // Conservative default — surfacing an unknown error
        // immediately beats hiding a real bug under three identical
        // failures.
        assert!(matches!(
            classify("some new error variant we have not seen before"),
            Retryable::No
        ));
    }

    #[test]
    fn classifier_sees_inner_source_message() {
        // The aws-sdk-rust SdkError::Display only emits "service error"
        // — the actual exception name (e.g. AccessDeniedException) lives
        // in the source chain. The classifier must walk it or every
        // terminal/transient case looks the same.
        let inner = StubErr::new("AccessDeniedException: User is not authorized");
        let outer = StubErr::with_source("service error", inner);
        assert!(matches!(AwsRetryPolicy.classify(&outer), Retryable::No));
    }

    #[test]
    fn chain_walker_concatenates_with_pipe_separator() {
        let inner = StubErr::new("InvalidParameterException: bad name");
        let outer = StubErr::with_source("service error", inner);
        let formatted = format_error_chain(&outer);
        assert!(
            formatted.contains("service error"),
            "outer message must be present: {formatted}"
        );
        assert!(
            formatted.contains("InvalidParameterException"),
            "inner message must be present: {formatted}"
        );
        assert!(
            formatted.contains(" | "),
            "expected ' | ' separator: {formatted}"
        );
    }

    #[test]
    fn only_a_moved_label_is_a_stale_label_move() {
        // Messages as AWS returns them (live, 2026-11-19).
        let cases = [
            (
                "InvalidParameterException: When you move staging label AWSCURRENT, if you \
                 specify RemoveFromVersionId, it must be set to the version that currently \
                 has the staging label 2F42BDF8-0B67-4F53-9EAA-FE6069C7914D.",
                true,
            ),
            ("InvalidParameterException: bad name", false),
            ("AccessDeniedException: User is not authorized", false),
        ];
        for (msg, stale) in cases {
            assert_eq!(is_stale_label_move(msg), stale, "{msg}");
        }
    }

    #[test]
    fn a_staged_write_is_done_refused_or_moved_by_what_was_seen() {
        let v = Seen::Version("v1".into());
        let cases = [
            (None, false, Next::Done),
            (None, true, Next::Done),
            (Some(&Seen::Absent), true, Next::Done),
            (Some(&Seen::Absent), false, Next::Conflict),
            (Some(&v), true, Next::Done),
            (Some(&v), false, Next::Move("v1")),
        ];
        for (seen, current, next) in cases {
            assert_eq!(
                after_stage(seen, current),
                next,
                "{seen:?} current={current}"
            );
        }
    }

    /// Opt-in live test of conditional writes. Needs AWS credentials that
    /// may create, write, move stages on and delete secrets under the URL's
    /// prefix. Run with:
    ///   MEDIATOR_TEST_AWS_URL=aws_secrets://ap-southeast-1/ci-mediator/ \
    ///   cargo test -p affinidi-messaging-mediator-common \
    ///     --features secrets-aws aws_live_conditional_writes -- --ignored
    #[tokio::test]
    #[ignore]
    async fn aws_live_conditional_writes() {
        use crate::secrets::url::parse_url;
        let url = std::env::var("MEDIATOR_TEST_AWS_URL")
            .expect("set MEDIATOR_TEST_AWS_URL to run the live AWS test");
        let ours = open(parse_url(&url).unwrap()).unwrap();
        let theirs = open(parse_url(&url).unwrap()).unwrap();
        let key = format!("mediator_probe_{}", uuid::Uuid::new_v4().simple());
        let conflict = |r: Result<()>| matches!(r, Err(SecretStoreError::Conflict { .. }));

        // A write built on a read that showed no value is refused once
        // there is one, as a stale read would be.
        assert_eq!(theirs.get(&key).await.unwrap(), None);
        ours.put(&key, &[1]).await.unwrap();
        assert!(conflict(theirs.put(&key, &[2]).await));
        assert_eq!(theirs.get(&key).await.unwrap(), Some(vec![1]));
        theirs.put(&key, &[2]).await.unwrap();

        // A write built on an older version is refused too.
        assert!(conflict(ours.put(&key, &[3]).await));
        assert_eq!(ours.get(&key).await.unwrap(), Some(vec![2]));
        ours.put(&key, &[3]).await.unwrap();
        ours.put(&key, &[4]).await.unwrap();
        assert_eq!(theirs.get(&key).await.unwrap(), Some(vec![4]));

        ours.delete(&key).await.unwrap();
    }
}
