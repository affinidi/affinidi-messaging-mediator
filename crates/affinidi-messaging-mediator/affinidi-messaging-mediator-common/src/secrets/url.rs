//! Backend URL parser.
//!
//! Every supported backend is identified by a URL:
//!
//! | Scheme           | Shape                                       | Example                                    |
//! |------------------|---------------------------------------------|--------------------------------------------|
//! | `keyring://`     | `keyring://<service>`                       | `keyring://affinidi-mediator`              |
//! | `file://`        | `file:///<absolute-path>[?encrypt=1]`       | `file:///var/lib/mediator/secrets.json`    |
//! | `aws_secrets://` | `aws_secrets://<region>/<namespace>`        | `aws_secrets://us-east-1/prod/mediator/`   |
//! | `gcp_secrets://` | `gcp_secrets://<project>/<namespace>`       | `gcp_secrets://my-proj/mediator-`          |
//! | `azure_keyvault://` | `azure_keyvault://<vault-name-or-url>`   | `azure_keyvault://my-vault`                |
//! | `vault://`       | `vault://<host[:port]>/<kv-path>[?auth=…]`  | `vault://vault.internal/secret/mediator`   |
//! | `k8s://`         | `k8s://<namespace>/<secret-name>`           | `k8s://affinidi/mediator-secrets`          |
//!
//! The `vault://` scheme accepts optional query parameters selecting a
//! non-default auth method and transport options — see `parse_vault`.
//! The `k8s://` scheme stores every mediator key inside one namespaced
//! `Secret` object — see `parse_k8s`.
//!
//! `string://` is intentionally not supported — inline secrets in
//! `mediator.toml` would defeat the whole point. CI scripts that used to
//! rely on it should use env-var overrides (`MEDIATOR_SECRETS_BACKEND=`
//! and per-entry overrides) against a `file://` or cloud backend.

use url::Url;

use crate::secrets::error::{Result, SecretStoreError};

/// Default Vault Kubernetes auth mount (the `kubernetes` auth backend).
pub const VAULT_DEFAULT_K8S_MOUNT: &str = "kubernetes";
/// Default in-pod ServiceAccount JWT path used by Kubernetes auth.
pub const VAULT_DEFAULT_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// Default Vault AppRole auth mount.
pub const VAULT_DEFAULT_APPROLE_MOUNT: &str = "approle";

/// Vault authentication method, parsed from the `?auth=` query parameter
/// of a `vault://` URL. Secret material (the token, or the AppRole
/// `role_id`/`secret_id`) is never carried in the URL — it is read from
/// the environment at login time so it never lands in `mediator.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultAuth {
    /// Token auth (default). Token read from `VAULT_TOKEN`.
    Token,
    /// Kubernetes auth: the pod's ServiceAccount JWT is exchanged for a
    /// Vault token against `mount` using `role`.
    Kubernetes {
        role: String,
        mount: String,
        jwt_path: String,
    },
    /// AppRole auth. `role_id`/`secret_id` read from `VAULT_ROLE_ID` /
    /// `VAULT_SECRET_ID` at login time.
    AppRole { mount: String },
}

impl VaultAuth {
    /// Whether this method can re-authenticate on its own (obtain a
    /// fresh token) — true for Kubernetes/AppRole, false for a static
    /// env-supplied token.
    pub fn is_renewable(&self) -> bool {
        !matches!(self, VaultAuth::Token)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendUrl {
    Keyring {
        service: String,
    },
    File {
        path: String,
        encrypted: bool,
    },
    Aws {
        region: String,
        namespace: String,
    },
    Gcp {
        project: String,
        namespace: String,
    },
    Azure {
        vault: String,
    },
    Vault {
        endpoint: String,
        path: String,
        /// Selected auth method (defaults to [`VaultAuth::Token`]).
        auth: VaultAuth,
        /// Vault Enterprise namespace (`X-Vault-Namespace` header), from
        /// `?namespace=`. Distinct from the per-key path namespace.
        enterprise_namespace: Option<String>,
        /// Skip TLS verification (`?insecure=1`) — dev/test only. Refused
        /// at open in a release build unless `MEDIATOR_ALLOW_INSECURE_VAULT=1`.
        insecure: bool,
        /// PEM CA bundle to trust for the Vault server (`?ca_cert=<path>`),
        /// the supported route for a private CA.
        ca_cert: Option<String>,
    },
    Kubernetes {
        /// Explicit namespace, or `None` to resolve from the in-pod
        /// ServiceAccount / kubeconfig context at connect time.
        namespace: Option<String>,
        /// Name of the `Secret` object holding every mediator key.
        secret_name: String,
    },
}

impl BackendUrl {
    /// A `file://` store without `?encrypt=1`: secrets are plaintext on disk.
    pub fn is_plaintext_file(&self) -> bool {
        matches!(
            self,
            BackendUrl::File {
                encrypted: false,
                ..
            }
        )
    }
}

/// Parse a backend URL. Returns a structured [`BackendUrl`] or an
/// `InvalidUrl` error with a human-actionable reason.
pub fn parse_url(raw: &str) -> Result<BackendUrl> {
    if raw.starts_with("string://") {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "inline 'string://' secrets are no longer supported — use 'file://' for \
                    local dev (with the --file-backend-encrypt hardening) or a cloud backend \
                    for production. Per-entry env var overrides are still available for CI."
                .into(),
        });
    }

    // `url::Url::parse` rejects some of our schemes because they're not
    // on its "special scheme" list, so we do a cheap prefix split first
    // and parse the body ourselves for keyring/aws/gcp/azure/vault. File
    // uses the real URL parser because the absolute path matters.
    let (scheme, rest) = split_scheme(raw)?;

    match scheme {
        "keyring" => parse_keyring(rest, raw),
        "file" => parse_file(raw),
        "aws_secrets" => parse_aws(rest, raw),
        "gcp_secrets" => parse_gcp(rest, raw),
        "azure_keyvault" => parse_azure(rest, raw),
        "vault" => parse_vault(rest, raw),
        "k8s" => parse_k8s(rest, raw),
        other => Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: format!(
                "unknown scheme '{other}://' — supported schemes: keyring, file, aws_secrets, \
                 gcp_secrets, azure_keyvault, vault, k8s"
            ),
        }),
    }
}

fn split_scheme(raw: &str) -> Result<(&str, &str)> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "expected '<scheme>://<body>'".into(),
        })?;
    Ok((scheme, rest))
}

fn parse_keyring(rest: &str, raw: &str) -> Result<BackendUrl> {
    let service = rest.trim_end_matches('/');
    if service.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "keyring:// requires a service name, e.g. keyring://affinidi-mediator".into(),
        });
    }
    if service.contains('/') {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "keyring:// service name must not contain '/'".into(),
        });
    }
    Ok(BackendUrl::Keyring {
        service: service.to_string(),
    })
}

/// Parse a boolean query value: `1|true|yes|on` or `0|false|no|off`, any
/// case. Anything else is an error rather than a silent `false` — for
/// `encrypt` that would mean writing secrets in plaintext.
fn parse_flag(raw: &str, scheme: &str, name: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: format!(
                "unrecognised value '{value}' for '{name}' on {scheme}:// URL — use 1/true/yes/on \
                 or 0/false/no/off"
            ),
        }),
    }
}

fn parse_file(raw: &str) -> Result<BackendUrl> {
    let url = Url::parse(raw).map_err(|e| SecretStoreError::InvalidUrl {
        url: raw.to_string(),
        reason: format!("malformed file:// URL: {e}"),
    })?;
    // `file://conf/secrets.json` parses as host `conf`, path
    // `/secrets.json` — a file at the filesystem root, not the relative
    // path the operator meant. Relative paths aren't supported at all.
    if let Some(host) = url.host_str().filter(|h| !h.is_empty()) {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: format!(
                "file:// URL names host '{host}'; the path must be absolute — use three \
                 slashes for an absolute path, e.g. file:///var/lib/mediator/secrets.json"
            ),
        });
    }
    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "file:// requires an absolute path, e.g. file:///var/lib/mediator/secrets.json"
                .into(),
        });
    }
    let mut encrypted = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "encrypt" => {
                encrypted = parse_flag(raw, "file", "encrypt", &v)?;
            }
            _ => {
                return Err(SecretStoreError::InvalidUrl {
                    url: raw.to_string(),
                    reason: format!("unknown query parameter '{k}' on file:// URL"),
                });
            }
        }
    }
    Ok(BackendUrl::File {
        path: path.to_string(),
        encrypted,
    })
}

fn parse_aws(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (region, namespace) = rest.split_once('/').ok_or_else(|| SecretStoreError::InvalidUrl {
        url: raw.to_string(),
        reason: "aws_secrets:// requires '<region>/<namespace>', e.g. aws_secrets://us-east-1/mediator/"
            .into(),
    })?;
    if region.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "aws_secrets:// requires a non-empty region".into(),
        });
    }
    Ok(BackendUrl::Aws {
        region: region.to_string(),
        namespace: normalize_namespace(namespace, &['/', '-', '_', '.'], '/'),
    })
}

/// Append `default_sep` to `ns` unless it already ends in one of `existing_seps`
/// (or is empty). The namespace is concatenated to keys without a separator at
/// call sites, so a bare `mediator` would otherwise produce names like
/// `mediatorprobe_xxx`. Operators who explicitly use a non-default separator
/// (`mediator-`, `mediator_`) keep their choice.
fn normalize_namespace(ns: &str, existing_seps: &[char], default_sep: char) -> String {
    if ns.is_empty() || ns.ends_with(existing_seps) {
        return ns.to_string();
    }
    let mut out = String::with_capacity(ns.len() + 1);
    out.push_str(ns);
    out.push(default_sep);
    out
}

fn parse_gcp(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (project, namespace) =
        rest.split_once('/')
            .ok_or_else(|| SecretStoreError::InvalidUrl {
                url: raw.to_string(),
                reason: "gcp_secrets:// requires '<project>/<namespace>'".into(),
            })?;
    if project.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "gcp_secrets:// requires a non-empty project id".into(),
        });
    }
    Ok(BackendUrl::Gcp {
        project: project.to_string(),
        // GCP secret IDs only allow [A-Za-z0-9_-], so '/' is not a legal
        // separator here — fall back to '-' for the auto-append.
        namespace: normalize_namespace(namespace, &['-', '_'], '-'),
    })
}

fn parse_azure(rest: &str, raw: &str) -> Result<BackendUrl> {
    let trimmed = rest.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "azure_keyvault:// requires a vault name or URL".into(),
        });
    }
    // Accept three input shapes:
    //   - `azure_keyvault://my-vault`
    //     → bare name, expand to `https://my-vault.vault.azure.net`.
    //     Works for Azure Commercial; the DNS is region-agnostic.
    //   - `azure_keyvault://my-vault.vault.usgovcloudapi.net`
    //     → full DNS name (the `.` in the host is the signal); prepend
    //     `https://`. Required for sovereign clouds (Government,
    //     China, Germany).
    //   - `azure_keyvault://https://my-vault.vault.azure.net`
    //     → already a full URL; pass through verbatim.
    let resolved = if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_string()
    } else if trimmed.contains('.') {
        format!("https://{trimmed}")
    } else {
        format!("https://{trimmed}.vault.azure.net")
    };
    Ok(BackendUrl::Azure { vault: resolved })
}

/// Parse a `vault://` URL.
///
/// Shape: `vault://<host[:port]>/<mount>[/<namespace>…][?<params>]`.
///
/// Query parameters (all optional):
///   - `auth=token|kubernetes|approle` — auth method (default `token`).
///   - `role=<name>` — Vault role (required for `kubernetes`).
///   - `k8s_mount=<mount>` — Kubernetes auth mount (default `kubernetes`).
///   - `jwt_path=<path>` — ServiceAccount JWT path
///     (default `/var/run/secrets/kubernetes.io/serviceaccount/token`).
///   - `approle_mount=<mount>` — AppRole auth mount (default `approle`).
///   - `namespace=<ns>` — Vault Enterprise namespace header.
///   - `insecure=1` — skip TLS verification (dev/test only; refused at
///     open in a release build unless `MEDIATOR_ALLOW_INSECURE_VAULT=1`).
///   - `ca_cert=<path>` — PEM CA bundle to trust for the Vault server.
///
/// No auth *secret* is accepted here: the token comes from `VAULT_TOKEN`
/// and AppRole credentials from `VAULT_ROLE_ID` / `VAULT_SECRET_ID`.
fn parse_vault(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (locator, query) = match rest.split_once('?') {
        Some((l, q)) => (l, Some(q)),
        None => (rest, None),
    };
    let (endpoint, path) = locator
        .split_once('/')
        .ok_or_else(|| SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "vault:// requires '<host>[:<port>]/<kv-path>'".into(),
        })?;
    if endpoint.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "vault:// requires a non-empty endpoint".into(),
        });
    }

    // Collect recognised query parameters. Values are taken verbatim
    // (no percent-decoding) — the recognised params (roles, mounts, a
    // JWT file path) don't need it, and avoiding it keeps `jwt_path`'s
    // slashes intact.
    let mut method: Option<&str> = None;
    let mut role: Option<String> = None;
    let mut k8s_mount = VAULT_DEFAULT_K8S_MOUNT.to_string();
    let mut jwt_path = VAULT_DEFAULT_JWT_PATH.to_string();
    let mut approle_mount = VAULT_DEFAULT_APPROLE_MOUNT.to_string();
    let mut enterprise_namespace: Option<String> = None;
    let mut insecure = false;
    let mut ca_cert: Option<String> = None;

    if let Some(query) = query {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "auth" => method = Some(v),
                "role" => role = Some(v.to_string()),
                "k8s_mount" => k8s_mount = v.to_string(),
                "jwt_path" => jwt_path = v.to_string(),
                "approle_mount" => approle_mount = v.to_string(),
                "namespace" => {
                    enterprise_namespace = (!v.is_empty()).then(|| v.to_string());
                }
                "insecure" => insecure = parse_flag(raw, "vault", "insecure", v)?,
                "ca_cert" => {
                    if v.is_empty() {
                        return Err(SecretStoreError::InvalidUrl {
                            url: raw.to_string(),
                            reason: "vault:// 'ca_cert' needs a path to a PEM CA bundle".into(),
                        });
                    }
                    ca_cert = Some(v.to_string());
                }
                other => {
                    return Err(SecretStoreError::InvalidUrl {
                        url: raw.to_string(),
                        reason: format!("unknown query parameter '{other}' on vault:// URL"),
                    });
                }
            }
        }
    }

    let auth = match method.unwrap_or("token") {
        "token" => VaultAuth::Token,
        "kubernetes" | "k8s" => {
            let role =
                role.filter(|r| !r.is_empty())
                    .ok_or_else(|| SecretStoreError::InvalidUrl {
                        url: raw.to_string(),
                        reason: "vault:// auth=kubernetes requires a 'role' query parameter".into(),
                    })?;
            VaultAuth::Kubernetes {
                role,
                mount: k8s_mount,
                jwt_path,
            }
        }
        "approle" => VaultAuth::AppRole {
            mount: approle_mount,
        },
        other => {
            return Err(SecretStoreError::InvalidUrl {
                url: raw.to_string(),
                reason: format!(
                    "unknown vault auth method '{other}' — supported: token, kubernetes, approle"
                ),
            });
        }
    };

    Ok(BackendUrl::Vault {
        endpoint: endpoint.to_string(),
        path: path.to_string(),
        auth,
        enterprise_namespace,
        insecure,
        ca_cert,
    })
}

/// Parse a `k8s://` URL.
///
/// Shape: `k8s://<namespace>/<secret-name>` or `k8s://<secret-name>`.
/// When the namespace segment is omitted (or empty), the backend resolves
/// it from the in-pod ServiceAccount / kubeconfig context at connect time.
fn parse_k8s(rest: &str, raw: &str) -> Result<BackendUrl> {
    if rest.contains('?') {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "k8s:// takes no query parameters".into(),
        });
    }
    if rest.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "k8s:// requires a Secret name, e.g. k8s://<namespace>/<secret-name>".into(),
        });
    }
    // Split on the first '/': `<namespace>/<secret-name>`. An empty
    // namespace segment (`k8s:///name`) means "resolve at connect time".
    // A trailing slash (`k8s://ns/`) leaves an empty secret name, which is
    // rejected below rather than silently treated as the name.
    let (namespace, secret_name) = match rest.split_once('/') {
        Some((ns, name)) => ((!ns.is_empty()).then(|| ns.to_string()), name),
        None => (None, rest),
    };
    if secret_name.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "k8s:// requires a non-empty Secret name".into(),
        });
    }
    if secret_name.contains('/') {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "k8s:// Secret name must not contain '/' — expected \
                     k8s://<namespace>/<secret-name>"
                .into(),
        });
    }
    Ok(BackendUrl::Kubernetes {
        namespace,
        secret_name: secret_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_ok() {
        let url = parse_url("keyring://affinidi-mediator").unwrap();
        assert_eq!(
            url,
            BackendUrl::Keyring {
                service: "affinidi-mediator".into()
            }
        );
    }

    #[test]
    fn keyring_missing_service_errors() {
        let err = parse_url("keyring://").unwrap_err();
        assert!(matches!(err, SecretStoreError::InvalidUrl { .. }));
    }

    #[test]
    fn keyring_with_slash_errors() {
        let err = parse_url("keyring://svc/extra").unwrap_err();
        assert!(matches!(err, SecretStoreError::InvalidUrl { .. }));
    }

    #[test]
    fn file_plaintext() {
        let url = parse_url("file:///var/lib/mediator/secrets.json").unwrap();
        assert_eq!(
            url,
            BackendUrl::File {
                path: "/var/lib/mediator/secrets.json".into(),
                encrypted: false,
            }
        );
    }

    #[test]
    fn file_with_encrypt_flag() {
        let url = parse_url("file:///tmp/m.json?encrypt=1").unwrap();
        assert_eq!(
            url,
            BackendUrl::File {
                path: "/tmp/m.json".into(),
                encrypted: true,
            }
        );
    }

    #[test]
    fn only_an_unencrypted_file_url_is_plaintext() {
        assert!(parse_url("file:///s.json").unwrap().is_plaintext_file());
        assert!(
            parse_url("file:///s.json?encrypt=0")
                .unwrap()
                .is_plaintext_file()
        );
        assert!(
            !parse_url("file:///s.json?encrypt=1")
                .unwrap()
                .is_plaintext_file()
        );
        assert!(!parse_url("k8s://ns/s").unwrap().is_plaintext_file());
    }

    #[test]
    fn file_missing_path_errors() {
        assert!(parse_url("file:///").is_err());
    }

    #[test]
    fn file_encrypt_values_are_case_insensitive() {
        for on in ["1", "true", "TRUE", "True", "yes", "On"] {
            let url = parse_url(&format!("file:///tmp/m.json?encrypt={on}")).unwrap();
            assert!(
                matches!(
                    url,
                    BackendUrl::File {
                        encrypted: true,
                        ..
                    }
                ),
                "{on}"
            );
        }
        for off in ["0", "false", "FALSE", "no", "off"] {
            let url = parse_url(&format!("file:///tmp/m.json?encrypt={off}")).unwrap();
            assert!(
                matches!(
                    url,
                    BackendUrl::File {
                        encrypted: false,
                        ..
                    }
                ),
                "{off}"
            );
        }
    }

    #[test]
    fn file_unknown_encrypt_value_is_rejected_not_plaintext() {
        for bad in ["enabled", "2", "", "y"] {
            let err = parse_url(&format!("file:///tmp/m.json?encrypt={bad}")).unwrap_err();
            match err {
                SecretStoreError::InvalidUrl { reason, .. } => {
                    assert!(reason.contains("encrypt"), "{bad}: {reason}")
                }
                other => panic!("{bad}: wrong error {other}"),
            }
        }
    }

    #[test]
    fn file_with_a_host_is_rejected() {
        // `file://conf/secrets.json` would otherwise mean `/secrets.json`.
        for raw in [
            "file://conf/secrets.json",
            "file://./conf/secrets.json",
            "file://example.com/var/secrets.json",
        ] {
            match parse_url(raw).unwrap_err() {
                SecretStoreError::InvalidUrl { reason, .. } => {
                    assert!(reason.contains("three slashes"), "{raw}: {reason}")
                }
                other => panic!("{raw}: wrong error {other}"),
            }
        }
    }

    #[test]
    fn aws_ok() {
        assert_eq!(
            parse_url("aws_secrets://us-east-1/prod/mediator/").unwrap(),
            BackendUrl::Aws {
                region: "us-east-1".into(),
                namespace: "prod/mediator/".into(),
            }
        );
    }

    #[test]
    fn aws_missing_slash_errors() {
        assert!(parse_url("aws_secrets://us-east-1").is_err());
    }

    #[test]
    fn aws_bare_namespace_gets_trailing_slash() {
        // No trailing separator → '/' is appended so concatenation with
        // a key produces 'glenn/vtc/mediator/probe' rather than the
        // confusing 'glenn/vtc/mediatorprobe'.
        assert_eq!(
            parse_url("aws_secrets://us-east-1/glenn/vtc/mediator").unwrap(),
            BackendUrl::Aws {
                region: "us-east-1".into(),
                namespace: "glenn/vtc/mediator/".into(),
            }
        );
    }

    #[test]
    fn aws_dash_namespace_is_preserved() {
        // Operators who pick '-' as the separator (to keep IAM
        // wildcards from spanning sibling apps) keep their choice.
        assert_eq!(
            parse_url("aws_secrets://us-east-1/mediator-").unwrap(),
            BackendUrl::Aws {
                region: "us-east-1".into(),
                namespace: "mediator-".into(),
            }
        );
    }

    #[test]
    fn aws_empty_namespace_stays_empty() {
        assert_eq!(
            parse_url("aws_secrets://us-east-1/").unwrap(),
            BackendUrl::Aws {
                region: "us-east-1".into(),
                namespace: String::new(),
            }
        );
    }

    #[test]
    fn gcp_ok() {
        assert_eq!(
            parse_url("gcp_secrets://my-proj/mediator-").unwrap(),
            BackendUrl::Gcp {
                project: "my-proj".into(),
                namespace: "mediator-".into(),
            }
        );
    }

    #[test]
    fn gcp_bare_namespace_gets_trailing_dash() {
        // GCP secret IDs disallow '/', so '-' is the auto-append.
        assert_eq!(
            parse_url("gcp_secrets://my-proj/mediator").unwrap(),
            BackendUrl::Gcp {
                project: "my-proj".into(),
                namespace: "mediator-".into(),
            }
        );
    }

    #[test]
    fn gcp_underscore_namespace_is_preserved() {
        assert_eq!(
            parse_url("gcp_secrets://my-proj/mediator_").unwrap(),
            BackendUrl::Gcp {
                project: "my-proj".into(),
                namespace: "mediator_".into(),
            }
        );
    }

    #[test]
    fn azure_bare_name_expands_to_commercial_cloud_url() {
        assert_eq!(
            parse_url("azure_keyvault://my-vault").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.azure.net".into()
            }
        );
    }

    #[test]
    fn azure_full_https_url_is_passed_through() {
        assert_eq!(
            parse_url("azure_keyvault://https://my-vault.vault.azure.net").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.azure.net".into()
            }
        );
    }

    #[test]
    fn azure_sovereign_dns_name_gets_https_prefix() {
        // A DNS name with `.` in it signals a sovereign-cloud host;
        // the parser prepends `https://` rather than treating it as a
        // bare name that would expand to the commercial DNS.
        assert_eq!(
            parse_url("azure_keyvault://my-vault.vault.usgovcloudapi.net").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.usgovcloudapi.net".into()
            }
        );
    }

    #[test]
    fn azure_empty_input_errors() {
        assert!(parse_url("azure_keyvault://").is_err());
    }

    #[test]
    fn vault_ok() {
        assert_eq!(
            parse_url("vault://vault.internal/secret/mediator").unwrap(),
            BackendUrl::Vault {
                endpoint: "vault.internal".into(),
                path: "secret/mediator".into(),
                auth: VaultAuth::Token,
                enterprise_namespace: None,
                insecure: false,
                ca_cert: None,
            }
        );
    }

    #[test]
    fn vault_defaults_to_token_auth() {
        let url = parse_url("vault://vault.internal/secret").unwrap();
        match url {
            BackendUrl::Vault { auth, .. } => assert_eq!(auth, VaultAuth::Token),
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    #[test]
    fn vault_kubernetes_auth_with_defaults() {
        let url =
            parse_url("vault://vault.internal/secret/mediator?auth=kubernetes&role=med").unwrap();
        assert_eq!(
            url,
            BackendUrl::Vault {
                endpoint: "vault.internal".into(),
                path: "secret/mediator".into(),
                auth: VaultAuth::Kubernetes {
                    role: "med".into(),
                    mount: VAULT_DEFAULT_K8S_MOUNT.into(),
                    jwt_path: VAULT_DEFAULT_JWT_PATH.into(),
                },
                enterprise_namespace: None,
                insecure: false,
                ca_cert: None,
            }
        );
    }

    #[test]
    fn vault_kubernetes_auth_requires_role() {
        assert!(parse_url("vault://vault.internal/secret?auth=kubernetes").is_err());
    }

    #[test]
    fn vault_kubernetes_auth_custom_mount_and_jwt_path() {
        let url = parse_url(
            "vault://vault.internal/secret/mediator?auth=kubernetes&role=r&k8s_mount=k8s-prod&jwt_path=/var/run/token",
        )
        .unwrap();
        match url {
            BackendUrl::Vault { auth, .. } => assert_eq!(
                auth,
                VaultAuth::Kubernetes {
                    role: "r".into(),
                    mount: "k8s-prod".into(),
                    jwt_path: "/var/run/token".into(),
                }
            ),
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    #[test]
    fn vault_approle_auth() {
        let url = parse_url("vault://vault.internal/secret?auth=approle&approle_mount=my-approle")
            .unwrap();
        match url {
            BackendUrl::Vault { auth, .. } => assert_eq!(
                auth,
                VaultAuth::AppRole {
                    mount: "my-approle".into()
                }
            ),
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    #[test]
    fn vault_enterprise_namespace_and_insecure() {
        let url = parse_url("vault://vault.internal/secret/mediator?namespace=team-a&insecure=1")
            .unwrap();
        match url {
            BackendUrl::Vault {
                enterprise_namespace,
                insecure,
                auth,
                ..
            } => {
                assert_eq!(enterprise_namespace, Some("team-a".into()));
                assert!(insecure);
                assert_eq!(auth, VaultAuth::Token);
            }
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    #[test]
    fn vault_insecure_value_must_be_recognised() {
        assert!(parse_url("vault://vault.internal/secret?insecure=maybe").is_err());
        match parse_url("vault://vault.internal/secret?insecure=0").unwrap() {
            BackendUrl::Vault { insecure, .. } => assert!(!insecure),
            other => panic!("expected Vault, got {other:?}"),
        }
    }

    #[test]
    fn vault_ca_cert() {
        match parse_url("vault://vault.internal/secret?ca_cert=/etc/vault/ca.pem").unwrap() {
            BackendUrl::Vault {
                ca_cert, insecure, ..
            } => {
                assert_eq!(ca_cert.as_deref(), Some("/etc/vault/ca.pem"));
                assert!(!insecure);
            }
            other => panic!("expected Vault, got {other:?}"),
        }
        assert!(parse_url("vault://vault.internal/secret?ca_cert=").is_err());
    }

    #[test]
    fn vault_unknown_query_param_errors() {
        assert!(parse_url("vault://vault.internal/secret?bogus=1").is_err());
    }

    #[test]
    fn vault_unknown_auth_method_errors() {
        assert!(parse_url("vault://vault.internal/secret?auth=ldap").is_err());
    }

    #[test]
    fn k8s_with_namespace() {
        assert_eq!(
            parse_url("k8s://affinidi/mediator-secrets").unwrap(),
            BackendUrl::Kubernetes {
                namespace: Some("affinidi".into()),
                secret_name: "mediator-secrets".into(),
            }
        );
    }

    #[test]
    fn k8s_without_namespace() {
        assert_eq!(
            parse_url("k8s://mediator-secrets").unwrap(),
            BackendUrl::Kubernetes {
                namespace: None,
                secret_name: "mediator-secrets".into(),
            }
        );
    }

    #[test]
    fn k8s_empty_namespace_segment_is_none() {
        assert_eq!(
            parse_url("k8s:///mediator-secrets").unwrap(),
            BackendUrl::Kubernetes {
                namespace: None,
                secret_name: "mediator-secrets".into(),
            }
        );
    }

    #[test]
    fn k8s_missing_secret_name_errors() {
        assert!(parse_url("k8s://").is_err());
        assert!(parse_url("k8s://affinidi/").is_err());
    }

    #[test]
    fn k8s_extra_path_segment_errors() {
        assert!(parse_url("k8s://ns/a/b").is_err());
    }

    #[test]
    fn k8s_query_param_errors() {
        assert!(parse_url("k8s://ns/secret?key=seed").is_err());
    }

    #[test]
    fn string_rejected_with_helpful_pointer() {
        let err = parse_url("string://foo").unwrap_err();
        match err {
            SecretStoreError::InvalidUrl { reason, .. } => {
                assert!(reason.contains("file://"));
                assert!(reason.contains("env var"));
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn unknown_scheme_errors() {
        assert!(parse_url("redis://foo").is_err());
    }
}
