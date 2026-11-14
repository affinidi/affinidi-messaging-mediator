//! Minting phase: the mediator DID, its operating keys, the admin DID and
//! the JWT secret, as values; no I/O.

use crate::app;
use crate::app::{AdminMode, DidMethod};
use crate::consts::*;
use crate::provision::MintedArtefacts;
use crate::provision::backend::validate_operating_secrets;
use crate::{config_writer, exit, generators, recipe, vta};

/// Project a [`vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterialV2`]
/// onto the `Secret` shape the mediator-common secrets store expects.
///
/// Emits the signing key, the key-agreement key, **and every additional
/// signing key the VTA minted**, each keyed by its full DID-URL
/// verification-method id. The private bytes move through
/// `Secret::from_multibase`, which decodes the multibase string, detects the
/// key type from its multicodec, and populates the secret's zeroized buffers.
///
/// The additional keys are empty for a v1 template, which is what the mediator
/// uses today. Handling them anyway is not speculative: they are published in
/// the DID document as verification methods, so a mediator that stored only the
/// first two would advertise a key it cannot use — and the failure surfaces at
/// a peer as an unverifiable signature, a long way from here.
#[cfg(feature = "vta")]
pub(crate) fn did_key_material_to_secrets(
    material: &vta_sdk::sealed_transfer::template_bootstrap::DidKeyMaterialV2,
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    let decode = |slot: &str, key_id: &str, private: &str| {
        Secret::from_multibase(private, Some(key_id))
            .map_err(|e| anyhow::anyhow!("decode {slot} private key ({key_id}): {e}"))
    };

    let mut secrets = vec![
        decode(
            &material.signing_key.slot,
            &material.signing_key.key_id,
            &material.signing_key.private_key_multibase,
        )?,
        decode(
            &material.ka_key.slot,
            &material.ka_key.key_id,
            &material.ka_key.private_key_multibase,
        )?,
    ];
    for extra in &material.additional_signing_keys {
        secrets.push(decode(
            &extra.slot,
            &extra.key_id,
            &extra.private_key_multibase,
        )?);
    }
    Ok(secrets)
}

/// Convert a flat `Vec<SecretEntry>` (the `ContextProvisionBundle`
/// shape used by the OfflineExport path) into `Secret` values the
/// mediator's runtime loader consumes.
///
/// Sibling to [`did_key_material_to_secrets`] — that one walks a
/// typed (signing, ka) pair grouped by DID; this one iterates a flat
/// list keyed by `key_id` and trusts the multibase prefix on each
/// entry to disambiguate Ed25519 / X25519 / P-256. The loader's
/// `Secret::from_multibase` does the actual key-type detection.
///
/// Both helpers feed into the same downstream sink (`provision_secrets`
/// in `secrets/mod.rs`); the duplication is in *iteration shape*
/// only, not in per-key handling.
#[cfg(feature = "vta")]
pub(crate) fn secret_entries_to_secrets(
    entries: &[vta_sdk::did_secrets::SecretEntry],
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    entries
        .iter()
        .map(|entry| {
            Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id))
                .map_err(|e| anyhow::anyhow!("decode key {}: {e}", entry.key_id))
        })
        .collect()
}

/// Project a completed [`vta::VtaSession`] onto the
/// [`vta_sdk::did_secrets::DidSecretsBundle`] shape the mediator's
/// runtime expects in its VTA fallback cache.
///
/// The mediator boots, tries to reach its VTA, and on any failure
/// (network, timeout, or VTA-side validation — `integration::startup`
/// in vta-sdk doesn't distinguish) loads this bundle to keep serving
/// DIDComm traffic with its existing keys. Pre-populating it at
/// wizard time means first-boot survives VTA unavailability.
///
/// Returns `None` for [`VtaReply::AdminOnly`](crate::vta::VtaReply::AdminOnly) sessions — those don't
/// carry a VTA-provisioned integration DID (the mediator brought its
/// own via the Did step), so there's nothing for the VTA cache to
/// seed. `TemplateBootstrap` and `ContextProvision` replies both map
/// to a bundle; their shapes differ but the target is unified.
#[cfg(feature = "vta")]
pub(crate) fn build_did_secrets_bundle(
    session: &vta::VtaSession,
) -> Option<vta_sdk::did_secrets::DidSecretsBundle> {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

    if let Some(provision) = session.as_full_provision() {
        // TemplateBootstrap path. Every key the VTA minted for this DID, each
        // typed by what the bundle *says* it is rather than by what this code
        // assumes.
        //
        // Both halves of that changed. The discriminants used to be pinned to
        // `Ed25519` / `X25519` literals "to match the didcomm-mediator
        // template's renderer contract" — true while a template could not ask
        // for anything else, and a mislabel the moment one can. `SlotKeyPair`
        // now carries the algorithm the VTA actually minted, so read it.
        //
        // And the additional signing keys are projected too. They are published
        // in the DID document as verification methods, so storing only the pair
        // would advertise a key the mediator cannot sign with — surfacing at a
        // peer as an unverifiable signature, far from here. Empty for a v1
        // template, which is what the mediator uses today.
        let material = provision.integration_key()?;
        let entry = |k: &vta_sdk::sealed_transfer::template_bootstrap::SlotKeyPair| SecretEntry {
            key_id: k.key_id.clone(),
            key_type: k.key_type.clone(),
            private_key_multibase: k.private_key_multibase.clone(),
        };
        let mut secrets = vec![entry(&material.signing_key), entry(&material.ka_key)];
        secrets.extend(material.additional_signing_keys.iter().map(entry));
        return Some(DidSecretsBundle {
            did: provision.integration_did()?.to_string(),
            secrets,
        });
    }

    if let Some(bundle) = session.as_context_export() {
        // OfflineExport path — ContextProvisionBundle already carries
        // a flat `Vec<SecretEntry>` typed by the VTA, so we pass it
        // through verbatim (including any future key types the VTA
        // adds).
        let did = bundle.did.as_ref()?;
        return Some(DidSecretsBundle {
            did: did.id.clone(),
            secrets: did.secrets.clone(),
        });
    }

    // AdminOnly — no VTA-provisioned integration DID to cache.
    None
}

/// Glue a base URL and an HTTP path prefix together with exactly one
/// `/` between them and no trailing slash. Used to feed the did:webvh
/// template's `URL` variable so service-endpoint URIs match what the
/// mediator actually serves at runtime.
///
/// `combine_url_prefix("https://m.example.com", "/mediator/v1/")`
/// → `"https://m.example.com/mediator/v1"`. An empty or `/` prefix
/// returns the base URL unchanged.
pub(crate) fn combine_url_prefix(base: &str, prefix: &str) -> String {
    let base = base.trim_end_matches('/');
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{prefix}")
    }
}

/// Build the DIDComm base URL advertised inside a generated did:peer.
///
/// `public_url` may be either the host root (`https://m.example.com`) or
/// an already-prefixed URL (`https://m.example.com/mediator/v1`). To stay
/// backward compatible with existing operator habits, append `api_prefix`
/// only when the URL path does not already end with it.
pub(crate) fn did_peer_service_url(public_url: &str, api_prefix: &str) -> Option<String> {
    let public_url = public_url.trim().trim_end_matches('/');
    if public_url.is_empty() {
        return None;
    }

    let prefix = api_prefix.trim_matches('/');
    if prefix.is_empty() {
        return Some(public_url.to_string());
    }

    let already_prefixed = url::Url::parse(public_url)
        .ok()
        .map(|url| {
            let path = url.path().trim_matches('/');
            path == prefix || path.ends_with(&format!("/{prefix}"))
        })
        .unwrap_or(false);

    Some(if already_prefixed {
        public_url.to_string()
    } else {
        combine_url_prefix(public_url, api_prefix)
    })
}

/// Phase 2 — pure-ish value computation. Branches on `did_method`,
/// `jwt_mode`, and `admin_did_mode` to determine what the wizard will
/// stamp into the config; produces no file or network side effects.
pub(crate) async fn mint_artefacts(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<MintedArtefacts> {
    // ── DID + operating secrets + (optional) DID log + (optional) VC ──
    let minted = mint_did_material(config, vta_session).await?;

    // ── JWT secret ────────────────────────────────────────────────────
    let jwt_secret: Option<Vec<u8>> = if config.jwt_mode == JWT_MODE_PROVIDE {
        out!(
            "  JWT secret: provide mode — wizard will NOT generate or store a key. \
             Set MEDIATOR_JWT_SECRET or pass --jwt-secret-file <path> when starting \
             the mediator."
        );
        None
    } else {
        Some(generators::jwt::generate_jwt_secret()?)
    };

    // ── Admin DID ─────────────────────────────────────────────────────
    // The admin-API identity is what the operator chose. In a VTA flow the
    // VTA-issued credential is the mediator↔VTA identity; it doubles as the
    // admin-API identity only when explicitly asked for (`AdminMode::Vta`), so a
    // generated admin stays a separate key by default.
    let (admin_did, admin_secret) = match config.admin_did_mode {
        Some(AdminMode::Generate) => {
            let (did, secret) = generators::did_key::generate_admin_did_key()?;
            (Some(did), Some(secret))
        }
        Some(AdminMode::Vta) => {
            let session = vta_session.ok_or_else(|| {
                exit::error(
                    exit::NO_VTA_SESSION,
                    "admin = VTA-issued credential, but this run has no VTA session",
                )
            })?;
            out!(
                "  Admin DID: the VTA-issued credential {}",
                session.admin_did()
            );
            (Some(session.admin_did().to_string()), None)
        }
        Some(AdminMode::Paste) => {
            let did = config.admin_did.trim();
            if did.is_empty() {
                return Err(exit::error(
                    exit::IMPORT_WITHOUT_DATA,
                    "admin = existing DID, but no admin DID was given",
                ));
            }
            if !recipe::looks_like_did(did) {
                anyhow::bail!("admin DID '{did}' is not a DID (expected did:<method>:<id>)");
            }
            (Some(did.to_string()), None)
        }
        Some(AdminMode::Skip) | None => (None, None),
    };
    // The admin is a separate identity from the mediator; the mediator
    // refuses to start otherwise, so stop here rather than write that config.
    if let Some(admin) = admin_did.as_deref() {
        affinidi_messaging_mediator_config::validate::check_admin_not_mediator(admin, &minted.did)
            .map_err(|msg| anyhow::anyhow!(msg))?;
    }

    Ok(MintedArtefacts {
        mediator_did: minted.did,
        mediator_secrets: minted.secrets,
        did_doc: minted.did_log,
        webvh_update_keys: minted.webvh_update_keys,
        authorization_vc: minted.authorization_vc,
        jwt_secret,
        admin_did,
        admin_secret,
    })
}

/// What [`mint_did_material`] produces.
pub(crate) struct MintedDid {
    did: String,
    secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    did_log: Option<String>,
    webvh_update_keys: Option<generators::did_webvh::WebvhUpdateKeys>,
    authorization_vc: Option<String>,
}

/// Mint the mediator's DID + operating secrets per `did_method`. The DID
/// log is `None` for non-webvh / non-VTA deployments, the update keys for
/// anything but a locally generated did:webvh, and the authorization VC
/// for anything but a VTA full setup.
pub(crate) async fn mint_did_material(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<MintedDid> {
    let mut webvh_update_keys = None;
    let (did, secrets, did_log, authorization_vc) = match config.did_method {
        Some(DidMethod::Peer) => {
            let service_uri = did_peer_service_url(&config.public_url, &config.api_prefix);
            let (did, secrets) = generators::did_peer::generate_did_peer(
                service_uri,
                &config.key_suite,
                config.tsp_enabled,
            )?;
            (did, secrets, None, None)
        }
        Some(DidMethod::Webvh) => {
            // The DID identifier should encode the host only (`example.com`)
            // so the resolver fetches `<host>/.well-known/did.jsonl`. The
            // template's URL variable, by contrast, needs the *full* URL
            // including the operator's `api_prefix` so the rendered service
            // endpoints (`#didcomm`, `#auth`, `#whois`) point at the routes
            // the mediator actually serves.
            let raw_url = if config.public_url.is_empty() {
                "https://localhost:7037".to_string()
            } else {
                config.public_url.clone()
            };
            let address = config_writer::strip_url_path(&raw_url);
            let service_url = combine_url_prefix(&address, &config.api_prefix);
            let result = generators::did_webvh::generate_did_webvh_as(
                &address,
                &service_url,
                &config.key_suite,
                config.tsp_enabled,
                generators::did_webvh::WebvhIdentity {
                    present_as_scid: config.present_as_scid,
                    scid_also_known_as: config.scid_also_known_as,
                },
            )
            .await?;
            webvh_update_keys = Some(result.update_keys);
            (result.did, result.secrets, Some(result.did_doc), None)
        }
        #[cfg(not(feature = "vta"))]
        Some(DidMethod::Vta) => {
            return Err(exit::error(exit::NO_VTA_SESSION, vta::VTA_UNAVAILABLE));
        }
        #[cfg(feature = "vta")]
        Some(DidMethod::Vta) => {
            // VTA-managed DID: two reply shapes carry it.
            // - `Full(ProvisionResultV2)` — fresh template render
            //   (online / offline-mint paths, FullSetup intent).
            // - `ContextExport(ContextProvisionBundle)` — re-export
            //   of already-provisioned material (offline-export path,
            //   OfflineExport intent).
            let from_full = vta_session.and_then(|s| s.as_full_provision());
            let from_export = vta_session.and_then(|s| s.as_context_export());
            if let Some(provision) = from_full {
                let integration_did = provision
                    .integration_did()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "VTA Full reply has no integration DID — the AdminRotation \
                             flow can't drive a mediator (`did_method = vta`); \
                             re-run with a FullSetup intent or pick a different did_method."
                        )
                    })?
                    .to_string();
                out!("  VTA-minted mediator DID: {integration_did}");

                // Persist the integration DID's private keys as `Secret`
                // values — the mediator's runtime secrets loader reads
                // these at startup.
                let secrets = provision
                    .integration_key()
                    .map(did_key_material_to_secrets)
                    .transpose()?
                    .unwrap_or_default();

                // Authorization VC content — actual file write happens
                // in `write_config_artefacts`. Pre-serialise here so the
                // mint phase produces a value-only `Option<String>` and
                // the IO phase has nothing to compute.
                let vc = serde_json::to_string_pretty(provision.authorization_vc()).ok();

                // The VTA also exposes the inner DID document separately
                // on `provision.payload.config.did_document`, but the
                // wizard only needs the log entry — the mediator's
                // loader extracts the DID document from the log envelope
                // for `/.well-known/did.json`.
                let log_entry = provision.webvh_log().map(str::to_string);
                (integration_did, secrets, log_entry, vc)
            } else if let Some(bundle) = from_export {
                // OfflineExport path. Bundle carries the existing
                // mediator DID + operational keys (Vec<SecretEntry>)
                // + did.jsonl entry. No authorization VC — the admin
                // identity is the `bundle.credential` itself.
                let did_view = bundle.did.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "OfflineExport bundle has no DID slot — admin-only contexts \
                         can't drive a mediator (`did_method = vta`); \
                         re-run with `did_method = peer` (admin-only) or \
                         re-export with a DID-bearing context."
                    )
                })?;
                let integration_did = did_view.id.clone();
                out!("  VTA-exported mediator DID: {integration_did}");

                let secrets = secret_entries_to_secrets(&did_view.secrets)?;
                let log_entry = did_view.log_entry.clone();
                (integration_did, secrets, log_entry, None)
            } else {
                // Never write a placeholder DID: the mediator cannot boot
                // with one, and exit 0 would report a broken setup as done.
                return Err(exit::error(
                    exit::NO_VTA_SESSION,
                    match vta_session {
                        Some(_) => {
                            "a VTA-managed mediator DID was requested, but the VTA session \
                             carries no mediator DID (it is an admin-credential-only \
                             session). Choose did:peer or did:webvh for the mediator."
                        }
                        None => {
                            "a VTA-managed mediator DID was requested, but there is no VTA \
                             session to take it from. Use a sealed-mint recipe, the \
                             interactive wizard, or did:peer / did:webvh."
                        }
                    },
                ));
            }
        }
        None => {
            return Err(exit::error(
                exit::IMPORT_WITHOUT_DATA,
                "no DID method was chosen, and the wizard cannot import an existing mediator \
                 DID. Choose did:peer, did:webvh or a VTA-managed DID.",
            ));
        }
    };

    // Provision-time guard — reject any keyset that the mediator could not use
    // to decrypt its own inbound traffic before it ever reaches disk / the VTA.
    let admin_did = vta_session.map(|s| s.admin_did().to_string());
    validate_operating_secrets(&did, &secrets, admin_did.as_deref())?;

    Ok(MintedDid {
        did,
        secrets,
        did_log,
        webvh_update_keys,
        authorization_vc,
    })
}

#[cfg(test)]
#[cfg(feature = "vta")]
mod cache_bundle_tests {
    use super::build_did_secrets_bundle;
    use crate::vta::VtaSession;
    use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::did_secrets::SecretEntry;
    use vta_sdk::keys::KeyType;

    #[test]
    fn full_provision_projects_to_signing_plus_ka_bundle() {
        // TemplateBootstrap path: mediator DID + typed signing/ka key
        // pair. Must land as two SecretEntries with the correct
        // discriminants (Ed25519 for signing, X25519 for key-agreement)
        // and the raw multibase passthrough.
        let provision = vta_sdk::provision_client::test_helpers::sample_provision_result_v2(
            /*rolled_over=*/ true, /*pq=*/ false,
        );
        let session = VtaSession::full(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            None,
            provision,
        );

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:integration.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert!(matches!(bundle.secrets[0].key_type, KeyType::Ed25519));
        assert!(matches!(bundle.secrets[1].key_type, KeyType::X25519));
        // Multibase passthrough — the runtime's `Secret::from_multibase`
        // is the one doing the actual key decode, so we round-trip the
        // string verbatim.
        assert_eq!(bundle.secrets[0].private_key_multibase, "zPrivateSample");
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKaPrivate");
    }

    /// **A post-quantum signing key the VTA minted must reach the mediator's
    /// secrets store.**
    ///
    /// The mediator's own template is v1, so this cannot happen yet — but the
    /// key would be *published in the DID document* as a verification method
    /// either way. A mediator that stored only the first two keys would
    /// advertise one it cannot sign with, and that failure surfaces at a peer as
    /// an unverifiable signature, a long way from this code.
    ///
    /// Pinned now rather than when a v2 mediator template appears, because at
    /// that point nothing here would fail — it would just quietly drop a key.
    #[test]
    fn an_additional_signing_key_is_projected_alongside_the_pair() {
        let provision = vta_sdk::provision_client::test_helpers::sample_provision_result_v2(
            /*rolled_over=*/ true, /*pq=*/ true,
        );
        let session = VtaSession::full(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            None,
            provision,
        );

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(
            bundle.secrets.len(),
            3,
            "signing + key-agreement + the post-quantum key the VTA minted, got {:?}",
            bundle.secrets.iter().map(|s| &s.key_id).collect::<Vec<_>>()
        );
        assert!(
            bundle.secrets.iter().any(|s| s.key_id.ends_with("#key-2")),
            "the additional key must be stored under the id the DID document publishes: {:?}",
            bundle.secrets.iter().map(|s| &s.key_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn admin_only_yields_no_bundle() {
        // AdminOnly session doesn't carry a VTA-provisioned integration
        // DID — the mediator brought its own. Nothing to cache; the
        // helper must signal that explicitly so the caller doesn't
        // write a malformed bundle keyed to the admin DID.
        let session = VtaSession::admin_only(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            None,
            None,
            "did:key:z6MkAdmin".into(),
            "zAdminPrivate".into(),
        );
        assert!(build_did_secrets_bundle(&session).is_none());
    }

    #[test]
    fn context_export_passes_through_secret_entries() {
        // OfflineExport path: ContextProvisionBundle already has a
        // flat Vec<SecretEntry> (including whatever key types the VTA
        // chose), so the projection is a direct copy.
        let did_view = ProvisionedDid {
            id: "did:webvh:mediator.example.com".into(),
            did_document: None,
            log_entry: None,
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-0".into(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "zSigning".into(),
                },
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-1".into(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "zKa".into(),
                },
            ],
        };
        let ctx_bundle = ContextProvisionBundle {
            context_id: "prod-mediator".into(),
            context_name: "Prod mediator".into(),
            vta_url: None,
            vta_did: Some("did:webvh:vta.example.com".into()),
            credential: CredentialBundle::new(
                "did:key:z6MkAdmin",
                "zAdminPrivate",
                "did:webvh:vta.example.com",
            ),
            admin_did: "did:key:z6MkAdmin".into(),
            did: Some(did_view),
        };
        let session = VtaSession::context_export("prod-mediator".into(), ctx_bundle);

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:mediator.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert_eq!(
            bundle.secrets[0].key_id,
            "did:webvh:mediator.example.com#key-0"
        );
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKa");
    }
}

#[cfg(test)]
mod did_peer_service_url_tests {
    use super::did_peer_service_url;

    #[test]
    fn appends_default_api_prefix_for_host_root_public_url() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }

    #[test]
    fn does_not_double_append_existing_api_prefix() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com/mediator/v1/", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }
}
