//! Non-interactive entry points for the online-VTA sub-flow.
//!
//! The wizard otherwise drives the connection via its TUI, but orchestrated
//! deploys need a scriptable way to run the same flow:
//!
//! - **Phase 1** (`--setup-key-out`): generate an ephemeral did:key, persist
//!   it, print the `pnm acl create` command, and exit. The operator (or
//!   automation) registers the ACL on the VTA between phases.
//! - **Phase 2** (`--setup-key-file`): reload the persisted key, run the
//!   diagnostic + auth runner, stream checklist lines to stdout, and exit
//!   with a non-zero status on failure.
//!
//! Both phases accept `--vta-did` and `--vta-context` for the inputs the TUI
//! would otherwise collect via text fields.
//!
//! Built on top of [`crate::vta::runner::run_connection_test`], which in turn
//! drives [`vta_sdk::provision_client::run_connection_test`]. The SDK's
//! [`vta_sdk::provision_client::driver`] ships an equivalent
//! `run_phase1_init` / `run_phase2_connect` pair, but the local wrapper here
//! adds two pieces of behaviour the SDK driver does not: (1) auto-fallback
//! across DIDComm ↔ REST on a pre-auth failure, and (2) `--wait-for-acl`
//! retry-on-ACL-propagation. Both are mediator-setup-specific operator
//! niceties — kept here rather than upstreamed.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::consts::DEFAULT_VTA_CONTEXT;
use crate::vta::{
    AttemptResultKind, DiagCheck, DiagStatus, EphemeralSetupKey, Protocol, ResolvedVta, VtaEvent,
    VtaIntent, runner::run_connection_test,
};

/// Categorises a headless terminal failure into the three exit-code
/// classes documented on the binary's `--help`. The CLI driver
/// returns this in the `Err` variant of [`HeadlessVtaError`] so
/// `main.rs` can pick the right `std::process::exit` code without
/// re-parsing the error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadlessFailureKind {
    /// VTA advertises neither DIDComm nor REST, OR every advertised
    /// transport's auth attempt failed pre-auth. Exit code 2.
    NoTransport,
    /// VTA accepted the auth handshake but rejected the request
    /// body afterwards (template render error, validation, etc.).
    /// A different wire would reproduce the rejection — sealed-
    /// handoff is the only escape hatch. Exit code 3.
    PostAuthFailed,
}

/// Structured terminal-failure shape for the headless CLI flow.
/// Carries each transport's last failure reason (or `None` if the
/// transport wasn't attempted), the failure class, and an
/// operator-facing recommendation that points at the offline
/// sealed-handoff command.
///
/// Implements `Display` so the wrapper in `main.rs` can `eprintln!`
/// it directly; the format is stable and grep-friendly for CI logs.
#[derive(Debug)]
pub struct HeadlessVtaError {
    pub tsp: Option<String>,
    pub didcomm: Option<String>,
    pub rest: Option<String>,
    pub kind: HeadlessFailureKind,
}

impl fmt::Display for HeadlessVtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Headless VTA setup failed.")?;
        if let Some(reason) = &self.tsp {
            writeln!(f, "  TSP: {reason}")?;
        }
        if let Some(reason) = &self.didcomm {
            writeln!(f, "  DIDComm: {reason}")?;
        }
        if let Some(reason) = &self.rest {
            writeln!(f, "  REST: {reason}")?;
        }
        if self.tsp.is_none() && self.didcomm.is_none() && self.rest.is_none() {
            writeln!(f, "  No transport advertised by the VTA's DID document.")?;
        }
        writeln!(f)?;
        match self.kind {
            HeadlessFailureKind::NoTransport => {
                writeln!(
                    f,
                    "Switch to the offline sealed-handoff flow: re-run with the recipe's \
                     `vta_mode = \"sealed-mint\"` (FullSetup) or `\"sealed-export\"` \
                     (OfflineExport) to bundle a request file for the VTA admin."
                )?;
            }
            HeadlessFailureKind::PostAuthFailed => {
                writeln!(
                    f,
                    "VTA accepted the auth handshake then rejected the request body. \
                     Inspect the VTA-side error above and either correct the request or \
                     switch to the offline sealed-handoff flow."
                )?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for HeadlessVtaError {}

/// Decide whether a Failed event should auto-fall back to the
/// alternate transport. Mirrors the interactive
/// `should_route_to_fallback` logic but inlined here so the CLI
/// driver doesn't need to construct a full `VtaConnectState`.
fn auto_fallback_target(
    last_protocol: Protocol,
    last_outcome: &AttemptResultKind,
    resolved: Option<&ResolvedVta>,
    didcomm_attempted: bool,
    rest_attempted: bool,
) -> Option<Protocol> {
    if !matches!(last_outcome, AttemptResultKind::PreAuthFailure(_)) {
        return None;
    }
    let resolved = resolved?;
    match last_protocol {
        Protocol::DidComm if resolved.rest_url.is_some() && !rest_attempted => Some(Protocol::Rest),
        Protocol::Rest if resolved.mediator_did.is_some() && !didcomm_attempted => {
            Some(Protocol::DidComm)
        }
        _ => None,
    }
}

/// The phase-2 command line that finishes the setup phase 1 started.
fn finalise_command(
    out_path: &Path,
    vta_did: Option<&str>,
    ctx: &str,
    mediator_url: Option<&str>,
    did_method: Option<crate::cli::DidMethod>,
) -> String {
    let did_method = match did_method {
        Some(crate::cli::DidMethod::Webvh) => "webvh",
        Some(crate::cli::DidMethod::Peer) => "peer",
        _ => "<peer|webvh>",
    };
    format!(
        "mediator-setup --setup-key-file {} \\\n      --vta-did {} --vta-context {ctx} \\\n      \
         --mediator-url {} --did-method {did_method} \\\n      [--secret-storage <backend> | \
         --from <recipe.toml>] [--set section.key=value …]",
        out_path.display(),
        vta_did.unwrap_or("<vta-did>"),
        mediator_url.unwrap_or("<https://mediator.example.com>"),
    )
}

/// Phase 1: generate + persist ephemeral key, print the context/ACL command
/// and the phase-2 command that finishes the setup.
pub async fn run_phase1_init(
    out_path: &Path,
    vta_did: Option<&str>,
    context_id: Option<&str>,
    mediator_url: Option<&str>,
    did_method: Option<crate::cli::DidMethod>,
) -> anyhow::Result<()> {
    let key = EphemeralSetupKey::generate()?;
    key.persist_to(out_path)?;

    let ctx = context_id.unwrap_or(DEFAULT_VTA_CONTEXT);

    out!();
    out!("  Setup DID (ephemeral):");
    out!("    {}", key.did);
    out!();
    out!("  Key stored at {} (0600)", out_path.display());
    out!();
    out!("  Using your Personal Network Manager (PNM) connected to this VTA,");
    out!("  create the mediator context and grant admin access to the setup DID:");
    out!();
    out!(
        "    pnm contexts create --id {ctx} --name \"Mediator\" \\\n      --admin-did {} --admin-expires {}",
        key.did,
        crate::consts::DEFAULT_VTA_SETUP_EXPIRY,
    );
    out!();
    out!("  --name is a human-readable label — change \"Mediator\" to anything");
    out!("  that fits your naming conventions.");
    out!();
    out!("  --admin-expires defaults to 1h. Use 24h, 7d, etc. for longer");
    out!("  roll-outs; the entry is promoted to permanent on first auth.");
    out!();
    out!("  Then finish the setup — authenticate, store the credential in the");
    out!("  secret backend, write the mediator config — with:");
    out!();
    out!(
        "    {}",
        finalise_command(out_path, vta_did, ctx, mediator_url, did_method)
    );
    out!();
    out!("  In this admin-only flow the setup did:key above becomes the mediator's");
    out!("  long-term VTA admin credential: phase 2 stores it in the secret backend");
    out!("  and deletes the key file. The mediator brings its own DID (--did-method).");
    out!();
    Ok(())
}

/// Phase 2: reload key + run runner + stream diagnostics to stdout. Returns
/// the admin-only [`crate::vta::VtaSession`] on a successful auth; on failure returns a structured
/// [`HeadlessVtaError`] that the caller maps to an exit code.
///
/// Auto-fallback: if a DIDComm pre-auth failure happens against a
/// VTA that also advertises REST (and REST hasn't been tried yet),
/// the CLI retries automatically over REST without prompting. Same
/// in the reverse direction. Post-auth failures terminate
/// immediately — a different wire reproduces the rejection.
pub async fn run_phase2_connect(
    key_path: &Path,
    vta_did: &str,
    context_id: Option<&str>,
    mediator_url: &str,
    wait_for_acl: Option<u64>,
) -> Result<crate::vta::VtaSession, HeadlessVtaError> {
    let key = EphemeralSetupKey::load_from(key_path).map_err(|e| HeadlessVtaError {
        tsp: None,
        didcomm: Some(format!("could not load setup key: {e}")),
        rest: None,
        kind: HeadlessFailureKind::NoTransport,
    })?;
    let ctx = context_id.unwrap_or(DEFAULT_VTA_CONTEXT);

    out!();
    out!("  VTA DID:      {vta_did}");
    out!("  Context:      {ctx}");
    out!("  Mediator URL: {mediator_url}");
    out!("  Setup DID:    {}", key.did);
    out!();

    let deadline = wait_for_acl.map(|s| Instant::now() + Duration::from_secs(s));
    let mut attempt = 0u32;

    // Per-transport state, carried across loop iterations so
    // auto-fallback can see what's already been tried.
    let mut force_transport: Option<Protocol> = None;
    let mut resolved: Option<ResolvedVta> = None;
    let mut tsp_failure: Option<String> = None;
    let mut didcomm_failure: Option<String> = None;
    let mut rest_failure: Option<String> = None;

    loop {
        attempt += 1;
        if attempt > 1 {
            match force_transport {
                Some(Protocol::Tsp) => out!("  Retrying TSP (attempt {attempt})…"),
                Some(Protocol::Rest) => out!("  Falling back to REST (attempt {attempt})…"),
                Some(Protocol::DidComm) => {
                    out!("  Retrying DIDComm (attempt {attempt})…")
                }
                None => out!("  Retrying (attempt {attempt})…"),
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
        let vta_did_owned = vta_did.to_string();
        let setup_did = key.did.clone();
        let privkey_mb = key.private_key_multibase().to_string();
        let ctx_owned = ctx.to_string();
        let mediator_url_owned = mediator_url.to_string();
        let force = force_transport;

        let runner = tokio::spawn(async move {
            // CLI phase-2 is AdminOnly — the interactive
            // FullSetup flow splits into preflight + webvh picker
            // + provision, which doesn't fit a one-shot CLI
            // surface.
            run_connection_test(
                VtaIntent::AdminOnly,
                vta_did_owned,
                setup_did,
                privkey_mb,
                ctx_owned,
                mediator_url_owned,
                force,
                tx,
            )
            .await;
        });

        let mut connected: Option<crate::vta::VtaSession> = None;
        let mut last_failure: Option<String> = None;
        // The most recent AttemptCompleted in this loop iteration —
        // used to decide auto-fallback after the runner emits Failed.
        let mut last_attempt: Option<(Protocol, AttemptResultKind)> = None;

        while let Some(event) = rx.recv().await {
            match event {
                VtaEvent::CheckStart(c) => {
                    out!("  [..] {}", c.label());
                }
                VtaEvent::CheckDone(c, status) => {
                    out!("  {}", format_check_line(c, &status));
                }
                VtaEvent::Connected {
                    protocol,
                    rest_url,
                    mediator_did,
                    reply,
                } => {
                    // AdminOnly: the setup did:key the operator enrolled is
                    // the long-term admin credential the reply carries.
                    connected = Some(crate::vta::VtaSession {
                        context_id: ctx.to_string(),
                        vta_did: vta_did.to_string(),
                        rest_url,
                        mediator_did,
                        reply: reply.into(),
                    });
                    out!();
                    out!("  Connected via {}", protocol.label());
                }
                VtaEvent::PreflightDone { .. } => {
                    // AdminOnly never emits PreflightDone. Defensive
                    // ignore so a future runner change doesn't panic.
                }
                VtaEvent::Resolved(r) => {
                    resolved = Some(r);
                }
                VtaEvent::AttemptCompleted { protocol, outcome } => {
                    // Record the last failure reason per transport so
                    // the terminal-error message can name both.
                    if let AttemptResultKind::PreAuthFailure(reason)
                    | AttemptResultKind::PostAuthFailure(reason) = &outcome
                    {
                        match protocol {
                            Protocol::Tsp => tsp_failure = Some(reason.clone()),
                            Protocol::DidComm => didcomm_failure = Some(reason.clone()),
                            Protocol::Rest => rest_failure = Some(reason.clone()),
                        }
                    }
                    last_attempt = Some((protocol, outcome));
                }
                VtaEvent::Failed(reason) => {
                    last_failure = Some(reason);
                }
                // `VtaEvent` is `#[non_exhaustive]` (vta-sdk 0.77+). The
                // outcome is decided by `Connected` / `Failed` / the runner
                // finishing, so an event this build doesn't know is skipped.
                _ => {}
            }
        }
        let _ = runner.await;

        if let Some(session) = connected {
            return Ok(session);
        }

        // Decide what to do next: auto-fallback, retry-on-wait, or terminal.
        let didcomm_attempted = didcomm_failure.is_some();
        let rest_attempted = rest_failure.is_some();

        if let Some((protocol, outcome)) = &last_attempt {
            // Post-auth failure → terminal immediately. The VTA
            // accepted us; a different wire reproduces the
            // rejection.
            if matches!(outcome, AttemptResultKind::PostAuthFailure(_)) {
                return Err(HeadlessVtaError {
                    tsp: tsp_failure,
                    didcomm: didcomm_failure,
                    rest: rest_failure,
                    kind: HeadlessFailureKind::PostAuthFailed,
                });
            }
            // Pre-auth failure → try the alternate transport if
            // it's advertised + unattempted.
            if let Some(target) = auto_fallback_target(
                *protocol,
                outcome,
                resolved.as_ref(),
                didcomm_attempted,
                rest_attempted,
            ) {
                force_transport = Some(target);
                continue;
            }
        }

        // No fallback available. If `--wait-for-acl` is set and the
        // failure looks transient, sleep and re-run with the same
        // transport choice.
        let reason = last_failure
            .clone()
            .unwrap_or_else(|| "unknown failure".into());
        if let Some(deadline) = deadline
            && Instant::now() < deadline
            && retryable(&reason)
        {
            let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
            out!();
            out!("  ACL not yet present — waiting up to {remaining}s more…");
            tokio::time::sleep(Duration::from_secs(3)).await;
            // Reset the relevant transport's failure so the retry
            // loop's "attempted" check doesn't block another
            // attempt. Keep the other transport's failure intact.
            match force_transport {
                Some(Protocol::Tsp) => tsp_failure = None,
                Some(Protocol::DidComm) => didcomm_failure = None,
                Some(Protocol::Rest) => rest_failure = None,
                None => {
                    tsp_failure = None;
                    didcomm_failure = None;
                    rest_failure = None;
                }
            }
            continue;
        }

        // Terminal failure. Pick the kind based on what we observed.
        return Err(HeadlessVtaError {
            tsp: tsp_failure,
            didcomm: didcomm_failure,
            rest: rest_failure,
            kind: HeadlessFailureKind::NoTransport,
        });
    }
}

fn format_check_line(c: DiagCheck, status: &DiagStatus) -> String {
    match status {
        DiagStatus::Pending => format!("[  ] {}", c.label()),
        DiagStatus::Running => format!("[..] {}", c.label()),
        DiagStatus::Ok(d) => format!("[OK] {}  {d}", c.label()),
        DiagStatus::Skipped(d) => format!("[--] {}  {d}", c.label()),
        DiagStatus::Failed(d) => format!("[!!] {}  {d}", c.label()),
        // `DiagStatus` is `#[non_exhaustive]` (vta-sdk 0.77+).
        _ => format!("[??] {}", c.label()),
    }
}

/// Rough heuristic for "worth retrying under --wait-for-acl": auth failures
/// are usually just waiting on ACL propagation; resolve / network errors
/// are unlikely to self-heal quickly.
fn retryable(reason: &str) -> bool {
    reason.contains("401")
        || reason.contains("403")
        || reason.contains("Authentication rejected")
        || reason.contains("ACL")
}

/// Validate that Phase 2 has all it needs before we start generating events.
pub fn validate_phase2_args(vta_did: &Option<String>) -> anyhow::Result<&str> {
    match vta_did {
        Some(d) => Ok(d),
        None => Err(anyhow::anyhow!(
            "--vta-did is required when --setup-key-file is used"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_hits_common_acl_errors() {
        assert!(retryable("authentication failed (401): ..."));
        assert!(retryable("authentication failed (403): ..."));
        assert!(retryable("Authentication rejected — confirm the ACL..."));
    }

    #[test]
    fn retryable_skips_network_errors() {
        assert!(!retryable("could not connect to VTA at ..."));
        assert!(!retryable("DID resolver init failed: ..."));
    }

    #[test]
    fn validate_phase2_args_requires_did() {
        let none: Option<String> = None;
        assert!(validate_phase2_args(&none).is_err());
        let some = Some("did:webvh:vta.example.com".into());
        assert_eq!(
            validate_phase2_args(&some).unwrap(),
            "did:webvh:vta.example.com"
        );
    }

    fn resolved(mediator_did: Option<&str>, rest_url: Option<&str>) -> ResolvedVta {
        ResolvedVta {
            vta_did: "did:webvh:vta.test".into(),
            // vta-sdk 0.20 added TSP discovery. These fixtures cover the
            // DIDComm/REST fallback ladder, so the VTA under test advertises
            // no `#tsp` service.
            tsp_mediator_did: None,
            mediator_did: mediator_did.map(str::to_string),
            rest_url: rest_url.map(str::to_string),
        }
    }

    #[test]
    fn auto_fallback_picks_rest_after_didcomm_pre_auth() {
        let r = resolved(Some("did:webvh:m"), Some("https://vta.test"));
        let target = auto_fallback_target(
            Protocol::DidComm,
            &AttemptResultKind::PreAuthFailure("ACL not found".into()),
            Some(&r),
            true,
            false,
        );
        assert_eq!(target, Some(Protocol::Rest));
    }

    #[test]
    fn auto_fallback_skips_post_auth_failure() {
        let r = resolved(Some("did:webvh:m"), Some("https://vta.test"));
        let target = auto_fallback_target(
            Protocol::DidComm,
            &AttemptResultKind::PostAuthFailure("template render rejected".into()),
            Some(&r),
            true,
            false,
        );
        assert_eq!(target, None);
    }

    #[test]
    fn auto_fallback_skips_when_alternate_already_attempted() {
        let r = resolved(Some("did:webvh:m"), Some("https://vta.test"));
        let target = auto_fallback_target(
            Protocol::DidComm,
            &AttemptResultKind::PreAuthFailure("ACL not found".into()),
            Some(&r),
            true,
            true,
        );
        assert_eq!(target, None);
    }

    #[test]
    fn auto_fallback_skips_when_alternate_not_advertised() {
        let r = resolved(Some("did:webvh:m"), None);
        let target = auto_fallback_target(
            Protocol::DidComm,
            &AttemptResultKind::PreAuthFailure("ACL not found".into()),
            Some(&r),
            true,
            false,
        );
        assert_eq!(target, None);
    }

    #[test]
    fn headless_error_display_names_both_protocols() {
        let err = HeadlessVtaError {
            tsp: None,
            didcomm: Some("ACL not found".into()),
            rest: Some("REST 401".into()),
            kind: HeadlessFailureKind::NoTransport,
        };
        let s = err.to_string();
        assert!(s.contains("DIDComm: ACL not found"));
        assert!(s.contains("REST: REST 401"));
        assert!(s.contains("sealed-handoff"));
    }

    #[test]
    fn headless_error_display_no_transport_message_differs_from_post_auth() {
        let no_transport = HeadlessVtaError {
            tsp: None,
            didcomm: Some("network".into()),
            rest: None,
            kind: HeadlessFailureKind::NoTransport,
        }
        .to_string();
        let post_auth = HeadlessVtaError {
            tsp: None,
            didcomm: Some("template error".into()),
            rest: None,
            kind: HeadlessFailureKind::PostAuthFailed,
        }
        .to_string();
        assert_ne!(no_transport, post_auth);
        assert!(post_auth.contains("rejected the request body"));
    }

    #[test]
    fn format_check_line_uses_expected_tags() {
        let ok = format_check_line(
            DiagCheck::ResolveDid,
            &DiagStatus::Ok("did:webvh:...".into()),
        );
        assert!(ok.contains("[OK]"));
        assert!(ok.contains("Resolve VTA DID"));

        let failed = format_check_line(
            DiagCheck::AuthenticateDIDComm,
            &DiagStatus::Failed("boom".into()),
        );
        assert!(failed.contains("[!!]"));
    }

    #[tokio::test]
    async fn phase1_writes_a_valid_key_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        run_phase1_init(
            &path,
            Some("did:webvh:vta.example.com"),
            Some("mediator"),
            None,
            None,
        )
        .await
        .unwrap();
        let reloaded = EphemeralSetupKey::load_from(&path).unwrap();
        assert!(reloaded.did.starts_with("did:key:z6Mk"));
    }
}
