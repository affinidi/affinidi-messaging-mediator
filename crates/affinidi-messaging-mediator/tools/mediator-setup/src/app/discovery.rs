//! The F5 discovery overlay on the cloud-backend namespace screens.

use tokio::sync::mpsc::unbounded_channel;
use tui_input::Input;

use crate::consts::*;
use crate::discovery::{DiscoveryEvent, DiscoveryRequest, DiscoveryState};

use super::{KeyStoragePhase, WizardApp};

impl WizardApp {
    /// `true` while the discovery overlay (loading spinner, results
    /// list, or error banner) is on screen. The main input handler
    /// short-circuits to [`Self::handle_discovery_key`] in this state
    /// so normal text-input keys don't leak through.
    pub fn in_discovery_overlay(&self) -> bool {
        self.discovery.is_some()
    }

    /// Build a [`DiscoveryRequest`] for the current key-storage phase
    /// and the wizard's accumulated config, or return `None` when the
    /// phase isn't discoverable (or required upstream config is
    /// missing — e.g. F5 on `AwsNamespace` before `AwsRegion` was filled).
    pub(super) fn discovery_request_for_phase(&self) -> Option<DiscoveryRequest> {
        let phase = self.key_storage_phase?;
        match phase {
            KeyStoragePhase::AwsNamespace => {
                let region = self.config.secret_aws_region.trim();
                if region.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Aws {
                    region: region.to_string(),
                })
            }
            KeyStoragePhase::GcpNamespace => {
                let project = self.config.secret_gcp_project.trim();
                if project.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Gcp {
                    project: project.to_string(),
                })
            }
            KeyStoragePhase::AzureVault => {
                // The vault name is the *current* text input — the
                // operator hasn't confirmed it yet. Treat F5 as a
                // sanity check on what they've typed so far.
                let vault = self.text_input.value().trim();
                if vault.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Azure {
                    vault: vault.to_string(),
                })
            }
            KeyStoragePhase::VaultMount => {
                let endpoint = self.config.secret_vault_endpoint.trim();
                if endpoint.is_empty() {
                    return None;
                }
                // Use the operator's currently-typed mount value as the
                // discovery target. Empty / unset → fall back to the
                // wizard default so F5 still works on a fresh entry.
                let raw_mount = self.text_input.value().trim();
                let mount = if raw_mount.is_empty() {
                    DEFAULT_VAULT_MOUNT.to_string()
                } else {
                    raw_mount.to_string()
                };
                Some(DiscoveryRequest::Vault {
                    endpoint: endpoint.to_string(),
                    mount,
                })
            }
            // Other key-storage phases are local-only (file path,
            // keyring service, AWS region, GCP project, Vault
            // endpoint, file gate, encrypt choice, file passphrase) —
            // no remote namespace to enumerate.
            _ => None,
        }
    }

    /// Kick off discovery for the current key-storage phase. Sets the
    /// overlay to `Loading` and spawns a background task that resolves
    /// to a `DiscoveryEvent` on the channel. No-op (silent) when the
    /// current phase isn't discoverable or upstream config is missing —
    /// the F5 hint footer makes the requirements visible.
    pub fn kick_off_discovery(&mut self) {
        if self.discovery.is_some() {
            // Already in flight or being browsed — F5 is idempotent.
            return;
        }
        let Some(req) = self.discovery_request_for_phase() else {
            return;
        };
        let (tx, rx) = unbounded_channel();
        self.discovery = Some(DiscoveryState::Loading);
        self.discovery_rx = Some(rx);
        crate::discovery::spawn(req, tx);
    }

    /// Drain any discovery events queued since the last tick into the
    /// overlay state. Called from the main loop's ticker so the UI
    /// reflects the result without waiting for a keypress.
    pub fn drain_discovery_events(&mut self) {
        let Some(rx) = self.discovery_rx.as_mut() else {
            return;
        };
        // Best-effort drain — `try_recv` doesn't block. We only handle
        // one event per tick because the channel only ever carries one
        // (Loaded or Failed) before we drop the receiver.
        if let Ok(event) = rx.try_recv() {
            self.discovery = Some(match event {
                DiscoveryEvent::Loaded { items } => DiscoveryState::Loaded {
                    items,
                    cursor: 0,
                    scroll: 0,
                },
                DiscoveryEvent::Failed(message) => DiscoveryState::Failed { message },
            });
            self.discovery_rx = None;
        }
    }

    /// Handle keypresses while the discovery overlay is on screen.
    /// Returns `true` when the key was consumed by the overlay so the
    /// caller skips the usual text-input dispatch.
    pub fn handle_discovery_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;
        let Some(state) = self.discovery.as_mut() else {
            return false;
        };
        match state {
            DiscoveryState::Loading => {
                // Esc cancels (drops the channel — the spawned task
                // can finish; its send goes to a dropped receiver).
                // Any other key is swallowed silently.
                if matches!(code, KeyCode::Esc) {
                    self.discovery = None;
                    self.discovery_rx = None;
                }
            }
            DiscoveryState::Failed { .. } => {
                // Any key dismisses the error banner.
                self.discovery = None;
                self.discovery_rx = None;
            }
            DiscoveryState::Loaded {
                items,
                cursor,
                scroll,
            } => {
                if items.is_empty() {
                    // Empty list — only Esc / Enter dismiss.
                    if matches!(code, KeyCode::Esc | KeyCode::Enter) {
                        self.discovery = None;
                    }
                    return true;
                }
                let max = items.len() - 1;
                match code {
                    KeyCode::Up | KeyCode::Char('k') if *cursor > 0 => {
                        *cursor -= 1;
                        // Keep cursor visible — scroll up if we
                        // walked past the top of the viewport.
                        if *cursor < *scroll {
                            *scroll = *cursor;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') if *cursor < max => {
                        *cursor += 1;
                        // Viewport height is rendered-side knowledge;
                        // we approximate with a generous 10-row
                        // window. Worst case the renderer clips a
                        // row — better than constraining input
                        // logic to a magic-number height.
                        if *cursor >= *scroll + 10 {
                            *scroll = cursor.saturating_sub(9);
                        }
                    }
                    KeyCode::PageUp => {
                        *cursor = cursor.saturating_sub(10);
                        *scroll = scroll.saturating_sub(10);
                    }
                    KeyCode::PageDown => {
                        *cursor = (*cursor + 10).min(max);
                        if *cursor >= *scroll + 10 {
                            *scroll = cursor.saturating_sub(9);
                        }
                    }
                    KeyCode::Home => {
                        *cursor = 0;
                        *scroll = 0;
                    }
                    KeyCode::End => {
                        *cursor = max;
                        *scroll = max.saturating_sub(9);
                    }
                    KeyCode::Enter => {
                        // Copy the selected secret name into the prompt
                        // verbatim. The operator can then trim it to
                        // the namespace portion they want — usually the
                        // dirname (everything up to and including the
                        // last `/`). We don't auto-trim because a flat
                        // name has no separator and an operator who
                        // really wants the full path as their namespace
                        // shouldn't have it silently rewritten.
                        let picked = items[*cursor].clone();
                        self.text_input = Input::new(picked);
                        self.discovery = None;
                    }
                    KeyCode::Esc => {
                        self.discovery = None;
                    }
                    _ => {}
                }
            }
        }
        true
    }
}
