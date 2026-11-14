//! Display labels for the typed wizard choices. The one place a
//! [`WizardConfig`](crate::app::WizardConfig) value becomes words on screen;
//! the config itself holds enums, never these strings.

use crate::app::{Deployment, DidMethod, SslMode, VtaMode};

impl Deployment {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "Local development",
            Self::Server => "Headless server",
            Self::Container => "Container",
        }
    }
}

impl DidMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vta => "VTA managed",
            Self::Webvh => "did:webvh",
            Self::Peer => "did:peer",
        }
    }
}

impl SslMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "No SSL (TLS proxy)",
            Self::Existing => "Existing certificates",
            Self::SelfSigned => "Self-signed",
        }
    }
}

impl VtaMode {
    /// How the interactive summary names the mode. The TUI's mint handoff
    /// is shown as `sealed`, as it always was; the intent shown beside it
    /// says what the VTA does. (Headless output prints [`VtaMode::as_str`].)
    #[cfg(feature = "vta")]
    pub fn label(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::SealedMint => "sealed",
            Self::SealedExport => "sealed-export",
        }
    }
}

/// The label of an optional choice; empty while it is unset.
pub fn label_of<T: Copy>(value: Option<T>, label: fn(T) -> &'static str) -> &'static str {
    value.map_or("", label)
}
