//! Process exit codes, so scripts can tell the failures that need different
//! handling apart. Listed in `--help` and in `docs/setup-guide.md`.
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | success |
//! | 1 | any other failure: invalid flags or recipe, backend unreachable, a write failed |
//! | 2 | `--setup-key-file`: no VTA transport worked (clap also exits 2 on a usage error) |
//! | 3 | `--setup-key-file`: the VTA accepted the handshake, then rejected the request |
//! | 4 | refused: the target secret backend already holds a provisioned mediator (`--force-reprovision` to replace it) |
//! | 5 | a VTA-managed DID was asked for, but no VTA session is available to provide it |
//! | 6 | an import was asked for without the data it needs (`admin = "import"` with no `admin_did`, or `did_method = "import"`, which is not supported) |
//! | 7 | setup completed, but publishing to `did_target` / `did_log_target` failed |
//! | 8 | the interactive wizard needs a terminal; use `--from` or `--non-interactive` |

use std::fmt;

pub const GENERIC: u8 = 1;
pub const VTA_NO_TRANSPORT: u8 = 2;
pub const VTA_POST_AUTH: u8 = 3;
pub const REFUSED_EXISTING: u8 = 4;
pub const NO_VTA_SESSION: u8 = 5;
pub const IMPORT_WITHOUT_DATA: u8 = 6;
pub const PUBLISH_FAILED: u8 = 7;
pub const NOT_A_TERMINAL: u8 = 8;

/// The text appended to `--help`.
pub const HELP: &str = "\
Exit codes:
  0  success
  1  any other failure (invalid flags or recipe, backend unreachable, write failed)
  2  --setup-key-file: no VTA transport worked (also clap's usage-error code)
  3  --setup-key-file: the VTA accepted the handshake, then rejected the request
  4  refused: the secret backend already holds a provisioned mediator
     (re-run with --force-reprovision to replace it, or --uninstall)
  5  a VTA-managed DID was requested but no VTA session is available
  6  an import was requested without the data it needs
  7  setup completed, but publishing the DID / DID log failed
  8  the interactive wizard needs a terminal (use --from or --non-interactive)";

/// An error that ends the process with a specific exit code. Travels inside
/// `anyhow::Error`; `main` finds it with [`code_of`].
#[derive(Debug)]
pub struct ExitError {
    pub code: u8,
    message: String,
}

impl ExitError {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

/// `anyhow::Error` carrying `code`.
pub fn error(code: u8, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ExitError::new(code, message))
}

/// The exit code an error should end the process with.
pub fn code_of(err: &anyhow::Error) -> u8 {
    err.chain()
        .find_map(|e| e.downcast_ref::<ExitError>())
        .map_or(GENERIC, |e| e.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_survives_context() {
        let e = error(NO_VTA_SESSION, "no session").context("while minting");
        assert_eq!(code_of(&e), NO_VTA_SESSION);
        assert_eq!(code_of(&anyhow::anyhow!("plain")), GENERIC);
    }

    #[test]
    fn help_lists_every_code() {
        for code in [
            GENERIC,
            VTA_NO_TRANSPORT,
            VTA_POST_AUTH,
            REFUSED_EXISTING,
            NO_VTA_SESSION,
            IMPORT_WITHOUT_DATA,
            PUBLISH_FAILED,
            NOT_A_TERMINAL,
        ] {
            assert!(
                HELP.lines()
                    .any(|l| l.trim_start().starts_with(&format!("{code} "))),
                "exit code {code} missing from --help"
            );
        }
    }
}
