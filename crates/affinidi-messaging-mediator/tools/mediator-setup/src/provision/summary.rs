//! The summary printed once provisioning has finished.

use std::io;

use crate::app;
use crate::consts::*;
use crate::provision::MintedArtefacts;
use crate::{config_writer, vta};

/// Phase 5 — operator-facing terminal output. The admin private key is
/// never printed unless asked for with `--show-admin-key` on a terminal:
/// it is already in the secret backend or `admin-monitor.json`, and stdout
/// often ends up in CI logs or the journal.
pub(crate) fn print_completion_summary(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    vta_session: Option<&vta::VtaSession>,
    show_admin_key: bool,
) {
    let conf_dir = config_writer::config_dir(config);
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Configuration: \x1b[1m{}\x1b[0m",
        config.config_path
    );
    out!(
        "  \x1b[32m\u{2714}\x1b[0m Lua functions: \x1b[1m{}\x1b[0m",
        conf_dir.join("atm-functions.lua").display()
    );

    if let Some(ref did) = artefacts.admin_did {
        out!("  \x1b[32m\u{2714}\x1b[0m Admin DID: \x1b[36m{did}\x1b[0m");
        let key = match (&artefacts.admin_secret, vta_session) {
            (Some(secret), _) => secret.get_private_keymultibase().ok(),
            (None, Some(session)) if config.admin_did_mode == ADMIN_VTA => {
                Some(session.admin_private_key_mb().to_string())
            }
            _ => None,
        };
        if let Some(key) = key {
            print_admin_key(&key, show_admin_key);
        }
    }

    if config.secret_storage == STORAGE_FILE {
        out!(
            "  \x1b[32m\u{2714}\x1b[0m Secrets: \x1b[1m{}\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        out!(
            "  \x1b[32m\u{2714}\x1b[0m SSL certificates: {}",
            conf_dir.join("keys").display()
        );
    }
}

/// Where the admin key is, and — only with `--show-admin-key` on a
/// terminal — the key itself.
pub(crate) fn print_admin_key(privkey_multibase: &str, show_admin_key: bool) {
    use std::io::IsTerminal;
    if !show_admin_key {
        out!(
            "    \x1b[2mThe admin private key is stored in the secret backend / \
             admin-monitor.json; it is not printed (--show-admin-key prints it on a \
             terminal).\x1b[0m"
        );
        return;
    }
    if !io::stdout().is_terminal() {
        err!(
            "  \x1b[33mNote:\x1b[0m --show-admin-key is ignored: stdout is not a terminal, and \
             the key would land in a log."
        );
        return;
    }
    out!();
    out!(
        "  \x1b[41;97m UNSAFE \x1b[0m \x1b[1mAdmin private key printed below (--show-admin-key).\x1b[0m"
    );
    out!("  \x1b[2mCopy it to an offline store now and clear your terminal scrollback.\x1b[0m");
    out!("  \x1b[2mPrivate key (multibase): {privkey_multibase}\x1b[0m");
}
