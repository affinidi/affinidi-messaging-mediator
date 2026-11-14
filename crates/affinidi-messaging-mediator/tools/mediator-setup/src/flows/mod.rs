//! Entry flows of the binary: the interactive wizard and the headless
//! recipe / flag runs. Each builds a `WizardConfig` and hands it to
//! [`crate::provision`].

pub(crate) mod headless;
pub(crate) mod interactive;

pub(crate) fn print_banner() {
    // Gradient from purple (141) → blue (69) → cyan (43) across rows
    let r = "\x1b[0m";

    out!();
    out!("  \x1b[38;5;141m    ___    _________       _     ___ {r}");
    out!("  \x1b[38;5;135m   /   |  / __/ __(_)___  (_)___/ (_){r}");
    out!("  \x1b[38;5;105m  / /| | / /_/ /_/ / __ \\/ / __  / / {r}");
    out!("  \x1b[38;5;69m / ___ |/ __/ __/ / / / / / /_/ / /  {r}");
    out!("  \x1b[38;5;33m/_/  |_/_/ /_/ /_/_/ /_/_/\\__,_/_/   {r}");
    out!();
    out!("  \x1b[38;5;43m\u{2501}\u{2501}\u{2501}\x1b[0m \x1b[1;38;5;255mMediator Setup\x1b[0m");
    out!("  \x1b[2mSecure, scalable DIDComm & TSP messaging infrastructure\x1b[0m");
    out!();
}
