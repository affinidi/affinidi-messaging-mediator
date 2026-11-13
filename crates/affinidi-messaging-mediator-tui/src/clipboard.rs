//! Getting text out of the console: copy to the terminal's clipboard with an
//! OSC 52 escape (which works over SSH, in terminals that allow it), or write
//! it to a file.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The OSC 52 sequence that asks the terminal to put `text` on the system
/// clipboard.
pub(crate) fn osc52(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", base64(text.as_bytes()))
}

/// Ask the terminal to put `text` on the clipboard. Whether it does is up to
/// the terminal (some need it enabled); nothing comes back to say.
pub(crate) fn copy(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(osc52(text).as_bytes())?;
    out.flush()
}

/// Write `text` to a new file in `dir` named after `stem`, never over an
/// existing one. Returns where it went.
pub(crate) fn save(dir: &Path, stem: &str, text: &str) -> std::io::Result<PathBuf> {
    let stem: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    for n in 0..1000 {
        let name = match n {
            0 => format!("{stem}.txt"),
            n => format!("{stem}-{n}.txt"),
        };
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(text.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free file name"))
}

/// Standard base64, padded.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain}");
        }
    }

    #[test]
    fn the_clipboard_escape_carries_the_text() {
        assert_eq!(osc52("hi"), "\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn a_saved_file_never_replaces_another() {
        let dir = std::env::temp_dir().join(format!("console-save-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = save(&dir, "message 1/2", "one").unwrap();
        let second = save(&dir, "message 1/2", "two").unwrap();
        assert_ne!(first, second);
        assert_eq!(first.file_name().unwrap(), "message_1_2.txt");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "two");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
