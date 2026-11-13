//! Text from a peer mediator, made safe to log and keep (#140).
//!
//! The next hop is chosen by the recipient's DID document, so whatever it
//! sends back is untrusted: a refusal body may be arbitrarily large, and it
//! and a relay-ack `reason` may carry newlines or control characters that
//! forge log lines. Both end up in a failure reason that is logged at WARN
//! and may be reported to the sender.
//!
//! So at most [`PEER_TEXT_LIMIT`] bytes are read from a refusal body, and any
//! peer text is cut to that length and has its control and bidirectional
//! formatting characters escaped before it is used.

/// Most bytes of peer text kept: enough for any error message a mediator
/// sends, small enough that a hostile peer can't fill memory or the log.
pub const PEER_TEXT_LIMIT: usize = 2048;

/// Marks text that was cut short.
const TRUNCATED: &str = "…[truncated]";

/// Read at most [`PEER_TEXT_LIMIT`] bytes of `response`'s body, then
/// [`sanitize`] it. The rest of the body is never read: the response is
/// dropped, closing its connection.
pub(crate) async fn bounded_body(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    let mut truncated = false;
    while body.len() <= PEER_TEXT_LIMIT {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            // A body that breaks off is reported as far as it got.
            Ok(None) | Err(_) => break,
        }
    }
    if body.len() > PEER_TEXT_LIMIT {
        body.truncate(PEER_TEXT_LIMIT);
        truncated = true;
    }
    let mut text = sanitize(&String::from_utf8_lossy(&body));
    if truncated && !text.ends_with(TRUNCATED) {
        text.push_str(TRUNCATED);
    }
    text
}

/// `text`, cut to at most [`PEER_TEXT_LIMIT`] bytes (on a character
/// boundary) and with every control character and bidirectional formatting
/// character escaped (`\n`, `\u{1b}`, `\u{202e}`, ...), so it stays on one
/// log line and reads as what it is.
pub fn sanitize(text: &str) -> String {
    let (kept, truncated) = if text.len() > PEER_TEXT_LIMIT {
        let mut end = PEER_TEXT_LIMIT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (&text[..end], true)
    } else {
        (text, false)
    };
    let mut out = String::with_capacity(kept.len());
    for c in kept.chars() {
        if c.is_control() || is_bidi_control(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    if truncated {
        out.push_str(TRUNCATED);
    }
    out
}

/// Characters that reorder how the text around them is displayed.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_bidi_characters_are_escaped() {
        assert_eq!(
            sanitize("bad\nFORWARD_OK fake\r\x1b[31m\u{202e}x"),
            "bad\\nFORWARD_OK fake\\r\\u{1b}[31m\\u{202e}x"
        );
        assert_eq!(sanitize("plain text, ünïcode"), "plain text, ünïcode");
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let long = "é".repeat(PEER_TEXT_LIMIT);
        let out = sanitize(&long);
        assert!(out.ends_with(TRUNCATED));
        assert!(out.len() <= PEER_TEXT_LIMIT + TRUNCATED.len());
        assert!(sanitize(&"a".repeat(PEER_TEXT_LIMIT)).len() == PEER_TEXT_LIMIT);
    }

    /// A peer's refusal body is read only up to the limit, however much it
    /// sends, and its control characters are escaped.
    #[tokio::test]
    async fn a_refusal_body_is_read_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            // Chunked, and far longer than the limit: 64 MiB if read whole.
            let _ = socket
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n\
                      10\r\nline one\nline 2!\r\n",
                )
                .await;
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..1024 {
                let head = format!("{:x}\r\n", chunk.len());
                if socket.write_all(head.as_bytes()).await.is_err()
                    || socket.write_all(&chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let body = tokio::time::timeout(std::time::Duration::from_secs(10), bounded_body(response))
            .await
            .expect("reading stops at the limit");
        assert!(body.starts_with("line one\\nline 2!x"), "{body}");
        assert!(body.ends_with(TRUNCATED));
        assert!(body.len() <= PEER_TEXT_LIMIT + TRUNCATED.len() + 8);
    }
}
