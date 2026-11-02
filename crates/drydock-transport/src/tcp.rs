//! Both ends' shared half of the agent's TCP handshake, for providers that
//! reach only a guest TCP port (a port proxy or a tunnel). The agent's
//! listener serves it; a module dials it through the provider's relay. A
//! guest TCP port is open to every guest user, so each connection first
//! proves it holds the vessel's token: one HTTP/1.1 request,
//!
//! ```text
//! GET /v1/connect HTTP/1.1
//! Connection: Upgrade
//! Upgrade: drydock-agent          (or websocket, for proxies that pass only that)
//! Authorization: Bearer <token>
//! ```
//!
//! answered `101 Switching Protocols`. The connection then carries raw bytes,
//! exactly what the agent's Unix socket carries, with no WebSocket framing
//! whichever token the client upgraded with. A wrong or missing token is
//! answered 401.
use crate::ByteStream;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use std::{fmt, io, sync::Arc};

/// The path of the handshake request.
pub const CONNECT_PATH: &str = "/v1/connect";
/// The `Upgrade` token the agent prefers, and answers with.
pub const PROTOCOL: &str = "drydock-agent";
/// Random bytes in a generated token, and the least a token may hold.
const TOKEN_BYTES: usize = 32;

/// A vessel's TCP token: at least 32 random bytes, base64url. It never
/// appears in `Debug` output, so diagnostics cannot leak it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(Arc<str>);
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}
impl Token {
    /// A fresh token of 32 random bytes, for a module to write into the vessel.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self(base64url(&bytes).into()))
    }
    /// A token's text: unpadded or padded base64url of at least 32 bytes.
    /// Surrounding whitespace, such as a file's final newline, is ignored, and
    /// the token is kept unpadded: a client may present either form.
    pub fn parse(text: &str) -> io::Result<Self> {
        let text = text.trim_ascii();
        let digits = text.trim_end_matches('=');
        let invalid = |reason: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tcp token {reason}"));
        if !digits.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || text.len() - digits.len() > 2 {
            return Err(invalid("must be base64url"));
        }
        if digits.len() % 4 == 1 {
            return Err(invalid("is not whole base64url"));
        }
        if digits.len() * 6 / 8 < TOKEN_BYTES {
            return Err(invalid("must hold at least 32 bytes"));
        }
        Ok(Self(digits.into()))
    }
    /// The token's text, for the module that writes it into the vessel and
    /// for the client's handshake. Never log it.
    pub fn secret(&self) -> &str {
        &self.0
    }
    /// Whether `presented` (padded or not, surrounding whitespace ignored) is
    /// this token. Constant-time in the presented value: both sides are
    /// digested first, so neither the token's length nor a matching prefix
    /// shows in timing.
    pub fn admits(&self, presented: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut presented = presented.trim_ascii();
        while let [rest @ .., b'='] = presented {
            presented = rest;
        }
        let (expected, presented) = (Sha256::digest(self.0.as_bytes()), Sha256::digest(presented));
        std::hint::black_box(expected.iter().zip(presented.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b))) == 0
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            text.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    text
}

/// The client's side of the handshake: asks `stream`, a connection to an
/// agent's TCP listener (directly or through a provider's relay), to switch
/// to the agent's wire. The result carries what a Unix-socket connection
/// does, so the agent's client takes it. A refused token is
/// `PermissionDenied`.
pub async fn connect(stream: ByteStream, token: &Token) -> io::Result<ByteStream> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(io::Error::other)?;
    // The connection task ends by handing its bytes to the upgrade; on any
    // early return it is aborted.
    struct Abort(tokio::task::JoinHandle<Result<(), hyper::Error>>);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _driver = Abort(tokio::spawn(connection.with_upgrades()));
    let request = Request::get(CONNECT_PATH)
        .header(header::HOST, PROTOCOL)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, PROTOCOL)
        .header(header::AUTHORIZATION, format!("Bearer {}", token.secret()))
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let mut response = sender.send_request(request).await.map_err(io::Error::other)?;
    match response.status() {
        StatusCode::SWITCHING_PROTOCOLS => {}
        StatusCode::UNAUTHORIZED => {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the agent refused the tcp token"));
        }
        status => {
            return Err(io::Error::other(format!("the agent's tcp listener answered {status}")));
        }
    }
    crate::http::upgraded(hyper::upgrade::on(&mut response)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // Generated tokens encode 32 random bytes; any base64url text of at least
    // 32 bytes parses, padded or not and with surrounding whitespace, and
    // admits exactly itself. Shorter, or with other characters, is refused.
    #[hegel::test]
    fn tokens_parse_base64url_of_at_least_32_bytes(tc: hegel::TestCase) {
        let generated = Token::generate().unwrap();
        assert_eq!(generated.secret().len(), 43);
        Token::parse(generated.secret()).unwrap();
        let bytes = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(96));
        let mut text = base64url(&bytes);
        if tc.draw(gs::booleans()) {
            text.push_str(&"=".repeat((4 - text.len() % 4) % 4));
        }
        let parsed = Token::parse(&format!(" {text}\n"));
        assert_eq!(parsed.is_ok(), bytes.len() >= 32, "{} bytes", bytes.len());
        if let Ok(token) = parsed {
            assert!(token.admits(text.as_bytes()));
            assert!(token.admits(text.trim_end_matches('=').as_bytes()));
            assert!(!token.secret().contains('='));
            assert!(!token.admits(format!("{text}A").as_bytes()));
            assert!(!token.admits(b""));
            assert!(!format!("{token:?}").contains(&text));
            let bad = tc.draw(gs::sampled_from(vec!['+', '/', '.', ' ', '\u{e9}']));
            let at = tc.draw(gs::integers::<usize>().max_value(text.trim_end_matches('=').len() - 1));
            let mut spoiled: Vec<char> = text.chars().collect();
            spoiled[at] = bad;
            assert!(Token::parse(&spoiled.into_iter().collect::<String>()).is_err());
        }
    }
}
