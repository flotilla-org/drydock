//! Live check of drydock-transport's WebSocket dialer and tunnel stream
//! against a provider's TCP tunnel to an agent's token-gated TCP listener,
//! as `scripts/live-tcp-listener.py --tunnel-check` runs it:
//!
//! `tunnel_check URL KEY_FILE TOKEN_FILE`
//!
//! URL is the tunnel's `wss://` URL, KEY_FILE holds the provider's API key
//! (sent as a Bearer token) and TOKEN_FILE the agent's TCP token. Through
//! the production TLS dialer it does the handshake and reads the agent's
//! hello, writes 4 MiB into the guest and reads it back (writes are split
//! into 64 KiB frames), then checks that a wrong token gets the agent's 401
//! and a wrong key the provider's. Every check prints PASS or FAIL; the exit
//! status is 0 when all passed.
use drydock_agent::{Client, FileOptions};
use drydock_transport::{
    tcp::{self, Token},
    websocket::{self, DialError, TlsDialer, WebSocketDialer, tungstenite::http},
};
use std::{io, path::Path, time::Instant};

/// Tensorlake's tunnel proxy drops connections carrying larger frames.
const MAX_FRAME: usize = 64 << 10;

fn bearer(key: &str) -> http::HeaderMap {
    let mut value = http::HeaderValue::from_str(&format!("Bearer {key}")).expect("a key fits a header");
    value.set_sensitive(true);
    http::HeaderMap::from_iter([(http::header::AUTHORIZATION, value)])
}

struct Checks(bool);
impl Checks {
    fn check(&mut self, passed: bool, message: impl AsRef<str>) {
        println!("{} {}", if passed { "PASS" } else { "FAIL" }, message.as_ref());
        self.0 &= passed;
    }
}

async fn agent(dialer: &TlsDialer, url: &str, key: &str, token: &Token, fingerprint: &str) -> io::Result<Client> {
    let socket = dialer.dial(url, bearer(key)).await.map_err(io::Error::other)?;
    let stream = tcp::connect(websocket::stream(socket, MAX_FRAME), token).await?;
    Client::connect(stream, fingerprint).await
}

async fn round_trip(client: &Client) -> io::Result<(f64, bool)> {
    // Unique per run, so concurrent checks against one sandbox do not collide.
    let probe =
        format!("/tmp/drydock-tunnel-check-{}-{}", std::process::id(), std::time::UNIX_EPOCH.elapsed().unwrap_or_default().as_nanos());
    let probe = Path::new(&probe);
    let content: Vec<u8> = (0..4u32 << 20).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    let started = Instant::now();
    client.write_bytes(probe, content.clone(), &FileOptions::default()).await?;
    let read = client.read_bytes(probe, 8 << 20).await?;
    let seconds = started.elapsed().as_secs_f64();
    client.remove(probe, false).await?;
    Ok((seconds, read == content))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, key_file, token_file] = &args[..] else {
        eprintln!("usage: tunnel_check URL KEY_FILE TOKEN_FILE");
        std::process::exit(2);
    };
    let key = std::fs::read_to_string(key_file).expect("read KEY_FILE").trim().to_owned();
    let token = Token::parse(&std::fs::read_to_string(token_file).expect("read TOKEN_FILE")).expect("TOKEN_FILE holds a tcp token");
    let dialer = TlsDialer::new().expect("TLS configuration");
    let mut checks = Checks(true);

    let started = Instant::now();
    match agent(&dialer, url, &key, &token, "").await {
        Ok(client) => {
            let hello = client.hello();
            checks.check(
                !hello.fingerprint.is_empty(),
                format!("hello through the Rust dialer in {:.2}s: fingerprint {:.16}…", started.elapsed().as_secs_f64(), hello.fingerprint),
            );
            // A second tunnel, expecting this agent, so file calls are permitted.
            let client = agent(&dialer, url, &key, &token, &hello.fingerprint).await;
            match async { round_trip(&client?).await }.await {
                Ok((seconds, same)) => checks.check(same, format!("4 MiB written and read back in {seconds:.2}s, in 64 KiB frames")),
                Err(error) => checks.check(false, format!("4 MiB round trip: {error}")),
            }
        }
        Err(error) => checks.check(false, format!("hello through the Rust dialer: {error}")),
    }

    let wrong = Token::generate().expect("random token");
    match agent(&dialer, url, &key, &wrong, "").await {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => checks.check(true, "a wrong token is refused through the tunnel"),
        other => checks.check(false, format!("a wrong token: {:?}", other.map(drop))),
    }
    match dialer.dial(url, bearer("tl_apiKey_wrong")).await {
        Err(DialError::Refused { status, body }) if status == 401 || status == 403 => {
            checks.check(true, format!("a wrong API key is refused with HTTP {status}: {body:.80}"))
        }
        other => checks.check(false, format!("a wrong API key: {:?}", other.map(drop))),
    }
    std::process::exit(if checks.0 { 0 } else { 1 });
}
