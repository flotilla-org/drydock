use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionKind {
    Single,
    Yamux,
}

/// Link streams carry exactly one long-lived HTTP/2 connection. Raw streams
/// identify an opaque forward ID, without consumer-specific vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    Forward { id: String },
    Control,
}
impl Purpose {
    pub(crate) fn validate(&self) -> io::Result<()> {
        match self {
            Self::Control => Ok(()),
            Self::Forward { id } => validate_text(id),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn validate_text(text: &str) -> io::Result<()> {
    if text.is_empty() || text.len() > 1024 || text.chars().any(char::is_control) {
        return Err(invalid("stream target must be 1..=1024 UTF-8 bytes without control characters"));
    }
    Ok(())
}

pub(crate) async fn write_connection_kind<W: AsyncWrite + Unpin>(s: &mut W, kind: ConnectionKind) -> io::Result<()> {
    s.write_all(match kind {
        ConnectionKind::Single => b"DDT\x01\x00",
        ConnectionKind::Yamux => b"DDT\x01\x01",
    })
    .await?;
    s.flush().await
}
/// Consumes only the five-byte preface, leaving the stream at its payload.
pub async fn read_connection_kind<R: AsyncRead + Unpin>(s: &mut R) -> io::Result<ConnectionKind> {
    let mut header = [0; 5];
    s.read_exact(&mut header).await?;
    if &header[..4] != b"DDT\x01" {
        return Err(invalid("unknown transport magic or version"));
    }
    match header[4] {
        0 => Ok(ConnectionKind::Single),
        1 => Ok(ConnectionKind::Yamux),
        _ => Err(invalid("unknown connection kind")),
    }
}
pub(crate) async fn write_purpose<W: AsyncWrite + Unpin>(s: &mut W, purpose: &Purpose) -> io::Result<()> {
    purpose.validate()?;
    let (tag, text) = match purpose {
        Purpose::Forward { id } => (4, id.as_str()),
        Purpose::Control => (0, ""),
    };
    s.write_u8(tag).await?;
    if tag >= 2 {
        s.write_u16(text.len() as u16).await?;
        s.write_all(text.as_bytes()).await?;
    }
    s.flush().await
}
pub(crate) async fn read_purpose<R: AsyncRead + Unpin>(s: &mut R) -> io::Result<Purpose> {
    let tag = s.read_u8().await?;
    let purpose = match tag {
        0 => Purpose::Control,
        4 => {
            let len = s.read_u16().await? as usize;
            if len == 0 || len > 1024 {
                return Err(invalid("stream target length out of bounds"));
            }
            let mut text = vec![0; len];
            s.read_exact(&mut text).await?;
            let text = String::from_utf8(text).map_err(|_| invalid("stream target is not UTF-8"))?;
            Purpose::Forward { id: text }
        }
        _ => return Err(invalid("unknown stream purpose")),
    };
    purpose.validate()?;
    Ok(purpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // The versioned wire layout is a contract: the five-byte preface and tag
    // must be unambiguous, with no buffering that consumes application bytes.
    #[tokio::test]
    async fn wire_layout_and_payload_boundary() {
        for (purpose, expected) in [(Purpose::Forward { id: "x".into() }, vec![4, 0, 1, b'x']), (Purpose::Control, vec![0])] {
            let mut encoded = Vec::new();
            write_connection_kind(&mut encoded, ConnectionKind::Single).await.unwrap();
            write_purpose(&mut encoded, &purpose).await.unwrap();
            assert_eq!(&encoded[..5], b"DDT\x01\x00");
            assert_eq!(&encoded[5..], expected);
            encoded.extend_from_slice(b"payload");
            let mut input = encoded.as_slice();
            assert_eq!(read_connection_kind(&mut input).await.unwrap(), ConnectionKind::Single);
            assert_eq!(read_purpose(&mut input).await.unwrap(), purpose);
            assert_eq!(input, b"payload");
        }
        let mut encoded = Vec::new();
        write_connection_kind(&mut encoded, ConnectionKind::Yamux).await.unwrap();
        assert_eq!(encoded, b"DDT\x01\x01");
    }

    // Every valid UTF-8 target round-trips; invalid sizes and controls
    // are refused before any wire bytes are written. Covers both size edges,
    // multibyte UTF-8 and both purpose variants.
    #[hegel::test]
    fn purposes_round_trip_or_refuse(tc: hegel::TestCase) {
        let tag = tc.draw(gs::integers::<u8>().min_value(0).max_value(1));
        let len = tc.draw(gs::integers::<usize>().min_value(0).max_value(1025));
        let alphabet = ["a", "β", "\0", "界"];
        let letter = alphabet[tc.draw(gs::integers::<usize>().min_value(0).max_value(3))];
        let text = letter.repeat(len);
        let valid_text = !text.is_empty() && text.len() <= 1024 && !text.contains('\0');
        let expected_valid = tag == 0 || valid_text;
        let purpose = match tag {
            0 => Purpose::Control,
            _ => Purpose::Forward { id: text },
        };
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let mut bytes = Vec::new();
            let result = write_purpose(&mut bytes, &purpose).await;
            assert_eq!(result.is_ok(), expected_valid);
            if expected_valid {
                assert_eq!(read_purpose(&mut bytes.as_slice()).await.unwrap(), purpose);
            } else {
                assert!(bytes.is_empty());
            }
        });
    }

    // Invalid magic/version/mode, unknown tags, malformed UTF-8, oversized and
    // truncated targets are rejected without allocating the claimed wire size.
    #[tokio::test]
    async fn rejects_invalid_and_truncated_headers() {
        for bytes in [b"BAD\x01\x00".as_slice(), b"DDT\x02\x00", b"DDT\x01\x02", b"DD"] {
            assert!(read_connection_kind(&mut &bytes[..]).await.is_err());
        }
        for bytes in [
            vec![1],
            vec![2],
            vec![3],
            vec![5],
            vec![4, 0, 0],
            vec![4, 4, 1],
            vec![4, 0, 1, 255],
            vec![4, 0, 2, b'x'],
            vec![3, 0, 1, b'h', 0, 0],
            vec![4, 0, 1, 0],
        ] {
            assert!(read_purpose(&mut bytes.as_slice()).await.is_err());
        }
        for len in [1, 1024] {
            let purpose = Purpose::Forward { id: "x".repeat(len) };
            let mut bytes = Vec::new();
            write_purpose(&mut bytes, &purpose).await.unwrap();
            for cut in 0..bytes.len() {
                assert!(read_purpose(&mut &bytes[..cut]).await.is_err());
            }
            assert_eq!(read_purpose(&mut bytes.as_slice()).await.unwrap(), purpose);
        }
    }
}
