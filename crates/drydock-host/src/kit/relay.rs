//! A relay over a vendor's process stream, carried one of two ways: a
//! WebSocket whose JSON text frames carry a process's stdin one way and its
//! output the other (the module dials and attaches it, and supplies its
//! [`Framing`]), or a connection the vendor's server took over, stdin
//! unframed and output in multiplexed frames ([`multiplexed`]).
use super::Vendor;
use crate::module::ByteStream;
use drydock_transport::websocket::{WebSocket, tungstenite::Message};
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The most stdin bytes one frame carries.
const STDIN_FRAME: usize = 32 << 10;

pub enum Frame {
    Stdout(Vec<u8>),
    Other,
    /// The process exited, or the vendor ended the stream.
    End,
}
/// A vendor's frames, `T` its output frame.
pub struct Framing<T> {
    pub vendor: Vendor,
    /// The frame carrying these stdin bytes; for none, the frame closing stdin.
    pub stdin: fn(&[u8]) -> serde_json::Value,
    /// What an output frame says; None when the relay cannot read it.
    pub output: fn(T) -> Option<Frame>,
}

/// The process's stdin and stdout as a byte stream, until the process exits,
/// the vendor ends the stream, or either side fails. Stdin closes at the
/// stream's end.
pub fn relay<T: DeserializeOwned + Send + 'static>(socket: WebSocket, framing: Framing<T>) -> ByteStream {
    let (near, far) = tokio::io::duplex(1 << 16);
    let vendor = framing.vendor;
    let (mut frames_out, mut frames_in) = socket.split();
    let (mut reader, mut writer) = tokio::io::split(far);
    let input = async move {
        let mut buffer = vec![0; STDIN_FRAME];
        loop {
            // Reading the local end of a duplex does not fail; if it did, its
            // end would be stdin's end all the same.
            let read = reader.read(&mut buffer).await.unwrap_or(0);
            let frame = (framing.stdin)(&buffer[..read]);
            if frames_out.send(Message::text(frame.to_string())).await.is_err() || read == 0 {
                break;
            }
        }
        // Stdin's end is not the relay's: output ends it, through the select below.
        std::future::pending::<()>().await
    };
    let output = async move {
        while let Some(Ok(message)) = frames_in.next().await {
            let text = match message {
                Message::Text(text) => text,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => break,
                _ => {
                    tracing::debug!("{vendor} sent a frame that is not text; the relay ends");
                    break;
                }
            };
            match serde_json::from_str::<T>(text.as_str()).ok().and_then(framing.output) {
                Some(Frame::Stdout(bytes)) if writer.write_all(&bytes).await.is_ok() => {}
                Some(Frame::Stdout(_) | Frame::End) => break,
                Some(Frame::Other) => {}
                None => {
                    tracing::debug!("{vendor} sent a frame the relay cannot read; the relay ends");
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::spawn(async move {
        tokio::select! {
            () = input => {}
            () = output => {}
        }
    });
    Box::new(near)
}

/// One stream of a multiplexed process stream, as a frame header names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdin,
    Stdout,
    Stderr,
    /// The server's own error, which ends the stream.
    System,
}
/// A multiplexed frame's header: its stream, three zero bytes, and its
/// length as a big-endian 32-bit number. None for any other header.
pub fn frame_header(header: [u8; 8]) -> Option<(Stream, usize)> {
    let stream = match header[0] {
        0 => Stream::Stdin,
        1 => Stream::Stdout,
        2 => Stream::Stderr,
        3 => Stream::System,
        _ => return None,
    };
    let [_, 0, 0, 0, a, b, c, d] = header else { return None };
    Some((stream, u32::from_be_bytes([a, b, c, d]) as usize))
}
/// The largest frame read; a server writes far smaller ones.
const FRAME_LIMIT: usize = 16 << 20;
/// The next frame, or None at the stream's end between frames. A stream
/// that ends inside a frame is an error.
async fn read_frame(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<Option<(Stream, Vec<u8>)>> {
    let mut header = [0; 8];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let invalid = |what| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    let (stream, length) = frame_header(header).ok_or_else(|| invalid("not a stream frame"))?;
    if length > FRAME_LIMIT {
        return Err(invalid("a stream frame over 16 MiB"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(Some((stream, bytes)))
}
/// A process's output from a multiplexed stream, appended to `chunks` as
/// (stderr, bytes) as it arrives, until the server ends the stream. A
/// server's error frame is the error it carries.
pub async fn read_output(mut stream: ByteStream, chunks: &mut Vec<(bool, Vec<u8>)>) -> std::io::Result<()> {
    while let Some((kind, bytes)) = read_frame(&mut stream).await? {
        match kind {
            Stream::Stdout | Stream::Stderr => chunks.push((kind == Stream::Stderr, bytes)),
            Stream::System => return Err(std::io::Error::other(String::from_utf8_lossy(&bytes).into_owned())),
            Stream::Stdin => {}
        }
    }
    Ok(())
}
/// A process's stdin and stdout over a connection a server took over: stdin
/// goes unframed, and output comes back in multiplexed frames, of which only
/// stdout is kept. The byte stream ends when the server ends the connection
/// or sends an error frame; its stdin's end half-closes the connection.
pub fn multiplexed(vendor: Vendor, connection: ByteStream) -> ByteStream {
    let (near, far) = tokio::io::duplex(1 << 16);
    let (mut from_server, mut to_server) = tokio::io::split(connection);
    let (mut reader, mut writer) = tokio::io::split(far);
    let input = async move {
        // Copying fails only when the connection does, which output sees too.
        if tokio::io::copy(&mut reader, &mut to_server).await.is_ok() {
            let _ = to_server.shutdown().await;
        }
        std::future::pending::<()>().await
    };
    let output = async move {
        loop {
            match read_frame(&mut from_server).await {
                Ok(Some((Stream::Stdout, bytes))) if writer.write_all(&bytes).await.is_ok() => {}
                Ok(Some((Stream::Stderr | Stream::Stdin, _))) => {}
                Ok(None) => break,
                Ok(Some((Stream::System, bytes))) => {
                    tracing::warn!(
                        "{vendor} ended the process stream with an error, so the relay ends: {}",
                        String::from_utf8_lossy(&bytes)
                    );
                    break;
                }
                Ok(Some((Stream::Stdout, _))) => break,
                Err(error) => {
                    tracing::warn!("{vendor} process stream failed, so the relay ends: {error}");
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::spawn(async move {
        tokio::select! {
            () = input => {}
            () = output => {}
        }
    });
    Box::new(near)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_headers() {
        assert_eq!(frame_header([1, 0, 0, 0, 0, 0, 1, 2]), Some((Stream::Stdout, 258)));
        assert_eq!(frame_header([2, 0, 0, 0, 0, 0, 0, 0]), Some((Stream::Stderr, 0)));
        assert_eq!(frame_header([3, 0, 0, 0, 0, 0, 0, 5]), Some((Stream::System, 5)));
        // Anything else is not a frame: a fourth stream, or padding that isn't zero.
        assert_eq!(frame_header([4, 0, 0, 0, 0, 0, 0, 1]), None);
        assert_eq!(frame_header([1, 0, 1, 0, 0, 0, 0, 1]), None);
    }

    // Only an end between frames is the stream's end; an end inside a frame,
    // or a frame over the limit, is an error.
    #[tokio::test]
    async fn frame_reads() {
        let mut whole: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 2, b'h', b'i'];
        assert_eq!(read_frame(&mut whole).await.unwrap(), Some((Stream::Stdout, b"hi".to_vec())));
        assert_eq!(read_frame(&mut whole).await.unwrap(), None);
        for mut cut in [&[1, 0, 0][..], &[1, 0, 0, 0, 0, 0, 0, 2, b'h'], &[1, 0, 0, 0, 2, 0, 0, 0]] {
            assert!(read_frame(&mut cut).await.is_err(), "{cut:?}");
        }
    }
}
