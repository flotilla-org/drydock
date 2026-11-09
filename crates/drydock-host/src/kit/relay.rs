//! A relay over a vendor's JSON-framed process stream: a WebSocket whose text
//! frames carry a process's stdin one way and its output the other. A module
//! dials and attaches the stream, and supplies its [`Framing`].
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
