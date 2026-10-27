//! Process output framing. Each frame is a one-byte kind, a big-endian u32
//! payload length and the payload. Output frames carry raw bytes after a
//! big-endian u64 offset into their stream, so a reader that reattaches can
//! see exactly which bytes it has. The exit frame carries JSON `ExitStatus`.
use crate::ExitStatus;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

pub(crate) const CONTENT_TYPE: &str = "application/vnd.drydock.process-frames";
pub(crate) const MAX_PAYLOAD: usize = 1024 * 1024;
const STDOUT: u8 = 1;
const STDERR: u8 = 2;
const EXIT: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Output { stderr: bool, offset: u64, bytes: Bytes },
    Exit(ExitStatus),
}
impl Frame {
    pub(crate) fn encode(&self) -> Bytes {
        match self {
            Frame::Output { stderr, offset, bytes } => {
                let mut out = BytesMut::with_capacity(13 + bytes.len());
                out.put_u8(if *stderr { STDERR } else { STDOUT });
                out.put_u32(8 + bytes.len() as u32);
                out.put_u64(*offset);
                out.extend_from_slice(bytes);
                out.freeze()
            }
            Frame::Exit(status) => {
                let json = serde_json::to_vec(status).expect("exit status serializes");
                let mut out = BytesMut::with_capacity(5 + json.len());
                out.put_u8(EXIT);
                out.put_u32(json.len() as u32);
                out.extend_from_slice(&json);
                out.freeze()
            }
        }
    }
}
/// The frame decoder: a length-delimited codec whose big-endian u32 length
/// follows the one-byte kind. It hands back whole frames, header included,
/// for [`Frame::decode`].
pub(crate) fn codec() -> tokio_util::codec::LengthDelimitedCodec {
    tokio_util::codec::LengthDelimitedCodec::builder()
        .length_field_offset(1)
        .length_field_length(4)
        // Keep the five header bytes in the frame, and count them in it.
        .num_skip(0)
        .length_adjustment(5)
        .max_frame_length(MAX_PAYLOAD + 8)
        .new_codec()
}
impl Frame {
    /// One whole frame from [`codec`].
    pub(crate) fn decode(mut frame: Bytes) -> io::Result<Frame> {
        let kind = frame.get_u8();
        frame.advance(4);
        match kind {
            STDOUT | STDERR => {
                if frame.len() < 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "process output frame lacks its offset"));
                }
                let offset = frame.get_u64();
                Ok(Frame::Output { stderr: kind == STDERR, offset, bytes: frame })
            }
            EXIT => serde_json::from_slice(&frame)
                .map(Frame::Exit)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("malformed exit frame: {e}"))),
            other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown process frame kind {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::Decoder;
    /// Decode `wire` fed in the given chunks, then at its end.
    fn decode(wire: &[u8], mut chunk: impl FnMut(usize) -> usize) -> io::Result<Vec<Frame>> {
        let (mut codec, mut buffer, mut decoded, mut at) = (codec(), BytesMut::new(), Vec::new(), 0);
        while at < wire.len() {
            let step = chunk(wire.len() - at);
            buffer.extend_from_slice(&wire[at..at + step]);
            at += step;
            while let Some(frame) = codec.decode(&mut buffer)? {
                decoded.push(Frame::decode(frame.freeze())?);
            }
        }
        while let Some(frame) = codec.decode_eof(&mut buffer)? {
            decoded.push(Frame::decode(frame.freeze())?);
        }
        Ok(decoded)
    }
    // Frames split at every generated boundary decode to the same sequence,
    // so framing never depends on how the transport chunks the body.
    #[hegel::test]
    fn frames_survive_any_chunking(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let frames = vec![
            Frame::Output { stderr: false, offset: 0, bytes: Bytes::from_static(&[0, 128, 255]) },
            Frame::Output { stderr: true, offset: 7, bytes: Bytes::new() },
            Frame::Output { stderr: false, offset: 3, bytes: Bytes::from(vec![9; 300]) },
            Frame::Exit(ExitStatus { code: None, signal: Some(9), timed_out: true }),
        ];
        let wire: Vec<u8> = frames.iter().flat_map(|f| f.encode().to_vec()).collect();
        let decoded = decode(&wire, |left| tc.draw(gs::integers::<usize>().min_value(1).max_value(left))).unwrap();
        assert_eq!(decoded, frames);
    }
    #[test]
    fn malformed_frames_are_refused() {
        for wire in [vec![9, 0, 0, 0, 0], vec![1, 0, 0, 0, 1, 0], vec![3, 0, 0, 0, 1, b'x'], vec![1, 0xff, 0xff, 0xff, 0xff]] {
            assert_eq!(decode(&wire, |left| left).unwrap_err().kind(), io::ErrorKind::InvalidData, "{wire:?}");
        }
    }
}
