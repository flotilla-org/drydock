use crate::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// Only the opening result is framed. All subsequent application bytes remain
// untouched, including half-closes, upgrades, headers and streaming bodies.
pub(crate) async fn acknowledge(stream: &mut ByteStream, result: Result<(), AgentError>) -> io::Result<()> {
    let bytes = serde_json::to_vec(&result).map_err(invalid)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
pub(crate) async fn opened(stream: &mut ByteStream) -> io::Result<()> {
    let length = stream.read_u32().await?;
    if length > 64 * 1024 {
        return Err(invalid("oversized forward opening result"));
    }
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await?;
    let result: Result<(), AgentError> = serde_json::from_slice(&bytes).map_err(invalid)?;
    result.map_err(AgentError::into_io)
}
pub(crate) async fn serve(mut stream: ByteStream, id: &str, endpoint: Option<&Endpoint>) -> io::Result<()> {
    let connected = match endpoint {
        Some(endpoint) => endpoint.connect().await.map_err(|e| AgentError::new("forward.open", format!("{id}: {endpoint:?}"), e)),
        None => Err(AgentError::new("forward.open", id, io::Error::new(io::ErrorKind::NotFound, "unknown forward ID"))),
    };
    match connected {
        Ok(mut destination) => {
            acknowledge(&mut stream, Ok(())).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut destination).await?;
            Ok(())
        }
        Err(error) => {
            acknowledge(&mut stream, Err(error.clone())).await?;
            Err(error.into_io())
        }
    }
}
