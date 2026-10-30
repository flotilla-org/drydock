use std::{
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
};
/// A dedicated run directory belongs to the agent's effective user. Refuse
/// symlinks and sticky/shared directories rather than changing their protection.
pub fn private_directory(path: &Path) -> io::Result<()> {
    let result = (|| {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o1000 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "run directory must be an owned, non-sticky directory"));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    })();
    result.map_err(|e| crate::error::context("socket.directory", path.display(), e))
}
pub fn protect(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| crate::error::context("socket.permissions", path.display(), e))
}

/// Joins a byte channel to the agent listening at `path`: `drydock-agent
/// --bridge` on a command channel's stdin and stdout, for providers whose only
/// way into a vessel is a command (Namespace's SSH gateway refuses Unix-socket
/// forwards). The end of `input` half-closes the socket; the agent closing its
/// side ends the bridge, whether or not `input` has ended.
pub async fn bridge<R, W>(path: &Path, mut input: R, mut output: W) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| crate::error::context("socket.connect", path.display(), e))?;
    let (mut from_agent, mut to_agent) = stream.into_split();
    {
        let outbound = tokio::io::copy(&mut from_agent, &mut output);
        tokio::pin!(outbound);
        let inbound = async {
            tokio::io::copy(&mut input, &mut to_agent).await?;
            to_agent.shutdown().await
        };
        tokio::select! {
            done = &mut outbound => { done?; }
            done = inbound => { done?; outbound.await?; }
        }
    }
    output.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Bytes cross both ways unchanged, the end of input reaches the agent as
    // EOF, and the bridge ends once the agent closes, with input still open.
    #[tokio::test]
    async fn bridge_carries_bytes_and_half_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let agent = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(&received.iter().rev().copied().collect::<Vec<_>>()).await.unwrap();
            received
        });
        let payload: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        let (mut input, bridge_input) = tokio::io::duplex(4096);
        let (bridge_output, mut output) = tokio::io::duplex(4096);
        let running = tokio::spawn({
            let path = path.clone();
            async move { bridge(&path, bridge_input, bridge_output).await }
        });
        let written = payload.clone();
        tokio::spawn(async move {
            input.write_all(&written).await.unwrap();
            input.shutdown().await.unwrap();
        });
        let mut echoed = Vec::new();
        output.read_to_end(&mut echoed).await.unwrap();
        running.await.unwrap().unwrap();
        assert_eq!(agent.await.unwrap(), payload);
        assert_eq!(echoed, payload.iter().rev().copied().collect::<Vec<_>>());

        // An agent that closes first ends the bridge while input stays open.
        let listener = tokio::net::UnixListener::bind(dir.path().join("closing.sock")).unwrap();
        tokio::spawn(async move { drop(listener.accept().await.unwrap()) });
        let (_open_input, bridge_input) = tokio::io::duplex(64);
        let (bridge_output, _output) = tokio::io::duplex(64);
        bridge(&dir.path().join("closing.sock"), bridge_input, bridge_output).await.unwrap();

        let missing = bridge(&dir.path().join("missing.sock"), tokio::io::empty(), tokio::io::sink()).await.unwrap_err();
        assert!(missing.to_string().contains("missing.sock"), "{missing}");
    }
}
