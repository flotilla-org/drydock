//! A stand-in agent for hosts' tests of how they handle a process whose output
//! ends badly. It answers hello and serves every process spawned through it the
//! scripted output, in the agent's own process framing, so a host test never
//! encodes drydock's wire format itself. Everything else is not found.
use crate::{ExitStatus, FEATURES, Hello, ProcessInfo, ProcessState, frames::Frame};
use axum::{
    Json, Router,
    body::Body,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use bytes::Bytes;
use drydock_transport::Transport;
use futures_util::StreamExt;
use std::{io, sync::Arc};

/// How a scripted process's output stream ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ending {
    /// With an exit frame, as every complete stream does.
    Exit(ExitStatus),
    /// Closed without an exit frame: the reader sees `UnexpectedEof`.
    Close,
    /// Never: the stream stays open and silent.
    Stall,
}

/// One process's output, as the stand-in serves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptedOutput {
    pub stdout: Bytes,
    pub stderr: Bytes,
    pub ending: Ending,
}

/// Serve the stand-in on `transport`'s host-facing links until it closes,
/// reporting `fingerprint` in its hello. `script` is asked for each process's
/// output as the process is read, so a test can change it between processes.
pub async fn serve(
    mut transport: Transport,
    fingerprint: String,
    script: impl Fn() -> ScriptedOutput + Send + Sync + 'static,
) -> io::Result<()> {
    let hello = Hello {
        fingerprint,
        features: FEATURES.iter().map(|feature| (*feature).into()).collect(),
        platform: Some(crate::Platform::current()),
        boot_id: "stand-in".into(),
        probation: false,
    };
    let script = Arc::new(script);
    let router = Router::new()
        .route("/hello", get(move || async move { Json(hello.clone()) }))
        .route(
            "/processes",
            post(|Json(request): Json<crate::Exec>| async move {
                let info = ProcessInfo {
                    id: "stand-in".into(),
                    pid: 0,
                    program: request.program,
                    state: ProcessState::Running,
                    buffered: 0,
                    stdout: 0,
                    stderr: 0,
                };
                (StatusCode::CREATED, Json(info))
            }),
        )
        .route(
            "/processes/{id}/output",
            get(move || {
                let output = script();
                async move {
                    let mut frames = Vec::new();
                    for (stderr, bytes) in [(false, output.stdout), (true, output.stderr)] {
                        if !bytes.is_empty() {
                            frames.push(Frame::Output { stderr, offset: 0, bytes }.encode());
                        }
                    }
                    if let Ending::Exit(status) = &output.ending {
                        frames.push(Frame::Exit(*status).encode());
                    }
                    let frames = futures_util::stream::iter(frames.into_iter().map(Ok::<_, io::Error>));
                    let body = match output.ending {
                        Ending::Stall => Body::from_stream(frames.chain(futures_util::stream::pending())),
                        Ending::Exit(_) | Ending::Close => Body::from_stream(frames),
                    };
                    ([(header::CONTENT_TYPE, crate::frames::CONTENT_TYPE)], body).into_response()
                }
            }),
        );
    while let Some(incoming) = transport.accept().await.map_err(|error| io::Error::new(error.kind(), error.to_string()))? {
        tokio::spawn(drydock_transport::http2::serve(incoming, router.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Client, Exec, ExecEvent};
    use drydock_transport::Limits;
    use std::sync::Mutex;

    // A host reading a scripted process sees exactly the scripted output, and a
    // stream closed without its exit is UnexpectedEof, as from a real agent.
    #[tokio::test]
    async fn scripted_output_reaches_the_real_client() {
        let (host, guest) = tokio::io::duplex(64 * 1024);
        let (host, guest) = tokio::join!(
            Transport::yamux(Box::new(host), true, Limits::default()),
            Transport::yamux(Box::new(guest), false, Limits::default())
        );
        let ending = Arc::new(Mutex::new(Ending::Exit(ExitStatus { code: Some(0), signal: None, timed_out: false })));
        let scripted = ending.clone();
        let server = tokio::spawn(serve(guest.unwrap(), "stand-in-test".into(), move || ScriptedOutput {
            stdout: Bytes::from_static(b"out"),
            stderr: Bytes::from_static(b"err"),
            ending: scripted.lock().unwrap().clone(),
        }));
        let client = Client::connect(host.unwrap(), "stand-in-test").await.unwrap();
        let (stdout, stderr, status) = client.exec(Exec::new("anything", ["at", "all"])).await.unwrap().collect(1024).await.unwrap();
        assert_eq!((stdout.as_slice(), stderr.as_slice(), status.code), (b"out".as_slice(), b"err".as_slice(), Some(0)));
        *ending.lock().unwrap() = Ending::Close;
        let mut output = client.exec(Exec::new("anything", Vec::<String>::new())).await.unwrap();
        assert_eq!(output.next().await.unwrap(), Some(ExecEvent::Stdout(Bytes::from_static(b"out"))));
        assert_eq!(output.next().await.unwrap(), Some(ExecEvent::Stderr(Bytes::from_static(b"err"))));
        assert_eq!(output.next().await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        server.abort();
    }
}
