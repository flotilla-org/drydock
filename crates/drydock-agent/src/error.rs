//! One error layer. Every refusal the agent sends, including the framework's
//! own rejections, is an [`AgentError`] carrying the HTTP status it chose and
//! the chain of causes behind its message. The client rebuilds the same value
//! as the source of its `io::Error`, so nothing is lost crossing the link.
use serde::{Deserialize, Serialize};
use std::{fmt, io};

macro_rules! kinds {
    ($($kind:ident),* $(,)?; $($agent:ident => $io:ident),* $(,)?) => {
        /// I/O kinds keep their `std::io` names; the remaining variants are
        /// agent refusals with no I/O equivalent and map to the nearest kind.
        #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
        pub enum ErrorKind { $($kind,)* $($agent,)* Other }
        impl From<io::ErrorKind> for ErrorKind {
            fn from(kind: io::ErrorKind) -> Self {
                match kind { $(io::ErrorKind::$kind => Self::$kind,)* _ => Self::Other }
            }
        }
        impl From<ErrorKind> for io::ErrorKind {
            fn from(kind: ErrorKind) -> Self {
                match kind { $(ErrorKind::$kind => Self::$kind,)* $(ErrorKind::$agent => Self::$io,)* ErrorKind::Other => Self::Other }
            }
        }
    }
}
kinds!(
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    StorageFull,
    NotSeekable,
    QuotaExceeded,
    FileTooLarge,
    ResourceBusy,
    ExecutableFileBusy,
    Deadlock,
    CrossesDevices,
    TooManyLinks,
    InvalidFilename,
    ArgumentListTooLong,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory;
    // The resource exists but is in the wrong state for this call.
    Conflict => Other,
    // Received bytes do not have the digest the caller promised.
    DigestMismatch => InvalidData,
    PreconditionFailed => Other,
    RangeNotSatisfiable => InvalidInput,
    UnsupportedMediaType => InvalidInput,
    PayloadTooLarge => FileTooLarge,
    MethodNotAllowed => Unsupported,
);

impl ErrorKind {
    /// The status the agent sends for a refusal of this kind.
    pub fn status(self) -> u16 {
        use ErrorKind::*;
        match self {
            NotFound => 404,
            PermissionDenied | ReadOnlyFilesystem => 403,
            AlreadyExists | AddrInUse | ResourceBusy | DirectoryNotEmpty | NotADirectory | IsADirectory | ExecutableFileBusy
            | CrossesDevices | TooManyLinks | Conflict => 409,
            InvalidInput | InvalidFilename | ArgumentListTooLong => 400,
            InvalidData | DigestMismatch => 422,
            FileTooLarge | PayloadTooLarge => 413,
            StorageFull | QuotaExceeded => 507,
            TimedOut => 504,
            Unsupported => 501,
            MethodNotAllowed => 405,
            UnsupportedMediaType => 415,
            RangeNotSatisfiable => 416,
            PreconditionFailed => 412,
            _ => 500,
        }
    }
    /// The kind for a status produced outside the agent's own handlers, such
    /// as a framework rejection.
    pub fn from_status(status: u16) -> Self {
        use ErrorKind::*;
        match status {
            400 => InvalidInput,
            403 => PermissionDenied,
            404 => NotFound,
            405 => MethodNotAllowed,
            409 => Conflict,
            412 => PreconditionFailed,
            413 => PayloadTooLarge,
            415 => UnsupportedMediaType,
            416 => RangeNotSatisfiable,
            422 => InvalidData,
            501 => Unsupported,
            504 => TimedOut,
            507 => StorageFull,
            _ => Other,
        }
    }
}

/// Machine-readable failure, also retained as the source of a client's io::Error.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentError {
    /// What the agent was doing, such as `file.write` or `process.signal`.
    pub operation: String,
    /// What it was doing it to: a path, a forward ID, a process ID.
    pub subject: String,
    pub kind: ErrorKind,
    /// The HTTP status of the refusal.
    pub status: u16,
    pub message: String,
    /// The underlying errors, outermost first, when the message has any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<String>,
}
impl AgentError {
    pub fn new(operation: impl Into<String>, subject: impl fmt::Display, kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            subject: subject.to_string(),
            kind,
            status: kind.status(),
            message: message.into(),
            causes: vec![],
        }
    }
    /// An I/O failure, keeping its kind and every cause in its source chain.
    /// An error that already carries an AgentError keeps that one unchanged.
    pub fn io(operation: impl Into<String>, subject: impl fmt::Display, error: io::Error) -> Self {
        if let Some(agent) = error.get_ref().and_then(|e| e.downcast_ref::<AgentError>()) {
            return agent.clone();
        }
        let mut causes = Vec::new();
        let mut source = error.get_ref().and_then(|e| e.source());
        while let Some(cause) = source {
            causes.push(cause.to_string());
            source = cause.source();
        }
        let mut agent = Self::new(operation, subject, error.kind().into(), error.to_string());
        if let Some(code) = error.raw_os_error() {
            causes.push(format!("os error {code}"));
            agent.message = io::Error::from_raw_os_error(code).to_string();
        }
        agent.causes = causes;
        agent
    }
    pub(crate) fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::from(self.kind), self)
    }
    /// The structured refusal behind a client error, when it came from the agent.
    pub fn of(error: &io::Error) -> Option<&AgentError> {
        error.get_ref().and_then(|e| e.downcast_ref::<AgentError>())
    }
}
impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.operation, self.subject, self.message)?;
        for cause in &self.causes {
            write!(f, ": {cause}")?;
        }
        write!(f, " ({:?}, {})", self.kind, self.status)
    }
}
impl std::error::Error for AgentError {}
impl axum::response::IntoResponse for AgentError {
    fn into_response(self) -> axum::response::Response {
        let status = http::StatusCode::from_u16(self.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
        (status, axum::Json(self)).into_response()
    }
}
pub(crate) fn context(operation: &str, subject: impl fmt::Display, error: io::Error) -> io::Error {
    AgentError::io(operation, subject, error).into_io()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Every kind's status maps back to a kind with the same status, so a
    // framework refusal and a handler refusal of one status look alike.
    #[test]
    fn statuses_round_trip_through_kinds() {
        for status in [400, 403, 404, 405, 409, 412, 413, 415, 416, 422, 501, 504, 507] {
            assert_eq!(ErrorKind::from_status(status).status(), status);
        }
        assert_eq!(ErrorKind::from_status(418), ErrorKind::Other);
    }
    // The cause chain survives: an OS error names its errno, and a wrapped
    // error lists the inner error after the outer message.
    #[test]
    fn causes_are_kept() {
        let error = AgentError::io("file.write", "/x", io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(error.kind, ErrorKind::StorageFull);
        assert_eq!(error.status, 507);
        assert_eq!(error.causes, vec![format!("os error {}", libc::ENOSPC)]);
        #[derive(Debug)]
        struct Outer(io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let error = AgentError::io("x", "y", io::Error::other(Outer(io::Error::other("inner"))));
        assert_eq!(error.message, "outer");
        assert_eq!(error.causes, vec!["inner".to_owned()]);
        let display = error.to_string();
        assert!(display.contains("outer: inner"), "{display}");
        let wrapped = AgentError::io("other", "z", error.clone().into_io());
        assert_eq!(wrapped, error);
    }
}
