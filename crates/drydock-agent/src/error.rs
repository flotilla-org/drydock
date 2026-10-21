use serde::{Deserialize, Serialize};
use std::{fmt, io};

macro_rules! kinds {
    ($($kind:ident),* $(,)?) => {
        #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
        pub enum ErrorKind { $($kind,)* Other }
        impl From<io::ErrorKind> for ErrorKind {
            fn from(kind: io::ErrorKind) -> Self {
                match kind { $(io::ErrorKind::$kind => Self::$kind,)* _ => Self::Other }
            }
        }
        impl From<ErrorKind> for io::ErrorKind {
            fn from(kind: ErrorKind) -> Self {
                match kind { $(ErrorKind::$kind => Self::$kind,)* ErrorKind::Other => Self::Other }
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
    OutOfMemory
);

/// Machine-readable failure, also retained as the source of a client's io::Error.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentError {
    pub operation: String,
    pub subject: String,
    pub kind: ErrorKind,
    pub message: String,
}
impl AgentError {
    pub(crate) fn new(operation: impl Into<String>, subject: impl std::fmt::Display, error: io::Error) -> Self {
        Self { operation: operation.into(), subject: subject.to_string(), kind: error.kind().into(), message: error.to_string() }
    }
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::from(self.kind), self)
    }
}
impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ({:?}): {}", self.operation, self.subject, self.kind, self.message)
    }
}
impl std::error::Error for AgentError {}
pub(crate) fn context(operation: &str, subject: impl fmt::Display, error: io::Error) -> io::Error {
    AgentError::new(operation, subject, error).into_io()
}
