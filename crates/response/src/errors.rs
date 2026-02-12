use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ResponseError {
    ProtectedProcess(u32),
    ProtectedPath(PathBuf),
    Io(std::io::Error),
    Signal(String),
    InvalidInput(String),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedProcess(pid) => write!(f, "process {} is protected", pid),
            Self::ProtectedPath(path) => {
                write!(f, "path {} is protected", path.display())
            }
            Self::Io(err) => write!(f, "io error: {}", err),
            Self::Signal(msg) => write!(f, "signal error: {}", msg),
            Self::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
        }
    }
}

impl std::error::Error for ResponseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ResponseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type ResponseResult<T> = std::result::Result<T, ResponseError>;
