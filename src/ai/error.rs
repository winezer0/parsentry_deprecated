use thiserror::Error;

#[derive(Error, Debug)]
pub enum AiError {
    #[error("timeout after {0}s")]
    Timeout(u64),
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("invalid response: {0}")]
    ParseError(String),
}

