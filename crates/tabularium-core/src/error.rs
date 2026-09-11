//! Error type shared by the whole engine.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("integrity violation: {0}")]
    Integrity(String),
    #[error("crypto: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
