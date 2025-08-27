use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("SDK error: {0}")]
    Sdk(#[from] hessra_sdk::SdkError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Token error: {0}")]
    Token(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[cfg(feature = "secure-storage")]
    #[error("Keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}

pub type Result<T> = std::result::Result<T, CliError>;
