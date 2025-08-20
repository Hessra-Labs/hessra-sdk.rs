use std::error::Error as StdError;
use thiserror::Error;

/// Error type for hessra-token operations
#[derive(Error, Debug)]
pub enum TokenError {
    /// Error occurred during Biscuit token operations
    #[error("Biscuit token error: {0}")]
    BiscuitError(String),

    /// Error occurred during token verification
    #[error("Token verification error: {0}")]
    VerificationError(String),

    /// Invalid key format provided
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Token authorization failed
    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    /// Identity verification or delegation error
    #[error("Identity error: {0}")]
    IdentityError(String),

    /// Generic error with message
    #[error("{0}")]
    Generic(String),
}

impl TokenError {
    /// Create a new Biscuit-related error
    pub fn biscuit_error<E: StdError>(err: E) -> Self {
        TokenError::BiscuitError(err.to_string())
    }

    /// Create a new verification error
    pub fn verification_error<S: Into<String>>(msg: S) -> Self {
        TokenError::VerificationError(msg.into())
    }

    /// Create a new invalid key format error
    pub fn invalid_key_format<S: Into<String>>(msg: S) -> Self {
        TokenError::InvalidKeyFormat(msg.into())
    }

    /// Create a new authorization error
    pub fn authorization_error<S: Into<String>>(msg: S) -> Self {
        TokenError::AuthorizationError(msg.into())
    }

    /// Create a new identity error
    pub fn identity_error<S: Into<String>>(msg: S) -> Self {
        TokenError::IdentityError(msg.into())
    }

    /// Create a new generic error
    pub fn generic<S: Into<String>>(msg: S) -> Self {
        TokenError::Generic(msg.into())
    }
}

impl From<biscuit_auth::error::Token> for TokenError {
    fn from(err: biscuit_auth::error::Token) -> Self {
        TokenError::BiscuitError(err.to_string())
    }
}

impl From<hex::FromHexError> for TokenError {
    fn from(err: hex::FromHexError) -> Self {
        TokenError::InvalidKeyFormat(err.to_string())
    }
}

impl From<&str> for TokenError {
    fn from(err: &str) -> Self {
        TokenError::Generic(err.to_string())
    }
}

impl From<String> for TokenError {
    fn from(err: String) -> Self {
        TokenError::Generic(err)
    }
}
