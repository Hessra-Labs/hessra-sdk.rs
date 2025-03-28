use base64::{engine::general_purpose::STANDARD, Engine};

use crate::error::TokenError;

/// Encode binary token data to base64 string
///
/// # Arguments
///
/// * `token_bytes` - Binary token data
///
/// # Returns
///
/// Base64 encoded token string
pub fn encode_token(token_bytes: &[u8]) -> String {
    STANDARD.encode(token_bytes)
}

/// Decode a base64 encoded token string to binary
///
/// # Arguments
///
/// * `token_string` - Base64 encoded token string
///
/// # Returns
///
/// Binary token data or TokenError if decoding fails
pub fn decode_token(token_string: &str) -> Result<Vec<u8>, TokenError> {
    STANDARD
        .decode(token_string)
        .map_err(|e| TokenError::generic(format!("Failed to decode base64 token: {}", e)))
}
