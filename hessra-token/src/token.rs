use biscuit_auth::{Biscuit, PublicKey};

use crate::error::TokenError;
use crate::utils::{decode_token, encode_token};
use crate::verify::{verify_biscuit_local, verify_service_chain_biscuit_local, ServiceNode};

/// Verify a base64-encoded token string
///
/// This is a convenience function that decodes the token string and calls verify_biscuit_local
///
/// # Arguments
///
/// * `token_string` - Base64 encoded token string
/// * `public_key` - The public key used to verify the token signature
/// * `subject` - The subject (user) identifier to verify authorization for
/// * `resource` - The resource identifier to verify authorization against
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource
/// * `Err(TokenError)` - If verification fails for any reason
pub fn verify_token(
    token_string: &str,
    public_key: PublicKey,
    subject: &str,
    resource: &str,
) -> Result<(), TokenError> {
    let token_bytes = decode_token(token_string)?;
    verify_biscuit_local(
        token_bytes,
        public_key,
        subject.to_string(),
        resource.to_string(),
    )
}

/// Verify a base64-encoded token string with service chain validation
///
/// This is a convenience function that decodes the token string and calls verify_service_chain_biscuit_local
///
/// # Arguments
///
/// * `token_string` - Base64 encoded token string
/// * `public_key` - The public key used to verify the token signature
/// * `subject` - The subject (user) identifier to verify authorization for
/// * `resource` - The resource identifier to verify authorization against
/// * `service_nodes` - List of service nodes that should have attested the token
/// * `component` - Optional component to verify up to in the service chain
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource
/// * `Err(TokenError)` - If verification fails for any reason
pub fn verify_service_chain_token(
    token_string: &str,
    public_key: PublicKey,
    subject: &str,
    resource: &str,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
) -> Result<(), TokenError> {
    let token_bytes = decode_token(token_string)?;
    verify_service_chain_biscuit_local(
        token_bytes,
        public_key,
        subject.to_string(),
        resource.to_string(),
        service_nodes,
        component,
    )
}

/// Extracts and parses a Biscuit token from a base64 string
///
/// This is useful when you need to inspect the token contents directly
///
/// # Arguments
///
/// * `token_string` - Base64 encoded token string
/// * `public_key` - The public key used to verify the token signature
///
/// # Returns
///
/// The parsed Biscuit token or an error
pub fn parse_token(token_string: &str, public_key: PublicKey) -> Result<Biscuit, TokenError> {
    let token_bytes = decode_token(token_string)?;
    Biscuit::from(&token_bytes, public_key).map_err(|e| e.into())
}
