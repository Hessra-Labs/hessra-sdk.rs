extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError};

/// Activate a latent capability token by attenuating it with a specific subject, resource, and operation.
///
/// Latent capability tokens contain broad `latent_right(resource, operation)` permissions but cannot
/// be used directly. They must be activated by the holder of the bound activator key, who adds a
/// third-party block containing `delegate(subject)` and `right(resource, operation)` facts.
///
/// The authority block's rules will derive the final `right(subject, resource, operation)` capability
/// from these facts, and the checks ensure:
/// 1. The derived right is valid
/// 2. The (resource, operation) pair exists in the original latent_rights
///
/// A single latent token can be activated multiple times with different combinations of subject,
/// resource, and operation, as long as the (resource, operation) pair is in the latent_rights set.
///
/// # Arguments
///
/// * `token` - The binary latent token data
/// * `public_key` - The root public key to verify the token
/// * `subject` - The subject (user/entity) to grant the capability to
/// * `resource` - The resource to activate (must be in latent_rights)
/// * `operation` - The operation to activate (must be in latent_rights with resource)
/// * `activator_key` - The keypair of the activator (must match the public key bound in the token)
///
/// # Returns
///
/// The activated token binary data
///
/// # Example
///
/// ```no_run
/// use hessra_token_authz::{activate_latent_token, decode_token};
/// use hessra_token_core::{KeyPair, PublicKey};
///
/// let latent_token_base64 = "..."; // base64-encoded latent token
/// let latent_token_bytes = decode_token(&latent_token_base64).unwrap();
/// let root_public_key_pem = "..."; // pem string
/// let root_public_key = PublicKey::from_pem(root_public_key_pem).unwrap();
/// let activator_keypair = KeyPair::new(); // Must be the keypair bound to the token
///
/// let activated_token = activate_latent_token(
///     latent_token_bytes,
///     root_public_key,
///     "alice".to_string(),
///     "resource1".to_string(),
///     "read".to_string(),
///     &activator_keypair,
/// ).unwrap();
/// ```
pub fn activate_latent_token(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
    activator_key: &KeyPair,
) -> Result<Vec<u8>, TokenError> {
    // Parse the latent token
    let biscuit = Biscuit::from(&token, public_key)?;

    // Create a third-party request for the activator to sign
    let third_party_request = biscuit.third_party_request()?;

    // Create the activation block with delegate and right facts
    let activation_block = block!(
        r#"
            delegate({subject});
            right({resource}, {operation});
        "#
    );

    // Sign the block with the activator's private key
    let signed_block =
        third_party_request.create_block(&activator_key.private(), activation_block)?;

    // Append the third-party block to the token
    let activated_biscuit = biscuit.append_third_party(activator_key.public(), signed_block)?;

    // Convert to binary format
    let activated_token = activated_biscuit.to_vec()?;

    Ok(activated_token)
}

/// Activate a latent capability token from a base64-encoded string.
///
/// This is a convenience wrapper around `activate_latent_token` that works with base64-encoded
/// token strings instead of binary token data. It decodes the input token, activates it, and
/// returns the result as a base64-encoded string.
///
/// # Arguments
///
/// * `token` - The base64-encoded latent token string
/// * `public_key` - The root public key to verify the token
/// * `subject` - The subject (user/entity) to grant the capability to
/// * `resource` - The resource to activate (must be in latent_rights)
/// * `operation` - The operation to activate (must be in latent_rights with resource)
/// * `activator_key` - The keypair of the activator (must match the public key bound in the token)
///
/// # Returns
///
/// The activated token as a base64-encoded string
///
/// # Example
///
/// ```no_run
/// use hessra_token_authz::activate_latent_token_from_string;
/// use hessra_token_core::{KeyPair, PublicKey};
///
/// let latent_token = "base64_encoded_latent_token".to_string();
/// let root_public_key_pem = "..."; // pem string
/// let root_public_key = PublicKey::from_pem(root_public_key_pem).unwrap();
/// let activator_keypair = KeyPair::new(); // Must be the keypair bound to the token
///
/// let activated_token = activate_latent_token_from_string(
///     latent_token,
///     root_public_key,
///     "alice".to_string(),
///     "resource1".to_string(),
///     "read".to_string(),
///     &activator_keypair,
/// ).unwrap();
/// ```
pub fn activate_latent_token_from_string(
    token: String,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
    activator_key: &KeyPair,
) -> Result<String, TokenError> {
    let token_bytes = hessra_token_core::decode_token(&token)?;
    let activated_bytes = activate_latent_token(
        token_bytes,
        public_key,
        subject,
        resource,
        operation,
        activator_key,
    )?;
    let activated_token = hessra_token_core::encode_token(&activated_bytes);
    Ok(activated_token)
}
