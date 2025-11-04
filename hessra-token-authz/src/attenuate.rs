extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig};

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
/// 3. The activated token expires before both the latent token and activation time limits
///
/// ## Time Attenuation
///
/// The activated token can have a shorter expiration than the original latent token. The latent token
/// might be valid for 30 minutes, but each activation can be restricted to a shorter timeframe (e.g., 5 minutes)
/// for additional security. The activated token will be valid until the earliest of:
/// - The latent token's expiration (from authority block)
/// - The activation's expiration (from activation block)
///
/// A single latent token can be activated multiple times with different combinations of subject,
/// resource, operation, and expiration times, as long as the (resource, operation) pair is in the latent_rights set.
///
/// # Arguments
///
/// * `token` - The binary latent token data
/// * `public_key` - The root public key to verify the token
/// * `subject` - The subject (user/entity) to grant the capability to
/// * `resource` - The resource to activate (must be in latent_rights)
/// * `operation` - The operation to activate (must be in latent_rights with resource)
/// * `activator_key` - The keypair of the activator (must match the public key bound in the token)
/// * `time_config` - Time configuration for the activated token's expiration
///
/// # Returns
///
/// The activated token binary data
///
/// # Example
///
/// ```no_run
/// use hessra_token_authz::{activate_latent_token, decode_token};
/// use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};
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
///     TokenTimeConfig::default(), // 5 minute expiration
/// ).unwrap();
/// ```
pub fn activate_latent_token(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
    activator_key: &KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, TokenError> {
    // Parse the latent token
    let biscuit = Biscuit::from(&token, public_key)?;

    // Create a third-party request for the activator to sign
    let third_party_request = biscuit.third_party_request()?;

    // Calculate expiration time for the activation
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;

    // Create the activation block with delegate, right facts, and time check
    let activation_block = block!(
        r#"
            delegate({subject});
            right({resource}, {operation});
            check if time($time), $time < {expiration};
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
/// See `activate_latent_token` for details on time attenuation and how the activated token
/// can have a shorter expiration than the latent token.
///
/// # Arguments
///
/// * `token` - The base64-encoded latent token string
/// * `public_key` - The root public key to verify the token
/// * `subject` - The subject (user/entity) to grant the capability to
/// * `resource` - The resource to activate (must be in latent_rights)
/// * `operation` - The operation to activate (must be in latent_rights with resource)
/// * `activator_key` - The keypair of the activator (must match the public key bound in the token)
/// * `time_config` - Time configuration for the activated token's expiration
///
/// # Returns
///
/// The activated token as a base64-encoded string
///
/// # Example
///
/// ```no_run
/// use hessra_token_authz::activate_latent_token_from_string;
/// use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};
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
///     TokenTimeConfig::default(), // 5 minute expiration
/// ).unwrap();
/// ```
pub fn activate_latent_token_from_string(
    token: String,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
    activator_key: &KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, TokenError> {
    let token_bytes = hessra_token_core::decode_token(&token)?;
    let activated_bytes = activate_latent_token(
        token_bytes,
        public_key,
        subject,
        resource,
        operation,
        activator_key,
        time_config,
    )?;
    let activated_token = hessra_token_core::encode_token(&activated_bytes);
    Ok(activated_token)
}
