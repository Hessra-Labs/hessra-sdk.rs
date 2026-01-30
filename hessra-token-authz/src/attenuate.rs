extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use hessra_token_core::{utils, Biscuit, KeyPair, PublicKey, TokenError};

/// Add a prefix restriction to a token
///
/// This function adds a third-party block to a token that attenuates
/// the token to restrict it to the specified prefix. A prefix might
/// be a URI prefix or file path prefix.
///
/// In order to avoid confused deputy attacks, the resource should be
/// as specific as possible. For cases where the source of truth for
/// certain specifiers for the resource is not the same as the source
/// minting the base token, the ability to add a prefix restriction
/// can be used by the source of truth to restrict the token to the
/// unique authorized resource.
///
/// # Arguments
///
/// * `token` - The binary token data
/// * `public_key` - The public key to verify the token
/// * `prefix` - The prefix identifier (e.g. "tenant/TENANTID/user/USERID/")
/// * `prefix_key` - The key pair of the prefix
///
/// # Returns
///
/// The attenuated token binary data
pub fn add_prefix_restriction(
    token: Vec<u8>,
    public_key: PublicKey,
    prefix: String,
    prefix_key: KeyPair,
) -> Result<Vec<u8>, TokenError> {
    // Note that this deserializes a token and validates the signature using the root public key
    // so this effectively validates that the base token was created and signed by the root key
    let biscuit = Biscuit::from(&token, public_key)?;

    let third_party_request = biscuit.third_party_request()?;

    let third_party_block = block!(
        r#"
            check if prefix({prefix});
            prefix_added(true);
        "#
    );

    let third_party_block =
        third_party_request.create_block(&prefix_key.private(), third_party_block)?;

    let attested_biscuit = biscuit.append_third_party(prefix_key.public(), third_party_block)?;

    let attested_token = attested_biscuit.to_vec()?;

    Ok(attested_token)
}

/// Add a prefix restriction to a base64-encoded token string
///
/// This function is a convenience wrapper around `add_prefix_restriction` that
/// works with base64-encoded token strings instead of binary token data. It decodes
/// the input token, adds the prefix restriction, and returns the result as a
/// base64-encoded string.
///
/// # Arguments
///
/// * `token` - The base64-encoded token string
/// * `public_key` - The public key to verify the token
/// * `prefix` - The prefix identifier (e.g. "tenant/TENANTID/user/USERID/")
/// * `prefix_key` - The key pair of the prefix
///
/// # Returns
///
/// * `Ok(String)` - The attested token as a base64-encoded string if successful
/// * `Err(TokenError)` - If token decoding, attestation, or encoding fails
///
pub fn add_prefix_restriction_to_token(
    token: String,
    public_key: PublicKey,
    prefix: String,
    prefix_key: KeyPair,
) -> Result<String, TokenError> {
    let biscuit = utils::decode_token(&token)?;
    let biscuit = add_prefix_restriction(biscuit, public_key, prefix, prefix_key)?;
    let attested_token = utils::encode_token(&biscuit);
    Ok(attested_token)
}
