extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use biscuit::{Biscuit, KeyPair, PublicKey};
use std::error::Error;

/// Add a service node attestation to a token
///
/// This function adds a third-party block to a token that attests
/// that the token has passed through the specified service node.
///
/// # Arguments
///
/// * `token` - The binary token data
/// * `public_key` - The public key to verify the token
/// * `service` - The service identifier
/// * `node_name` - The name of the node attesting
/// * `node_key` - The public key of the node attesting
/// * `node_private_key` - Optional private key for signing, if not provided a test key will be generated
///
/// # Returns
///
/// The attenuated token binary data
pub fn add_service_node_attenuation(
    token: Vec<u8>,
    public_key: PublicKey,
    service: &str,
    node_key: &KeyPair,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit = Biscuit::from(&token, public_key)?;

    // Create a third-party request
    let third_party_request = biscuit.third_party_request()?;
    let service_name = service.to_string();

    // Create a block for the service attestation
    let third_party_block = block!(
        r#"
            service({service_name});
        "#
    );

    // Create the third-party block and sign it
    let third_party_block =
        third_party_request.create_block(&node_key.private(), third_party_block)?;

    // Append the third-party block to the token
    let attenuated_biscuit = biscuit.append_third_party(node_key.public(), third_party_block)?;

    // Serialize the token
    let attenuated_token = attenuated_biscuit.to_vec()?;

    Ok(attenuated_token)
}
