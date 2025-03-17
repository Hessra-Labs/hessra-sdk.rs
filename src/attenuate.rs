extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use biscuit::{Biscuit, PublicKey};
use std::error::Error;

pub fn add_service_node_attenuation(
    token: Vec<u8>,
    public_key: PublicKey,
    service: &str,
    node_name: &str,
    node_key: &PublicKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit = Biscuit::from(&token, public_key)?;
    let third_party_request = biscuit.third_party_request()?;
    let third_party_block = block!(
        r#"
            service({service});
        "#
    );
    let third_party_block =
        third_party_request.create_block(&node_key.private(), third_party_block)?;
    let attenuated_biscuit = biscuit.append_third_party(node_key.public(), third_party_block)?;
    let attenuated_token = attenuated_biscuit.to_vec()?;

    Ok(attenuated_token)
}
