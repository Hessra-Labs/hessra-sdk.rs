extern crate biscuit_auth as biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig};

pub fn add_identity_attenuation_to_token(
    token: String,
    identity: String,
    public_key: PublicKey,
    time_config: TokenTimeConfig,
) -> Result<String, TokenError> {
    let ephemeral_key = KeyPair::new();
    let biscuit = Biscuit::from_base64(&token, public_key).map_err(TokenError::biscuit_error)?;
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;
    let identity_block = block!(
        r#"
            check if actor($a), $a == {identity} || $a.starts_with({identity} + ":");
            check if time($time), $time < {expiration};
        "#
    );

    let third_party_request = biscuit
        .third_party_request()
        .map_err(TokenError::biscuit_error)?;

    let identity_block = third_party_request
        .create_block(&ephemeral_key.private(), identity_block)
        .map_err(TokenError::biscuit_error)?;

    let attenuated_biscuit = biscuit
        .append_third_party(ephemeral_key.public(), identity_block)
        .map_err(TokenError::biscuit_error)?;

    let token = attenuated_biscuit
        .to_base64()
        .map_err(TokenError::biscuit_error)?;
    Ok(token)
}
