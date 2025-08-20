extern crate biscuit_auth as biscuit;

use biscuit::macros::biscuit;
use biscuit::BiscuitBuilder;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, TokenTimeConfig};
use std::error::Error;

fn create_base_identity_biscuit_builder_with_time(
    subject: String,
    time_config: TokenTimeConfig,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;

    let biscuit_builder = biscuit!(
        r#"
            subject({subject});
            check if actor($a), $a == {subject} || $a.starts_with({subject} + ":");
            check if time($time), $time < {expiration};
        "#
    );

    Ok(biscuit_builder)
}

pub fn create_raw_identity_biscuit(
    subject: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    let biscuit_builder = create_base_identity_biscuit_builder_with_time(subject, time_config)?;
    let biscuit = biscuit_builder.build(&key)?;
    Ok(biscuit)
}

pub fn create_identity_biscuit(
    subject: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit = create_raw_identity_biscuit(subject, key, time_config)?;
    let biscuit = biscuit.to_vec()?;
    Ok(biscuit)
}

pub fn create_identity_token(
    subject: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_raw_identity_biscuit(subject, key, time_config)?;
    let token = biscuit.to_base64()?;
    Ok(token)
}
