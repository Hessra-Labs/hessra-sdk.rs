extern crate biscuit_auth as biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

fn build_base_identity_authorizer(
    identity: String,
) -> Result<biscuit::AuthorizerBuilder, TokenError> {
    let now = Utc::now().timestamp();

    let authz = authorizer!(
        r#"
            time({now});
            actor({identity});
        "#
    );
    Ok(authz)
}

pub fn verify_identity_token(
    token: String,
    public_key: PublicKey,
    identity: String,
) -> Result<(), TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key).map_err(TokenError::biscuit_error)?;
    let authz = build_base_identity_authorizer(identity)?;
    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err(TokenError::identity_error("Identity does not match token"))
    }
}
