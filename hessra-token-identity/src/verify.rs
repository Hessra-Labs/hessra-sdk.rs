extern crate biscuit_auth as biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

/// Verifies the token as a bearer token. This validates the expiration and the signature of the token, but does not check the identity.
pub fn verify_bearer_token(token: String, public_key: PublicKey) -> Result<(), TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key).map_err(TokenError::biscuit_error)?;
    let now = Utc::now().timestamp();

    let authz = authorizer!(
        r#"
            time({now});
            actor($a) <- subject($a);
            
            // Allow if all checks pass
            allow if true;
        "#
    );

    let mut authz = authz
        .build(&biscuit)
        .map_err(|e| TokenError::identity_error(format!("Failed to build authorizer: {e}")))?;

    match authz.authorize() {
        Ok(_) => Ok(()),
        Err(e) => Err(TokenError::identity_error(format!(
            "Identity verification failed: {e}"
        ))),
    }
}

/// Verifies the token as an identity token. This validates the expiration, the signature of the token, and the identity of the token.
pub fn verify_identity_token(
    token: String,
    public_key: PublicKey,
    identity: String,
) -> Result<(), TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key).map_err(TokenError::biscuit_error)?;
    let now = Utc::now().timestamp();

    let authz = authorizer!(
        r#"
            time({now});
            actor({identity});
            
            // Allow if all checks pass
            allow if true;
        "#
    );

    let mut authz = authz
        .build(&biscuit)
        .map_err(|e| TokenError::identity_error(format!("Failed to build authorizer: {e}")))?;

    match authz.authorize() {
        Ok(_) => Ok(()),
        Err(e) => Err(TokenError::identity_error(format!(
            "Identity verification failed: {e}"
        ))),
    }
}
