extern crate biscuit_auth as biscuit;

use biscuit::macros::authorizer;
use biscuit::{Biscuit, PublicKey};

use chrono::Utc;
use std::error::Error;

/// Verifies a Biscuit authorization token locally without contacting the authorization server.
///
/// This function performs local verification of a Biscuit token using the provided public key.
/// It validates that the token grants access to the specified resource for the given subject.
///
/// # Arguments
///
/// * `token` - The binary Biscuit token bytes (typically decoded from Base64)
/// * `public_key` - The public key used to verify the token signature
/// * `subject` - The subject (user) identifier to verify authorization for
/// * `resource` - The resource identifier to verify authorization against
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource
/// * `Err(Box<dyn Error>)` - If verification fails for any reason
///
/// # Errors
///
/// Returns an error if:
/// - The token is malformed or cannot be parsed
/// - The token signature is invalid
/// - The token does not grant the required access rights
/// - The token has expired or other authorization checks fail
pub fn verify_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
) -> Result<(), Box<dyn Error>> {
    let biscuit = Biscuit::from(&token, public_key)?;
    let now = Utc::now().timestamp();

    let authz = authorizer!(
        r#"
     time({now});
     resource({resource});
     subject({subject});
     operation("read");
     operation("write");
     allow if subject($sub), resource($res), operation($op), right($sub, $res, $op);
  "#
    );
    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err("Authorization failed: token does not grant required access rights".into())
    }
}
