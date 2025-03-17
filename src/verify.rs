extern crate biscuit_auth as biscuit;

use biscuit::macros::{authorizer, check};
use biscuit::Algorithm as Alg;
use biscuit::{AuthorizerBuilder, Biscuit, PublicKey};
use chrono::Utc;
use serde::Deserialize;
use std::error::Error;

fn build_base_authorizer(
    subject: String,
    resource: String,
) -> Result<AuthorizerBuilder, Box<dyn Error>> {
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
    Ok(authz)
}

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

    let authz = build_base_authorizer(subject, resource)?;
    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err("Authorization failed: token does not grant required access rights".into())
    }
}

/// Takes a public key encoded as a string in the format "ed25519/..." or "secp256r1/..."
/// and returns a PublicKey.
pub fn biscuit_key_from_string(key: String) -> Result<PublicKey, Box<dyn Error>> {
    // first split the string on the /
    let parts = key.split('/').collect::<Vec<&str>>();
    // match the algorithm
    let alg = match parts[0] {
        "ed25519" => Alg::Ed25519,
        "secp256r1" => Alg::Secp256r1,
        _ => return Err("Invalid key format".into()),
    };
    // decode the key from hex
    let key = hex::decode(parts[1]).unwrap();
    // construct the public key based on the algorithm
    let key = PublicKey::from_bytes(&key, alg)?;
    Ok(key)
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceNode {
    pub component: String,
    pub public_key: String,
}

pub fn verify_service_chain_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
    service_nodes: Vec<ServiceNode>,
) -> Result<(), Box<dyn Error>> {
    let biscuit = Biscuit::from(&token, public_key)?;

    let mut authz = build_base_authorizer(subject, resource.clone())?;
    for service_node in service_nodes {
        let service = resource.clone();
        let node_name = service_node.component;
        let node_key = biscuit_key_from_string(service_node.public_key)?;
        authz = authz.check(check!(
            r#"
                check if node({service}, {node_name}) trusting authority, {node_key};
            "#
        ))?;
    }

    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err("Authorization failed: token does not grant required access rights".into())
    }
}
