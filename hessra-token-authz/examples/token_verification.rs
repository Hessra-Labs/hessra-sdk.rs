use biscuit_auth::macros::biscuit;
use hessra_token_authz::{
    add_service_node_attestation, biscuit_key_from_string, verify_service_chain_token_local,
    verify_token_local, ServiceNode,
};
use hessra_token_core::{decode_token, encode_token, KeyPair, TokenError};
use std::sync::Arc;
fn main() -> Result<(), TokenError> {
    // Generate an example token
    let root_keypair = Arc::new(KeyPair::new());
    let token_base64 = generate_example_token(root_keypair.clone())?;
    println!("Generated token: {}\n", token_base64);

    // Example 1: Basic verification
    println!("Example 1: Basic verification");
    verify_token_local(
        &token_base64,
        root_keypair.public(),
        "alice",
        "resource1",
        "read",
    )?;
    println!("✅ Basic verification successful\n");

    // Example 2: Service chain verification
    println!("Example 2: Service chain verification");

    // Create service node keypairs
    let service1_keypair = KeyPair::new();
    let service1_pk_hex = hex::encode(service1_keypair.public().to_bytes());
    let service1_public_key = format!("ed25519/{}", service1_pk_hex);

    let service2_keypair = KeyPair::new();
    let service2_pk_hex = hex::encode(service2_keypair.public().to_bytes());
    let service2_public_key = format!("ed25519/{}", service2_pk_hex);

    // Define service nodes
    let service_nodes = vec![
        ServiceNode {
            component: "node1".to_string(),
            public_key: service1_public_key.clone(),
        },
        ServiceNode {
            component: "node2".to_string(),
            public_key: service2_public_key.clone(),
        },
    ];

    // Generate a token with service chain
    let chain_token = generate_service_chain_token(
        root_keypair.clone(),
        service1_public_key,
        service2_public_key,
    )?;

    // attest the token for node1
    let attested_token = add_service_node_attestation(
        decode_token(&chain_token)?,
        root_keypair.public(),
        "resource1",
        &service1_keypair,
    )?;

    // attest the token for node2
    let attested_token2 = add_service_node_attestation(
        attested_token,
        root_keypair.public(),
        "resource1",
        &service2_keypair,
    )?;

    // Verify with service chain
    verify_service_chain_token_local(
        &encode_token(&attested_token2),
        root_keypair.public(),
        "alice",
        "resource1",
        "read",
        service_nodes,
        None,
    )?;
    println!("✅ Service chain verification successful\n");

    // Example 3: Verification with key from string
    println!("Example 3: Verification with key from string");

    // Convert public key to string format and back
    let pk_hex = hex::encode(root_keypair.public().to_bytes());
    let pk_str = format!("ed25519/{}", pk_hex);
    let parsed_pk = biscuit_key_from_string(pk_str)?;

    // Verify with parsed key
    verify_token_local(&token_base64, parsed_pk, "alice", "resource1", "read")?;
    println!("✅ Verification with key from string successful");

    Ok(())
}

/// Generate an example token for testing
fn generate_example_token(keypair: Arc<KeyPair>) -> Result<String, TokenError> {
    // Create a simple test biscuit with authorization rules
    let biscuit_builder = biscuit!(
        r#"
            // Grant rights to alice for resource1
            right("alice", "resource1", "read");
            right("alice", "resource1", "write");
        "#
    );

    // Build and serialize the token
    let biscuit = biscuit_builder
        .build(&keypair)
        .map_err(TokenError::biscuit_error)?;

    let token_bytes = biscuit.to_vec().map_err(TokenError::biscuit_error)?;

    // Encode to base64 for transmission
    Ok(encode_token(&token_bytes))
}

/// Generate a token with service chain attestations
fn generate_service_chain_token(
    root_keypair: Arc<KeyPair>,
    service1_public_key: String,
    service2_public_key: String,
) -> Result<String, TokenError> {
    // Create a biscuit with service chain authorization
    let biscuit_builder = biscuit!(
        r#"
            // Basic rights
            right("alice", "resource1", "read");
            right("alice", "resource1", "write");
            
            // Service nodes
            node($s, "node1") <- service($s) trusting authority, {node1_public_key};
            node($s, "node2") <- service($s) trusting authority, {node2_public_key};
        "#,
        node1_public_key = biscuit_key_from_string(service1_public_key)?,
        node2_public_key = biscuit_key_from_string(service2_public_key)?,
    );

    // Build and serialize the token
    let biscuit = biscuit_builder
        .build(&root_keypair)
        .map_err(TokenError::biscuit_error)?;

    let token_bytes = biscuit.to_vec().map_err(TokenError::biscuit_error)?;

    // Encode to base64
    Ok(encode_token(&token_bytes))
}
