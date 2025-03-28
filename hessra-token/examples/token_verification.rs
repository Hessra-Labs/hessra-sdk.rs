use biscuit_auth::macros::biscuit;
use hessra_token::{
    biscuit_key_from_string, encode_token, verify_service_chain_token, verify_token, KeyPair,
    PublicKey, ServiceNode, TokenError,
};

fn main() -> Result<(), TokenError> {
    // Generate an example token
    let token_base64 = generate_example_token()?;
    println!("Generated token: {}\n", token_base64);

    // Example 1: Basic verification
    println!("Example 1: Basic verification");
    let root_keypair = KeyPair::new();
    verify_token(&token_base64, root_keypair.public(), "alice", "resource1")?;
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
            component: "service1".to_string(),
            public_key: service1_public_key,
        },
        ServiceNode {
            component: "service2".to_string(),
            public_key: service2_public_key,
        },
    ];

    // Generate a token with service chain
    let chain_token = generate_service_chain_token(&service1_keypair, &service2_keypair)?;

    // Verify with service chain
    verify_service_chain_token(
        &chain_token,
        root_keypair.public(),
        "alice",
        "resource1",
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
    verify_token(&token_base64, parsed_pk, "alice", "resource1")?;
    println!("✅ Verification with key from string successful");

    Ok(())
}

/// Generate an example token for testing
fn generate_example_token() -> Result<String, TokenError> {
    // Create a test keypair (in a real application, you would use your secret key)
    let keypair = KeyPair::new();

    // Create a simple test biscuit with authorization rules
    let biscuit_builder = biscuit!(
        r#"
            // Grant rights to alice for resource1
            right("alice", "resource1", "read");
            right("alice", "resource1", "write");
            
            // Define an expiration time (24 hours from now)
            expiration({chrono::Utc::now().timestamp() + 86400});
        "#
    );

    // Build and serialize the token
    let biscuit = biscuit_builder
        .build(&keypair)
        .map_err(|e| TokenError::biscuit_error(e))?;

    let token_bytes = biscuit.to_vec().map_err(|e| TokenError::biscuit_error(e))?;

    // Encode to base64 for transmission
    Ok(encode_token(&token_bytes))
}

/// Generate a token with service chain attestations
fn generate_service_chain_token(
    service1_keypair: &KeyPair,
    service2_keypair: &KeyPair,
) -> Result<String, TokenError> {
    // Create a root keypair
    let root_keypair = KeyPair::new();

    // Create a biscuit with service chain authorization
    let biscuit_builder = biscuit!(
        r#"
            // Basic rights
            right("alice", "resource1", "read");
            right("alice", "resource1", "write");
            
            // Service chain trust
            node("resource1", "service1") trusting authority, {service1_keypair.public()};
            node("resource1", "service2") trusting authority, {service2_keypair.public()};
        "#
    );

    // Build and serialize the token
    let biscuit = biscuit_builder
        .build(&root_keypair)
        .map_err(|e| TokenError::biscuit_error(e))?;

    let token_bytes = biscuit.to_vec().map_err(|e| TokenError::biscuit_error(e))?;

    // Encode to base64
    Ok(encode_token(&token_bytes))
}
