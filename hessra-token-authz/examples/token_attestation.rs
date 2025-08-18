use biscuit_auth::macros::biscuit;
use hessra_token_authz::{add_service_node_attestation, verify_token_local};
use hessra_token_core::{decode_token, encode_token, KeyPair, TokenError};

fn main() -> Result<(), TokenError> {
    // Generate an example token
    let (token_base64, root_keypair) = generate_example_token()?;
    println!("Original token: {}\n", token_base64);

    // Create a service node keypair
    let service_keypair = KeyPair::new();

    // 1. First, we need the binary token data
    let token_bytes = decode_token(&token_base64)?;

    // 2. Add service node attestation
    println!("Adding service node attestation...");
    let attested_token = add_service_node_attestation(
        token_bytes,
        root_keypair.public(),
        "my-service",
        &service_keypair,
    )?;

    // 3. Encode back to base64
    let attested_token_base64 = encode_token(&attested_token);
    println!("Attested token: {}\n", attested_token_base64);

    // 4. Verify the attested token still works
    println!("Verifying attested token...");
    verify_token_local(
        &attested_token_base64,
        root_keypair.public(),
        "alice",
        "resource1",
        "read",
    )?;
    println!("✅ Verification successful for attested token");

    // 5. Generate a chain of attestations
    println!("\nCreating a chain of attestations...");
    let token_with_chain = create_attestation_chain(&token_base64, &root_keypair)?;
    println!("Token with attestation chain: {}", token_with_chain);

    // 6. Verify the chain token
    println!("\nVerifying token with attestation chain...");
    verify_token_local(
        &token_with_chain,
        root_keypair.public(),
        "alice",
        "resource1",
        "read",
    )?;
    println!("✅ Verification successful for token with attestation chain");

    Ok(())
}

/// Generate an example token for testing, returning both token and keypair
fn generate_example_token() -> Result<(String, KeyPair), TokenError> {
    // Create a test keypair
    let keypair = KeyPair::new();

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
    Ok((encode_token(&token_bytes), keypair))
}

/// Create a chain of service attestations
fn create_attestation_chain(
    token_base64: &str,
    root_keypair: &KeyPair,
) -> Result<String, TokenError> {
    // Decode the original token
    let mut token_bytes = decode_token(token_base64)?;

    // Create service keypairs
    let service_names = ["service-1", "service-2", "service-3"];

    // Add multiple service attestations
    for service_name in service_names.iter() {
        println!("  Adding attestation for {}", service_name);

        // Create a new keypair for this service
        let service_keypair = KeyPair::new();

        // Add an attestation
        token_bytes = add_service_node_attestation(
            token_bytes,
            root_keypair.public(),
            service_name,
            &service_keypair,
        )?;
    }

    // Encode the final token
    Ok(encode_token(&token_bytes))
}
