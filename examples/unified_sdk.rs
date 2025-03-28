use hessra_sdk::{Hessra, Protocol, SdkError, ServiceChain, ServiceNode};
use std::error::Error;

/// This example demonstrates how to use the unified Hessra SDK
/// to perform token operations using the high-level API.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load the demo certificates
    let mtls_key = include_str!("../certs/client.key");
    let mtls_cert = include_str!("../certs/client.crt");
    let server_ca = include_str!("../certs/ca.crt");

    // Create a Hessra SDK instance using the builder pattern
    println!("Creating Hessra SDK instance...");
    let hessra = Hessra::builder()
        .base_url("api.hessra.com")
        .port(443)
        .mtls_key(mtls_key)
        .mtls_cert(mtls_cert)
        .server_ca(server_ca)
        .protocol(Protocol::Http1)
        .build()?;

    // Request a token for a resource
    println!("Requesting token for resource...");
    let token = match hessra.request_token("my-resource").await {
        Ok(token) => {
            println!("✅ Token received successfully");
            token
        }
        Err(e) => {
            println!("❌ Token request failed: {}", e);
            // For demo purposes, use a mock token
            println!("Using mock token for demonstration");
            "mock.token.data".to_string()
        }
    };

    // Verify the token remotely
    println!("\nVerifying token remotely...");
    match hessra.verify_token(&token, "user123", "my-resource").await {
        Ok(result) => println!("✅ Token verified remotely: {}", result),
        Err(e) => println!("❌ Remote verification failed: {}", e),
    }

    // Define a service chain for attestation
    let service_chain = ServiceChain::builder()
        .add_node(ServiceNode::new("auth-service", "ed25519/123456"))
        .add_node(ServiceNode::new("payment-service", "ed25519/abcdef"))
        .add_node(ServiceNode::new("order-service", "ed25519/fedcba"))
        .build();

    // Verify a service chain token
    println!("\nVerifying service chain token...");
    match hessra
        .verify_service_chain_token(
            &token,
            "user123",
            "my-resource",
            Some("payment-service".to_string()),
        )
        .await
    {
        Ok(result) => println!("✅ Service chain token verified: {}", result),
        Err(e) => println!("❌ Service chain verification failed: {}", e),
    }

    // Get the public key for local verification
    println!("\nFetching public key for local verification...");
    match hessra.get_public_key().await {
        Ok(key) => println!(
            "✅ Public key retrieved successfully (length: {})",
            key.len()
        ),
        Err(e) => println!("❌ Public key retrieval failed: {}", e),
    }

    // Demonstrating error handling with SdkError
    println!("\nDemonstrating error handling with SdkError:");
    let config_error: SdkError =
        hessra_sdk::ConfigError::InvalidUrl("invalid url".to_string()).into();
    println!("Config error: {}", config_error);

    // In a real application, you would also:
    // 1. Perform local token verification with cached public keys
    // 2. Attenuate tokens with service node information
    // 3. Save and load service chains from configuration

    println!("\nSDK example completed successfully.");
    Ok(())
}
