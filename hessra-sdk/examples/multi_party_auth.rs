//! # Multi-Party Authorization Integration Test
//!
//! This integration test demonstrates multi-party authorization where a token
//! is issued by the primary authorization service and then signed by additional
//! authorization services before being verified.
//!
//! ## Test Scenario
//!
//! 1. Request token for "update_telemetry" resource with "update" operation
//! 2. Collect signoffs from multi-party signers (same auth service in this test)
//! 3. Verify the final token authorizes the operation
//!
//! ## Usage
//!
//! Run this test against a local authorization server with:
//! ```bash
//! cargo run --example multi_party_auth
//! ```

use hessra_sdk::{fetch_public_key, Hessra, Protocol};

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Multi-Party Authorization Integration Test");
    println!("==========================================");

    // Test scenario: Client "URI:urn:test:argo-cli0" requests token for "update_telemetry" with "update" operation
    println!("Testing multi-party authorization flow...");

    let client = create_test_client().await?;

    let resource = "update_telemetry";
    let operation = "update";

    println!(
        "Requesting token for resource '{}' with operation '{}'",
        resource, operation
    );

    // Step 1: Request initial token
    let token_response = client.request_token(resource, operation).await?;
    println!("Initial token request successful");

    if let Some(pending_signoffs) = &token_response.pending_signoffs {
        println!(
            "Token requires {} additional signoffs",
            pending_signoffs.len()
        );
        println!("Signoffs: {:?}", pending_signoffs);

        // Step 2: Collect signoffs
        let fully_signed_token = client
            .collect_signoffs(token_response, resource, operation)
            .await?;
        println!("All signoffs collected successfully");

        // Step 3: Verify the token authorizes the operation
        println!("Verifying final token...");
        let subject = "uri:urn:test:argo-cli0";
        match client
            .verify_token(&fully_signed_token, subject, resource, operation)
            .await
        {
            Ok(()) => println!("Token verification successful - token authorizes the operation"),
            Err(e) => return Err(format!("Token verification failed: {}", e).into()),
        }

        println!("Multi-party authorization test completed successfully");
        println!(
            "Final token length: {} characters",
            fully_signed_token.len()
        );
    } else if let Some(token) = &token_response.token {
        println!("Token issued without pending signoffs");
        println!("Single-party authorization completed");

        // Verify the single-party token
        println!("Verifying single-party token...");
        let subject = "URI:urn:test:argo-cli0";
        match client
            .verify_token(token, subject, resource, operation)
            .await
        {
            Ok(()) => println!("Token verification successful - token authorizes the operation"),
            Err(e) => return Err(format!("Token verification failed: {}", e).into()),
        }

        println!("Token length: {} characters", token.len());
    } else {
        return Err("No token received in response".into());
    }

    Ok(())
}

/// Create a Hessra client using test certificates
async fn create_test_client() -> Result<Hessra, Box<dyn std::error::Error>> {
    // Fetch the public key first for local verification
    let public_key = fetch_public_key(BASE_URL, Some(PORT), SERVER_CA).await?;

    let client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(MTLS_CERT)
        .mtls_key(MTLS_KEY)
        .server_ca(SERVER_CA)
        .public_key(public_key)
        .build()?;

    Ok(client)
}
