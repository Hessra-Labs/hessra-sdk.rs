//! Example demonstrating identity token functionality
//!
//! This example shows how to:
//! 1. Request an identity token using mTLS authentication
//! 2. Verify the identity token locally
//! 3. Attenuate the token by delegating to a new identity
//! 4. Refresh an identity token

use hessra_sdk::{Hessra, IdentityTokenResponse, Protocol};
use std::error::Error;

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create the SDK instance
    let mut sdk = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(MTLS_CERT)
        .mtls_key(MTLS_KEY)
        .server_ca(SERVER_CA)
        .build()?;

    // Setup the SDK by fetching the public key
    sdk.setup().await?;
    println!("SDK setup complete - public key fetched");

    // 1. Request an identity token (requires mTLS authentication)
    println!("\n=== Requesting Identity Token ===");
    let identity_response = sdk.request_identity_token(None).await?;

    match &identity_response {
        IdentityTokenResponse {
            token: Some(token),
            expires_in: Some(expires),
            identity: Some(id),
            ..
        } => {
            println!("Identity token received!");
            println!("  Identity: {}", id);
            println!("  Expires in: {} seconds", expires);
            println!("  Token (truncated): {}...", &token[..50.min(token.len())]);

            // 2. Verify the identity token locally
            println!("\n=== Verifying Identity Token Locally ===");
            sdk.verify_identity_token_local(token, id)?;
            println!("Identity token verified successfully!");

            // 3. Attenuate the token by delegating to a new identity
            println!("\n=== Attenuating Identity Token ===");
            let delegated_identity = format!("{}:agent1", id); // Note: using colon separator for agent1
            let attenuated_token = sdk.attenuate_identity_token(
                token,
                &delegated_identity,
                1800, // 30 minutes
            )?;
            println!("Token attenuated to delegate to: {}", delegated_identity);
            println!(
                "  Attenuated token (truncated): {}...",
                &attenuated_token[..50.min(attenuated_token.len())]
            );

            // Verify the attenuated token
            sdk.verify_identity_token_local(&attenuated_token, &delegated_identity)?;
            println!("Attenuated token verified successfully!");

            // 3a. Use the delegated identity token to request an authorization token as agent1
            println!("\n=== Using Delegated Identity Token for Authorization ===");
            println!(
                "Acting as agent1 with delegated identity: {}",
                delegated_identity
            );

            // First, let's try to refresh using the delegated token (this should fail)
            println!("\nVerifying agent1 cannot refresh delegated tokens:");
            match sdk
                .refresh_identity_token(&attenuated_token, Some(delegated_identity.clone()))
                .await
            {
                Ok(_) => println!("✗ Warning: Delegated token refresh should have failed!"),
                Err(e) => println!("✓ Expected: Cannot refresh delegated tokens: {}", e),
            }

            // Now demonstrate what agent1 can access using the delegated identity token
            // Agent1 is configured with only read access to resource4
            println!("\n=== Demonstrating Agent1 Permissions ===");
            println!("Agent1 ({}) is configured with:", delegated_identity);
            println!("  - resource4: read (only)");

            println!("\nAttempting to request authorization token for resource4:write using agent1's token but with the root identity certificate:");
            match sdk
                .request_token_with_identity("resource4", "write", &attenuated_token)
                .await
            {
                Ok(response) => {
                    if response.token.is_some() {
                        println!("✗ Unexpected: Agent1 should NOT have write access to resource4");
                    } else {
                        println!("✓ Correctly denied: {}", response.response_msg);
                    }
                }
                Err(e) => {
                    // The current implementation correctly prevents identity mismatch
                    // When using a delegated identity token with mTLS, the certificate must match
                    if e.to_string().contains("Identity mismatch") {
                        println!("✓ Correctly prevented identity mismatch attack");
                        println!("  The server detected that the mTLS certificate (argo-cli0) doesn't match");
                        println!("  the delegated identity token (agent1), preventing privilege escalation");
                    } else {
                        println!("✓ Expected denial for write operation: {}", e);
                    }
                }
            }

            // use a new instance of the sdk using plain TLS and only the agent1 identity token for authentication
            let sdk2 = Hessra::builder()
                .base_url(BASE_URL)
                .port(PORT)
                .protocol(Protocol::Http1)
                .server_ca(SERVER_CA)
                .build()?;

            println!("\nAttempting to request authorization token for resource4:read as agent1:");
            println!("  (Identity token sent via Authorization: Bearer <token> header)");
            match sdk2
                .request_token_with_identity("resource4", "read", &attenuated_token)
                .await
            {
                Ok(response) => {
                    if let Some(auth_token) = response.token {
                        println!("✓ Successfully got authorization token for resource4:read");
                        println!(
                            "  Token (truncated): {}...",
                            &auth_token[..50.min(auth_token.len())]
                        );
                    } else {
                        println!("✗ Failed to get token: {}", response.response_msg);
                    }
                }
                Err(e) => {
                    println!("✗ Error requesting token with identity: {}", e);
                }
            }

            // Compare with using mTLS authentication (original identity)
            println!("\n=== Comparing with mTLS Authentication ===");
            println!(
                "Using original mTLS certificate ({}), not the delegated identity:",
                id
            );

            println!("\nAttempting to request authorization token for resource4:write with mTLS:");
            match sdk.request_token("resource4", "write").await {
                Ok(response) => {
                    if let Some(_auth_token) = response.token {
                        println!("✓ Successfully got write access with original identity (has full permissions)");
                    } else {
                        println!("✗ Failed to get token: {}", response.response_msg);
                    }
                }
                Err(e) => {
                    println!("✗ Error: {}", e);
                }
            }

            // Demonstrate the delegation chain
            println!("\n=== Identity Delegation Chain ===");
            println!("1. Original identity: {}", id);
            println!("2. Delegated to: {}:agent1", id);
            println!("3. Agent1 can only access what's configured in clients.toml:");
            println!("   - resource4: read only");
            println!("\nThis demonstrates defense in depth:");
            println!("- Identity tokens prove WHO you are");
            println!("- Authorization tokens prove WHAT you can do");
            println!("- Delegated identities inherit restrictions from configuration");

            // 4. Refresh the original identity token
            println!("\n=== Refreshing Identity Token ===");
            let refresh_response = sdk.refresh_identity_token(token, None).await?;

            match refresh_response {
                IdentityTokenResponse {
                    token: Some(new_token),
                    expires_in: Some(new_expires),
                    ..
                } => {
                    println!("Identity token refreshed!");
                    println!("  New expiration: {} seconds", new_expires);
                    println!(
                        "  New token (truncated): {}...",
                        &new_token[..50.min(new_token.len())]
                    );
                }
                _ => println!("Failed to refresh token: {}", refresh_response.response_msg),
            }

            // Note: Trying to refresh an attenuated token should fail
            println!("\n=== Attempting to Refresh Attenuated Token ===");
            match sdk.refresh_identity_token(&attenuated_token, None).await {
                Ok(_) => println!("Warning: Attenuated token refresh should have failed!"),
                Err(e) => println!("Expected failure - cannot refresh attenuated tokens: {}", e),
            }
        }
        _ => {
            println!(
                "Failed to get identity token: {}",
                identity_response.response_msg
            );
        }
    }

    println!("\n=== Identity Token Example Complete ===");
    Ok(())
}
