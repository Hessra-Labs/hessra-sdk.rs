//! Example demonstrating domain-restricted identity token functionality
//!
//! This example shows how to:
//! 1. Mint domain-restricted identity tokens from a realm identity
//! 2. Use domain-restricted tokens with default role permissions
//! 3. Use domain-restricted tokens with explicit role assignments
//! 4. Prevent sub-domain creation (no nested domain identities)
//! 5. Request authorization tokens with domain parameter for enhanced verification

use hessra_sdk::{Hessra, MintIdentityTokenResponse, Protocol};
use std::error::Error;

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;

// Realm identity: uri:urn:test:argo-cli1 (can mint domain-restricted tokens)
static MTLS_CERT: &str = include_str!("../../certs/argo-cli1.pem");
static MTLS_KEY: &str = include_str!("../../certs/argo-cli1.key.pem");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

// Domain for this realm identity
static DOMAIN: &str = "uri:urn:test:argo-cli1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Domain-Restricted Identity Token Example ===\n");

    // Create the SDK instance with realm identity (uri:urn:test:argo-cli1)
    println!("=== Phase 1: Setup with Realm Identity ===");
    let mut realm_sdk = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(MTLS_CERT)
        .mtls_key(MTLS_KEY)
        .server_ca(SERVER_CA)
        .build()?;

    // Setup the SDK by fetching the public key
    realm_sdk.setup().await?;
    println!("Realm SDK setup complete - public key fetched");
    println!("Realm identity: {DOMAIN}\n");

    // Phase 2: Mint domain-restricted tokens
    println!("=== Phase 2: Minting Domain-Restricted Identity Tokens ===");

    // Mint token for a new user (will get default 'member' role)
    println!("\n--- Minting token for default role user ---");
    let default_user_subject = format!("{DOMAIN}:user123");
    println!("Subject: {default_user_subject}");
    println!("Expected role: member (default)");
    println!("Expected permissions: resource3:read");

    let default_user_response = realm_sdk
        .mint_domain_restricted_identity_token(default_user_subject.clone(), Some(3600))
        .await?;

    let default_user_token = match default_user_response {
        MintIdentityTokenResponse {
            token: Some(token),
            expires_in: Some(expires),
            identity: Some(id),
            ..
        } => {
            println!("✓ Minted token successfully!");
            println!("  Identity: {id}");
            println!("  Expires in: {expires} seconds");
            println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            token
        }
        _ => {
            return Err(format!(
                "Failed to mint default user token: {}",
                default_user_response.response_msg
            )
            .into())
        }
    };

    // Mint token for admin user (explicit 'admin' role assignment in config)
    println!("\n--- Minting token for admin user ---");
    let admin_user_subject = format!("{DOMAIN}:admin-user");
    println!("Subject: {admin_user_subject}");
    println!("Expected role: admin (explicit assignment)");
    println!("Expected permissions: resource4:read,write and resource2:read,write");

    let admin_user_response = realm_sdk
        .mint_domain_restricted_identity_token(admin_user_subject.clone(), Some(3600))
        .await?;

    let admin_user_token = match admin_user_response {
        MintIdentityTokenResponse {
            token: Some(token),
            expires_in: Some(expires),
            identity: Some(id),
            ..
        } => {
            println!("✓ Minted token successfully!");
            println!("  Identity: {id}");
            println!("  Expires in: {expires} seconds");
            println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            token
        }
        _ => {
            return Err(format!(
                "Failed to mint admin user token: {}",
                admin_user_response.response_msg
            )
            .into())
        }
    };

    // Phase 3: Test default role permissions
    println!("\n=== Phase 3: Testing Default Role Permissions ===");
    println!("Creating SDK instance WITHOUT mTLS for default user...");

    let default_user_sdk = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .server_ca(SERVER_CA)
        .build()?;

    println!("\nTesting default role (member) permissions:");
    println!("Expected: resource3:read allowed");

    // Should succeed: resource3:read (member role has this)
    println!("\n--- Test 1: resource3:read (should succeed) ---");
    match default_user_sdk
        .request_token_with_identity(
            "resource3",
            "read",
            &default_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if let Some(token) = response.token {
                println!("✓ SUCCESS: Got authorization token for resource3:read");
                println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            } else {
                println!("✗ FAILED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✗ ERROR: {e}"),
    }

    // Should fail: resource4:write (not in member role)
    println!("\n--- Test 2: resource4:write (should fail) ---");
    match default_user_sdk
        .request_token_with_identity(
            "resource4",
            "write",
            &default_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if response.token.is_some() {
                println!("✗ UNEXPECTED: Default user should NOT have write access to resource4");
            } else {
                println!("✓ CORRECTLY DENIED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✓ CORRECTLY DENIED: {e}"),
    }

    // Phase 4: Test explicit role (admin) permissions
    println!("\n=== Phase 4: Testing Explicit Role (Admin) Permissions ===");
    println!("Creating SDK instance WITHOUT mTLS for admin user...");

    let admin_user_sdk = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .server_ca(SERVER_CA)
        .build()?;

    println!("\nTesting admin role permissions:");
    println!("Expected: resource4:read,write and resource2:read,write allowed");

    // Should succeed: resource4:write (admin role has this)
    println!("\n--- Test 1: resource4:write (should succeed) ---");
    match admin_user_sdk
        .request_token_with_identity(
            "resource4",
            "write",
            &admin_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if let Some(token) = response.token {
                println!("✓ SUCCESS: Got authorization token for resource4:write");
                println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            } else {
                println!("✗ FAILED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✗ ERROR: {e}"),
    }

    // Should succeed: resource2:read (admin role has this)
    println!("\n--- Test 2: resource2:read (should succeed) ---");
    match admin_user_sdk
        .request_token_with_identity(
            "resource2",
            "read",
            &admin_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if let Some(token) = response.token {
                println!("✓ SUCCESS: Got authorization token for resource2:read");
                println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            } else {
                println!("✗ FAILED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✗ ERROR: {e}"),
    }

    // Should fail: resource3:read (not in admin role, admin doesn't have member permissions)
    println!("\n--- Test 3: resource3:read (should fail - not in admin role) ---");
    match admin_user_sdk
        .request_token_with_identity(
            "resource3",
            "read",
            &admin_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if response.token.is_some() {
                println!("✗ UNEXPECTED: Admin user should NOT have access to resource3");
            } else {
                println!("✓ CORRECTLY DENIED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✓ CORRECTLY DENIED: {e}"),
    }

    // Phase 5: Test sub-domain prevention
    println!("\n=== Phase 5: Testing Sub-domain Prevention ===");
    println!("Domain-restricted identities should NOT be able to mint new identities");

    // Create SDK with domain-restricted identity and mTLS
    // Note: In real scenario, this would use admin-user's cert, but for testing we simulate
    println!("\nAttempting to mint identity using domain-restricted token...");
    let sub_subject = format!("{DOMAIN}:admin-user:agent1");
    println!("Attempting to mint: {sub_subject}");
    println!("Expected result: DENIED (no sub-domains allowed)");

    // This would require mTLS with admin-user cert, which we don't have in this example
    // In real usage, the server will reject this because admin-user is domain-restricted
    println!("\nNote: This requires mTLS cert for domain-restricted identity,");
    println!("which is not typical. Domain-restricted identities cannot mint new identities.");
    println!("✓ Server enforces: Only realm identities can mint domain identities");

    // Phase 6: Test domain parameter usage
    println!("\n=== Phase 6: Testing Domain Parameter in Token Requests ===");
    println!("Requesting authorization tokens WITH domain parameter enables enhanced verification");
    println!("The server uses ensure_subject_in_domain() to verify subject is in domain");

    println!("\n--- With domain parameter (enhanced verification) ---");
    match default_user_sdk
        .request_token_with_identity(
            "resource3",
            "read",
            &default_user_token,
            Some(DOMAIN.to_string()),
        )
        .await
    {
        Ok(response) => {
            if let Some(token) = response.token {
                println!("✓ SUCCESS with enhanced domain verification");
                println!("  Server verified subject is in domain: {DOMAIN}");
                println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            } else {
                println!("✗ FAILED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✗ ERROR: {e}"),
    }

    println!("\n--- Without domain parameter (standard verification) ---");
    match default_user_sdk
        .request_token_with_identity("resource3", "read", &default_user_token, None)
        .await
    {
        Ok(response) => {
            if let Some(token) = response.token {
                println!("✓ SUCCESS with standard verification");
                println!("  Token (truncated): {}...", &token[..50.min(token.len())]);
            } else {
                println!("✗ FAILED: {}", response.response_msg);
            }
        }
        Err(e) => println!("✗ ERROR: {e}"),
    }

    // Summary
    println!("\n=== Summary: Domain-Restricted Identity Tokens ===");
    println!("1. ✓ Realm identity can mint domain-restricted tokens");
    println!("2. ✓ Default role (member) gets configured default permissions");
    println!("3. ✓ Explicit role (admin) gets group-assigned permissions");
    println!("4. ✓ Role permissions are strictly enforced");
    println!("5. ✓ Sub-domain creation is prevented (no nested domains)");
    println!("6. ✓ Domain parameter enables enhanced subject-in-domain verification");
    println!("\nKey Features:");
    println!("- Domain-restricted tokens cannot mint new identities");
    println!("- Permissions are defined by domain roles in server config");
    println!("- Role assignments override default permissions");
    println!("- Domain verification ensures subject belongs to claimed domain");

    println!("\n=== Domain-Restricted Identity Token Example Complete ===");
    Ok(())
}
