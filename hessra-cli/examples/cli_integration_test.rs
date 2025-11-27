//! Integration test for hessra CLI tool
//!
//! This example tests the CLI functionality against the live test.hessra.net service.
//! It verifies:
//! - Server initialization and configuration
//! - Authentication and identity token creation
//! - Automatic CA certificate fetching
//! - Server-specific public key and token storage
//! - Token delegation with server-aware caching
//! - Token verification
//! - Token management (list, delete)
//! - Server management commands
//! - Authorization token request (mTLS and identity token)
//! - Authorization token verification
//! - Domain-restricted identity minting
//! - Authorization with domain parameter
//! - Domain-based permission enforcement

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// Test certificates for mTLS authentication (argo-cli0 identity)
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");

// Realm identity certificates (argo-cli1 - can mint domain-restricted tokens)
static MTLS_CERT_REALM: &str = include_str!("../../certs/argo-cli1.pem");
static MTLS_KEY_REALM: &str = include_str!("../../certs/argo-cli1.key.pem");

const TEST_SERVER: &str = "test.hessra.net";
const REALM_DOMAIN: &str = "uri:urn:test:argo-cli1";

fn run_hessra_command(args: &[&str]) -> Result<(String, String, bool)> {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .args(args)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    Ok((stdout, stderr, success))
}

fn setup_test_certificates() -> Result<(PathBuf, PathBuf)> {
    let temp_dir = std::env::temp_dir().join("hessra_cli_test");
    fs::create_dir_all(&temp_dir)?;

    let cert_path = temp_dir.join("client.crt");
    let key_path = temp_dir.join("client.key");

    fs::write(&cert_path, MTLS_CERT)?;
    fs::write(&key_path, MTLS_KEY)?;

    Ok((cert_path, key_path))
}

fn setup_realm_certificates() -> Result<(PathBuf, PathBuf)> {
    let temp_dir = std::env::temp_dir().join("hessra_cli_test");
    fs::create_dir_all(&temp_dir)?;

    let cert_path = temp_dir.join("argo-cli1.pem");
    let key_path = temp_dir.join("argo-cli1.key.pem");

    fs::write(&cert_path, MTLS_CERT_REALM)?;
    fs::write(&key_path, MTLS_KEY_REALM)?;

    Ok((cert_path, key_path))
}

fn cleanup_test_tokens() -> Result<()> {
    // Clean up any test tokens from previous runs (server-specific directory)
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let server_tokens_dir = home
        .home_dir()
        .join(".hessra")
        .join("servers")
        .join(TEST_SERVER)
        .join("tokens");

    if server_tokens_dir.exists() {
        for entry in fs::read_dir(&server_tokens_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name() {
                let name = name.to_string_lossy();
                if name.starts_with("test_") && name.ends_with(".token") {
                    fs::remove_file(&path)?;
                }
            }
        }
    }

    Ok(())
}

fn verify_public_key_cached(server: &str) -> Result<bool> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    // New server-based path
    let pubkey_path = home
        .home_dir()
        .join(".hessra")
        .join("servers")
        .join(server)
        .join("public_key.pem");

    Ok(pubkey_path.exists())
}

fn verify_ca_cert_cached(server: &str) -> Result<bool> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    let ca_path = home
        .home_dir()
        .join(".hessra")
        .join("servers")
        .join(server)
        .join("ca.crt");

    Ok(ca_path.exists())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Hessra CLI Integration Test ===\n");

    // Setup
    println!("Setting up test environment...");
    let (cert_path, key_path) = setup_test_certificates()?;
    cleanup_test_tokens()?;

    // Test 0: Server initialization
    println!("\n0. Testing server initialization...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "init",
        TEST_SERVER,
        "--cert",
        cert_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--set-default",
        "--force", // Overwrite if exists
        "--json",
    ])?;

    if !success {
        eprintln!("Server initialization failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Server initialization should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    println!("✓ Server initialization successful");

    // Verify CA cert was fetched and cached
    let ca_cached = verify_ca_cert_cached(TEST_SERVER)?;
    assert!(ca_cached, "CA certificate should be cached");
    println!("✓ CA certificate fetched and cached");

    // Verify public key was fetched and cached
    let key_cached = verify_public_key_cached(TEST_SERVER)?;
    assert!(key_cached, "Public key should be cached");
    println!("✓ Public key fetched and cached");

    // Test 1: Authenticate and get identity token (no --ca needed!)
    println!("\n1. Testing authentication with auto-resolved server...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "authenticate",
        // No --server needed (uses default)
        // No --cert/--key needed (uses server config)
        // No --ca needed (auto-loaded from server directory)
        "--save-as",
        "test_main",
        "--json",
    ])?;

    if !success {
        eprintln!("Authentication failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Authentication should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    assert!(
        stdout.contains("\"server\": \"test.hessra.net\""),
        "Should show correct server"
    );
    assert!(
        stdout.contains("uri:urn:test:argo-cli0"),
        "Should have correct identity"
    );
    println!("✓ Authentication successful (all parameters auto-resolved!)");

    // Test 2: Delegate token using server-aware cached public key
    println!("\n2. Testing delegation with server-aware cached public key...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "delegate",
        "--identity",
        "uri:urn:test:argo-cli0:agent1",
        "--from-token",
        "test_main",
        "--save-as",
        "test_delegated",
        // No --server needed (uses default)
        // No --ca needed (auto-loaded from server directory)
        // No --public-key needed (auto-loaded from server directory)
        "--json",
    ])?;

    if !success {
        eprintln!("Delegation stderr: {stderr}");
        eprintln!("Delegation stdout: {stdout}");
    }
    assert!(success, "Delegation should succeed with cached key");
    assert!(
        stdout.contains("\"success\": true"),
        "Delegation should indicate success"
    );
    assert!(
        stdout.contains("\"server\": \"test.hessra.net\""),
        "Should show correct server"
    );
    assert!(
        stdout.contains("uri:urn:test:argo-cli0:agent1"),
        "Should have delegated identity"
    );
    println!("✓ Delegation successful using server-aware cached public key");

    // Test 3: Verify the delegated token
    println!("\n3. Testing token verification...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "verify",
        "--token-name",
        "test_delegated",
        "--identity",
        "uri:urn:test:argo-cli0:agent1",
        // No --server needed (uses default)
        "--json",
    ])?;

    if !success {
        eprintln!("Verification failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Verification should succeed");
    assert!(stdout.contains("\"valid\": true"), "Token should be valid");
    println!("✓ Token verification successful");

    // Test 4: List tokens (server-aware)
    println!("\n4. Testing server-aware token listing...");
    let (stdout, _stderr, success) = run_hessra_command(&["identity", "list", "--json"])?;

    assert!(success, "List should succeed");
    assert!(stdout.contains("test_main"), "Should list main token");
    assert!(
        stdout.contains("test_delegated"),
        "Should list delegated token"
    );
    println!("✓ Token listing successful");

    // Test 5: Server management - list servers
    println!("\n5. Testing server management commands...");
    let (stdout, _stderr, success) = run_hessra_command(&["config", "list", "--json"])?;

    assert!(success, "Server list should succeed");
    assert!(stdout.contains(TEST_SERVER), "Should list test.hessra.net");
    println!("✓ Server list successful");

    // Test 6: Server management - show server details
    println!("\n6. Testing server details command...");
    let (stdout, _stderr, success) =
        run_hessra_command(&["config", "show", TEST_SERVER, "--json"])?;

    assert!(success, "Server show should succeed");
    assert!(stdout.contains("\"hostname\""), "Should show hostname");
    assert!(
        stdout.contains("\"ca_cert_exists\": true"),
        "Should confirm CA cert exists"
    );
    assert!(
        stdout.contains("\"public_key_exists\": true"),
        "Should confirm public key exists"
    );
    assert!(
        stdout.contains("\"is_default\": true"),
        "Should be marked as default"
    );
    println!("✓ Server details successful");

    // Test 7: Delete delegated token
    println!("\n7. Testing token deletion...");
    let (_stdout, _stderr, success) =
        run_hessra_command(&["identity", "delete", "test_delegated", "--json"])?;

    assert!(success, "Delete should succeed");
    println!("✓ Token deletion successful");

    // Verify token was deleted from server-specific directory
    let (stdout, _stderr, success) = run_hessra_command(&["identity", "list", "--json"])?;
    assert!(success, "List should succeed");
    assert!(
        !stdout.contains("\"test_delegated\""),
        "Deleted token should not be listed"
    );
    println!("✓ Verified token removed from server-specific storage");

    // Test 8: Test CA auto-fetch on fresh server
    println!("\n8. Testing CA auto-fetch on authentication...");

    // Remove the server's CA cert to simulate fresh state
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let ca_path = home
        .home_dir()
        .join(".hessra")
        .join("servers")
        .join(TEST_SERVER)
        .join("ca.crt");

    if ca_path.exists() {
        fs::remove_file(&ca_path)?;
    }

    // Authenticate - should auto-fetch CA
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "authenticate",
        "--save-as",
        "test_auto_ca",
        "--json",
    ])?;

    if !success {
        eprintln!("Auto-fetch CA failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Authentication with auto-fetch CA should succeed");

    // Verify CA was re-fetched
    let ca_cached = verify_ca_cert_cached(TEST_SERVER)?;
    assert!(ca_cached, "CA certificate should be auto-fetched");
    println!("✓ CA certificate auto-fetch successful");

    // Test 9: Test fallback to fetching public key when removed
    println!("\n9. Testing auto-fetch public key on delegation...");

    // Remove cached public key
    let pubkey_path = home
        .home_dir()
        .join(".hessra")
        .join("servers")
        .join(TEST_SERVER)
        .join("public_key.pem");

    if pubkey_path.exists() {
        fs::remove_file(&pubkey_path)?;
    }

    // Try delegation - should auto-fetch public key using cached CA
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "delegate",
        "--identity",
        "uri:urn:test:argo-cli0:agent2",
        "--from-token",
        "test_main",
        "--save-as",
        "test_auto_pubkey",
        "--json",
    ])?;

    if !success {
        eprintln!("Auto-fetch pubkey failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Delegation with auto-fetch pubkey should succeed");

    // Verify key was re-cached
    let key_cached = verify_public_key_cached(TEST_SERVER)?;
    assert!(key_cached, "Public key should be auto-fetched");
    println!("✓ Public key auto-fetch successful");

    // ========================================
    // NEW TESTS: Authorization and Domain-Restricted Identity
    // ========================================

    // Test 10: Authorization request with mTLS
    println!("\n10. Testing authorization request with mTLS...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "authorize",
        "request",
        "--resource",
        "resource1",
        "--operation",
        "read",
        "--cert",
        cert_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--json",
    ])?;

    if !success {
        eprintln!("Authorization request (mTLS) failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Authorization request with mTLS should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    assert!(stdout.contains("\"token\":"), "Should contain auth token");
    println!("✓ Authorization request with mTLS successful");

    // Test 11: Authorization request with identity token
    println!("\n11. Testing authorization request with identity token...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "authorize",
        "request",
        "--resource",
        "resource1",
        "--operation",
        "read",
        "--identity-token",
        "test_main",
        "--json",
    ])?;

    if !success {
        eprintln!("Authorization request (identity token) failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(
        success,
        "Authorization request with identity token should succeed"
    );
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    println!("✓ Authorization request with identity token successful");

    // Extract the token for verification test
    let auth_token: serde_json::Value = serde_json::from_str(&stdout)?;
    let auth_token_str = auth_token["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No token in authorization response"))?;

    // Test 12: Authorization token verification
    println!("\n12. Testing authorization token verification...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "authorize",
        "verify",
        "--token",
        auth_token_str,
        "--subject",
        "uri:urn:test:argo-cli0",
        "--resource",
        "resource1",
        "--operation",
        "read",
        "--json",
    ])?;

    if !success {
        eprintln!("Authorization verification failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Authorization verification should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Verification should indicate success"
    );
    println!("✓ Authorization token verification successful");

    // ========================================
    // Domain-Restricted Identity Tests
    // ========================================

    // Test 13: Domain-restricted identity minting
    println!("\n13. Testing domain-restricted identity minting...");

    // First, setup realm identity (argo-cli1) as the server config
    let (realm_cert_path, realm_key_path) = setup_realm_certificates()?;

    let (stdout, stderr, success) = run_hessra_command(&[
        "init",
        TEST_SERVER,
        "--cert",
        realm_cert_path.to_str().unwrap(),
        "--key",
        realm_key_path.to_str().unwrap(),
        "--force",
        "--json",
    ])?;

    if !success {
        eprintln!("Realm identity setup failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Realm identity setup should succeed");
    println!("  Realm identity (argo-cli1) configured");

    // Now mint a domain-restricted token
    let domain_subject = format!("{REALM_DOMAIN}:user123");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "mint",
        "--subject",
        &domain_subject,
        "--ttl",
        "3600",
        "--save-as",
        "test_domain_restricted",
        "--json",
    ])?;

    if !success {
        eprintln!("Domain-restricted identity minting failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(success, "Domain-restricted identity minting should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    assert!(
        stdout.contains(&domain_subject),
        "Should contain the minted subject"
    );
    println!("✓ Domain-restricted identity token minted successfully");

    // Restore original client certificates for subsequent tests
    let (_, _, _) = run_hessra_command(&[
        "init",
        TEST_SERVER,
        "--cert",
        cert_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--force",
        "--json",
    ])?;

    // Test 14: Authorization with domain parameter
    println!("\n14. Testing authorization with domain parameter...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "authorize",
        "request",
        "--resource",
        "resource3",
        "--operation",
        "read",
        "--identity-token",
        "test_domain_restricted",
        "--domain",
        REALM_DOMAIN,
        "--json",
    ])?;

    if !success {
        eprintln!("Authorization with domain failed!");
        eprintln!("stderr: {stderr}");
        eprintln!("stdout: {stdout}");
    }

    assert!(
        success,
        "Authorization with domain parameter should succeed for allowed resource"
    );
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );
    println!("✓ Authorization with domain parameter successful");

    // Test 15: Domain permission enforcement (should fail)
    println!("\n15. Testing domain permission enforcement...");
    let (stdout, _stderr, success) = run_hessra_command(&[
        "authorize",
        "request",
        "--resource",
        "resource4",
        "--operation",
        "write",
        "--identity-token",
        "test_domain_restricted",
        "--domain",
        REALM_DOMAIN,
        "--json",
    ])?;

    // This should fail - member role doesn't have resource4:write
    assert!(
        !success || stdout.contains("\"success\": false"),
        "Authorization should fail for unauthorized resource"
    );
    println!("✓ Domain permission enforcement working (correctly denied resource4:write)");

    // Cleanup
    println!("\n16. Cleaning up test artifacts...");
    cleanup_test_tokens()?;
    fs::remove_dir_all(cert_path.parent().unwrap())?;
    println!("✓ Cleanup complete");

    println!("\n=== All tests passed! ===");
    println!("\nKey improvements demonstrated:");
    println!("  ✓ Server-aware storage (tokens and keys isolated per server)");
    println!("  ✓ Automatic CA certificate fetching");
    println!("  ✓ Automatic public key fetching");
    println!("  ✓ Server config auto-resolution (no repetitive parameters)");
    println!("  ✓ Default server support (minimal command arguments)");
    println!("  ✓ Server management commands (list, show, switch)");
    println!("  ✓ Authorization token request with mTLS and identity token");
    println!("  ✓ Authorization token verification");
    println!("  ✓ Domain-restricted identity minting");
    println!("  ✓ Authorization with domain parameter");
    println!("  ✓ Domain-based permission enforcement");

    Ok(())
}
