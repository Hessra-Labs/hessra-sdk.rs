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

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// Test certificates for mTLS authentication
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");

const TEST_SERVER: &str = "test.hessra.net";

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
        eprintln!("stderr: {}", stderr);
        eprintln!("stdout: {}", stdout);
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
        eprintln!("stderr: {}", stderr);
        eprintln!("stdout: {}", stdout);
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
        eprintln!("Delegation stderr: {}", stderr);
        eprintln!("Delegation stdout: {}", stdout);
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
        eprintln!("stderr: {}", stderr);
        eprintln!("stdout: {}", stdout);
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
        eprintln!("stderr: {}", stderr);
        eprintln!("stdout: {}", stdout);
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
        eprintln!("stderr: {}", stderr);
        eprintln!("stdout: {}", stdout);
    }

    assert!(success, "Delegation with auto-fetch pubkey should succeed");

    // Verify key was re-cached
    let key_cached = verify_public_key_cached(TEST_SERVER)?;
    assert!(key_cached, "Public key should be auto-fetched");
    println!("✓ Public key auto-fetch successful");

    // Cleanup
    println!("\n10. Cleaning up test artifacts...");
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

    Ok(())
}
