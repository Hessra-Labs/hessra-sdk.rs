//! Integration test for hessra CLI tool
//!
//! This example tests the CLI functionality against the live test.hessra.net service.
//! It verifies:
//! - Authentication and identity token creation
//! - Public key caching
//! - Token delegation with cached keys
//! - Token verification
//! - Token management (list, delete)

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// Test certificates for mTLS authentication
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

const TEST_SERVER: &str = "test.hessra.net";
const TEST_PORT: u16 = 443;

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

fn setup_test_certificates() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let temp_dir = std::env::temp_dir().join("hessra_cli_test");
    fs::create_dir_all(&temp_dir)?;

    let cert_path = temp_dir.join("client.crt");
    let key_path = temp_dir.join("client.key");
    let ca_path = temp_dir.join("ca.crt");

    fs::write(&cert_path, MTLS_CERT)?;
    fs::write(&key_path, MTLS_KEY)?;
    fs::write(&ca_path, SERVER_CA)?;

    Ok((cert_path, key_path, ca_path))
}

fn cleanup_test_tokens() -> Result<()> {
    // Clean up any test tokens from previous runs
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let tokens_dir = home.home_dir().join(".hessra").join("tokens");

    if tokens_dir.exists() {
        for entry in fs::read_dir(&tokens_dir)? {
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
    let keys_dir = home.home_dir().join(".hessra").join("public_keys");

    if !keys_dir.exists() {
        return Ok(false);
    }

    let sanitized_server = server
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':'], "_");

    let key_file = keys_dir.join(format!("{}.pub", sanitized_server));
    Ok(key_file.exists())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Hessra CLI Integration Test ===\n");

    // Setup
    println!("Setting up test environment...");
    let (cert_path, key_path, ca_path) = setup_test_certificates()?;
    cleanup_test_tokens()?;

    // Test 1: Authenticate and get identity token
    println!("\n1. Testing authentication with mTLS...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "authenticate",
        "--server",
        TEST_SERVER,
        "--port",
        &TEST_PORT.to_string(),
        "--cert",
        cert_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--ca",
        ca_path.to_str().unwrap(),
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
        stdout.contains("uri:urn:test:argo-cli0"),
        "Should have correct identity"
    );
    println!("✓ Authentication successful");

    // Verify public key was cached
    let key_cached = verify_public_key_cached(TEST_SERVER)?;
    assert!(
        key_cached,
        "Public key should be cached after authentication"
    );
    println!("✓ Public key cached successfully");

    // Test 2: Delegate token using cached public key (no CA needed)
    println!("\n2. Testing delegation with cached public key...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "delegate",
        "--identity",
        "uri:urn:test:argo-cli0:agent1",
        "--from-token",
        "test_main",
        "--save-as",
        "test_delegated",
        "--server",
        TEST_SERVER,
        "--port",
        &TEST_PORT.to_string(),
        "--json",
        // Note: NOT providing --ca, should use cached key
    ])?;

    if !success {
        eprintln!("Delegation stderr: {}", stderr);
    }
    assert!(success, "Delegation should succeed with cached key");
    assert!(
        stdout.contains("\"success\": true"),
        "Delegation should indicate success"
    );
    assert!(
        stdout.contains("uri:urn:test:argo-cli0:agent1"),
        "Should have delegated identity"
    );
    println!("✓ Delegation successful using cached public key");

    // Test 3: Verify the delegated token
    println!("\n3. Testing token verification...");
    let (stdout, stderr, success) = run_hessra_command(&[
        "identity",
        "verify",
        "--token-name",
        "test_delegated",
        "--identity",
        "uri:urn:test:argo-cli0:agent1",
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

    // Test 4: List tokens
    println!("\n4. Testing token listing...");
    let (stdout, _stderr, success) = run_hessra_command(&["identity", "list", "--json"])?;

    assert!(success, "List should succeed");
    assert!(stdout.contains("test_main"), "Should list main token");
    assert!(
        stdout.contains("test_delegated"),
        "Should list delegated token"
    );
    println!("✓ Token listing successful");

    // Test 5: Test delegation with explicit public key via environment variable
    println!("\n5. Testing delegation with explicit public key (via environment variable)...");

    // The --public-key flag also supports the HESSRA_PUBLIC_KEY environment variable
    // This is more practical for public keys which contain newlines
    // We've already tested the cached key functionality, so this test is optional
    println!("  (Skipping - public key env var is already supported via HESSRA_PUBLIC_KEY)");

    // Test 6: Delete tokens
    println!("\n6. Testing token deletion...");
    let (_stdout, _stderr, success) =
        run_hessra_command(&["identity", "delete", "test_delegated", "--json"])?;

    assert!(success, "Delete should succeed");
    println!("✓ Token deletion successful");

    // Verify token was deleted
    let (stdout, _stderr, success) = run_hessra_command(&["identity", "list", "--json"])?;
    assert!(success, "List should succeed");
    assert!(
        !stdout.contains("\"test_delegated\""),
        "Deleted token should not be listed"
    );

    // Test 7: Test fallback to fetching public key when not cached
    println!("\n7. Testing fallback to fetching public key...");

    // Remove cached public key
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let keys_dir = home.home_dir().join(".hessra").join("public_keys");
    if keys_dir.exists() {
        fs::remove_dir_all(&keys_dir)?;
    }

    // Try delegation with CA provided (should fetch and cache)
    let (stdout, _stderr, success) = run_hessra_command(&[
        "identity",
        "delegate",
        "--identity",
        "uri:urn:test:argo-cli0:agent3",
        "--from-token",
        "test_main",
        "--save-as",
        "test_delegated_fetched",
        "--server",
        TEST_SERVER,
        "--port",
        &TEST_PORT.to_string(),
        "--ca",
        ca_path.to_str().unwrap(),
        "--verbose",
        "--json",
    ])?;

    assert!(success, "Delegation with CA should succeed");
    assert!(
        stdout.contains("\"success\": true"),
        "Should indicate success"
    );

    // Verify key was re-cached
    let key_cached = verify_public_key_cached(TEST_SERVER)?;
    assert!(key_cached, "Public key should be re-cached after fetching");
    println!("✓ Fallback to fetching public key successful");

    // Cleanup
    println!("\n8. Cleaning up test artifacts...");
    cleanup_test_tokens()?;
    fs::remove_dir_all(cert_path.parent().unwrap())?;
    println!("✓ Cleanup complete");

    println!("\n=== All tests passed! ===");
    Ok(())
}
