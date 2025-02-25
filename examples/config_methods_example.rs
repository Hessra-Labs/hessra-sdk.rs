use hessra_sdk::{
    get_default_config, set_default_config, try_load_default_config, HessraConfig, Protocol,
};
use std::env;
use std::error::Error;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Example 1: Creating configuration manually
    println!("Example 1: Creating configuration manually");
    let manual_config = HessraConfig::new(
        "https://test.hessra.net",            // base URL
        Some(443),                            // port (optional)
        Protocol::Http1,                      // protocol
        include_str!("../certs/client.crt"),  // mTLS certificate
        include_str!("../certs/client.key"),  // mTLS key
        include_str!("../certs/ca-2030.pem"), // Server CA certificate
    );

    let _client = manual_config.create_client()?;
    println!("Client created from manual configuration");

    // Example 2: Loading configuration from a JSON file
    println!("\nExample 2: Loading configuration from a JSON file");

    // Create a temporary JSON file
    let temp_dir = tempfile::tempdir()?;
    let file_path = temp_dir.path().join("config.json");

    let config_json = r#"{
        "base_url": "https://json.example.com",
        "port": 9443,
        "mtls_cert": "-----BEGIN CERTIFICATE-----\nJSON CERT\n-----END CERTIFICATE-----",
        "mtls_key": "-----BEGIN PRIVATE KEY-----\nJSON KEY\n-----END PRIVATE KEY-----",
        "server_ca": "-----BEGIN CERTIFICATE-----\nJSON CA\n-----END CERTIFICATE-----",
        "protocol": "Http1"
    }"#;

    fs::write(&file_path, config_json)?;

    // Load the configuration from the file
    let json_config = HessraConfig::from_file(&file_path)?;
    println!("Configuration loaded from JSON file:");
    println!("  Base URL: {}", json_config.base_url);
    println!("  Port: {:?}", json_config.port);

    // Example 3: Loading from environment variables
    println!("\nExample 3: Loading from environment variables");

    // Set environment variables
    env::set_var("TEST_BASE_URL", "https://env.example.com");
    env::set_var("TEST_PORT", "6443");
    env::set_var(
        "TEST_MTLS_CERT",
        "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----",
    );
    env::set_var(
        "TEST_MTLS_KEY",
        "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----",
    );
    env::set_var(
        "TEST_SERVER_CA",
        "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----",
    );

    // Load the configuration from environment variables
    let env_config = HessraConfig::from_env("TEST")?;
    println!("Configuration loaded from environment:");
    println!("  Base URL: {}", env_config.base_url);
    println!("  Port: {:?}", env_config.port);

    // Example 4: Using global configuration
    println!("\nExample 4: Using global configuration");

    // Set as the default configuration
    set_default_config(manual_config.clone())?;

    // Later in the code, get the default configuration
    if let Some(default_config) = get_default_config() {
        println!("Default configuration is set:");
        println!("  Base URL: {}", default_config.base_url);
        println!("  Port: {:?}", default_config.port);
    }

    // Example 5: Using from_env_or_file method
    println!("\nExample 5: Using from_env_or_file method");

    // Create certificate files
    let cert_path = temp_dir.path().join("client.crt");
    let key_path = temp_dir.path().join("client.key");
    let ca_path = temp_dir.path().join("ca.crt");

    fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nFILE CERT CONTENT\n-----END CERTIFICATE-----",
    )?;
    fs::write(
        &key_path,
        "-----BEGIN PRIVATE KEY-----\nFILE KEY CONTENT\n-----END PRIVATE KEY-----",
    )?;
    fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nFILE CA CONTENT\n-----END CERTIFICATE-----",
    )?;

    // Set environment variables with file paths
    env::set_var("FILE_TEST_BASE_URL", "https://file.example.com");
    env::set_var("FILE_TEST_PORT", "5443");
    env::set_var("FILE_TEST_MTLS_CERT_FILE", cert_path.to_str().unwrap());
    env::set_var("FILE_TEST_MTLS_KEY_FILE", key_path.to_str().unwrap());
    env::set_var("FILE_TEST_SERVER_CA_FILE", ca_path.to_str().unwrap());

    // Load the configuration from environment variables with file paths
    let file_env_config = HessraConfig::from_env_or_file("FILE_TEST")?;
    println!("Configuration loaded from env with file paths:");
    println!("  Base URL: {}", file_env_config.base_url);
    println!("  Port: {:?}", file_env_config.port);

    // Example 6: Trying to load configuration from standard locations
    println!("\nExample 6: Trying to load configuration from standard locations");
    if let Some(config) = try_load_default_config() {
        println!("Configuration found in standard location:");
        println!("  Base URL: {}", config.base_url);
        println!("  Port: {:?}", config.port);
    } else {
        println!("No configuration found in standard locations");
    }

    // Clean up
    env::remove_var("TEST_BASE_URL");
    env::remove_var("TEST_PORT");
    env::remove_var("TEST_MTLS_CERT");
    env::remove_var("TEST_MTLS_KEY");
    env::remove_var("TEST_SERVER_CA");

    env::remove_var("FILE_TEST_BASE_URL");
    env::remove_var("FILE_TEST_PORT");
    env::remove_var("FILE_TEST_MTLS_CERT_FILE");
    env::remove_var("FILE_TEST_MTLS_KEY_FILE");
    env::remove_var("FILE_TEST_SERVER_CA_FILE");

    Ok(())
}
