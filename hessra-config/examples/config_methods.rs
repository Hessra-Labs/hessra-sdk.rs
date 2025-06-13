use base64;
use base64::Engine;
use hessra_config::{get_default_config, set_default_config, HessraConfig, Protocol};
use std::env;
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Hessra Configuration Example ===\n");

    // Method 1: Create configuration manually
    println!("Method 1: Create configuration manually");
    let config = HessraConfig::new(
        "https://test.hessra.example.com",
        Some(443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nMANUAL CERT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nMANUAL KEY\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nMANUAL CA\n-----END CERTIFICATE-----",
    );
    println!("Manual config: {}\n", config.base_url);

    // Method 2: Use the builder pattern
    println!("Method 2: Use the builder pattern");
    let builder_config = HessraConfig::builder()
        .base_url("https://builder.hessra.example.com")
        .port(8443)
        .protocol(Protocol::Http1)
        .mtls_cert("-----BEGIN CERTIFICATE-----\nBUILDER CERT\n-----END CERTIFICATE-----")
        .mtls_key("-----BEGIN PRIVATE KEY-----\nBUILDER KEY\n-----END PRIVATE KEY-----")
        .server_ca("-----BEGIN CERTIFICATE-----\nBUILDER CA\n-----END CERTIFICATE-----")
        .public_key("-----BEGIN PUBLIC KEY-----\nBUILDER PUBLIC KEY\n-----END PUBLIC KEY-----")
        .build()?;
    println!("Builder config: {}\n", builder_config.base_url);

    // Method 3: Load from JSON file
    println!("Method 3: Load from JSON file");
    // Create a temporary JSON file
    let json_config = r#"{
        "base_url": "https://json.hessra.example.com",
        "port": 9443,
        "mtls_cert": "-----BEGIN CERTIFICATE-----\nJSON CERT\n-----END CERTIFICATE-----",
        "mtls_key": "-----BEGIN PRIVATE KEY-----\nJSON KEY\n-----END PRIVATE KEY-----",
        "server_ca": "-----BEGIN CERTIFICATE-----\nJSON CA\n-----END CERTIFICATE-----",
        "protocol": "Http1"
    }"#;

    let temp_dir = tempfile::tempdir()?;
    let json_path = temp_dir.path().join("config.json");
    fs::write(&json_path, json_config)?;

    let json_config = HessraConfig::from_file(json_path)?;
    println!("JSON config: {}\n", json_config.base_url);

    // Method 4: Load from environment variables
    println!("Method 4: Load from environment variables");

    // Create PEM content and base64 encode it
    let cert_content = "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----";
    let key_content = "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----";
    let ca_content = "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----";

    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_content);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_content);
    let ca_b64 = base64::engine::general_purpose::STANDARD.encode(ca_content);

    env::set_var("HESSRA_BASE_URL", "https://env.hessra.example.com");
    env::set_var("HESSRA_PORT", "7443");
    env::set_var("HESSRA_MTLS_CERT", cert_b64);
    env::set_var("HESSRA_MTLS_KEY", key_b64);
    env::set_var("HESSRA_SERVER_CA", ca_b64);
    env::set_var("HESSRA_PROTOCOL", "Http1");

    let env_config = HessraConfig::from_env("HESSRA")?;
    println!("Env config: {}\n", env_config.base_url);

    // Clean up environment variables
    env::remove_var("HESSRA_BASE_URL");
    env::remove_var("HESSRA_PORT");
    env::remove_var("HESSRA_MTLS_CERT");
    env::remove_var("HESSRA_MTLS_KEY");
    env::remove_var("HESSRA_SERVER_CA");
    env::remove_var("HESSRA_PROTOCOL");

    // Method 5: Global configuration
    println!("Method 5: Global configuration");
    set_default_config(config.clone())?;

    let default_config = get_default_config().expect("Default config should be set");
    println!("Default config: {}\n", default_config.base_url);

    println!("Configuration example completed successfully!");

    Ok(())
}
