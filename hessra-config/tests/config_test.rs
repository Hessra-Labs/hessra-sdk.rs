use base64;
use base64::Engine;
use hessra_config::{get_default_config, set_default_config, ConfigError, HessraConfig, Protocol};
use std::env;
use std::fs;

// Helper function to create base64-encoded PEM content
fn create_base64_pem(content: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(content)
}

#[test]
fn test_config_new() {
    let config = HessraConfig::new(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "CERT CONTENT",
        "KEY CONTENT",
        "CA CONTENT",
    );

    assert_eq!(config.base_url, "https://test.example.com");
    assert_eq!(config.port, Some(8443));
    assert_eq!(config.mtls_cert, Some("CERT CONTENT".to_string()));
    assert_eq!(config.mtls_key, Some("KEY CONTENT".to_string()));
    assert_eq!(config.server_ca, "CA CONTENT");
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }
}

#[test]
fn test_config_validation() {
    // Valid config
    let valid_config = HessraConfig::new(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCERT CONTENT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nKEY CONTENT\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );
    assert!(valid_config.validate().is_ok());

    // Missing base URL
    let invalid_config = HessraConfig::new(
        "",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCERT CONTENT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nKEY CONTENT\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );
    match invalid_config.validate() {
        Err(ConfigError::MissingBaseUrl) => {}
        _ => panic!("Expected MissingBaseUrl error"),
    }

    // Missing certificate
    let invalid_config = HessraConfig::new(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "",
        "-----BEGIN PRIVATE KEY-----\nKEY CONTENT\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );
    match invalid_config.validate() {
        Err(ConfigError::MissingCertificate) => {}
        _ => panic!("Expected MissingCertificate error"),
    }

    // Missing key
    let invalid_config = HessraConfig::new(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCERT CONTENT\n-----END CERTIFICATE-----",
        "",
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );
    match invalid_config.validate() {
        Err(ConfigError::MissingKey) => {}
        _ => panic!("Expected MissingKey error"),
    }

    // Missing server CA
    let invalid_config = HessraConfig::new(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCERT CONTENT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nKEY CONTENT\n-----END PRIVATE KEY-----",
        "",
    );
    match invalid_config.validate() {
        Err(ConfigError::MissingServerCA) => {}
        _ => panic!("Expected MissingServerCA error"),
    }
}

#[test]
fn test_config_from_file() {
    // Create a temporary JSON file
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("config.json");

    let config_json = r#"{
        "base_url": "https://json.example.com",
        "port": 9443,
        "mtls_cert": "-----BEGIN CERTIFICATE-----\nJSON CERT\n-----END CERTIFICATE-----",
        "mtls_key": "-----BEGIN PRIVATE KEY-----\nJSON KEY\n-----END PRIVATE KEY-----",
        "server_ca": "-----BEGIN CERTIFICATE-----\nJSON CA\n-----END CERTIFICATE-----",
        "protocol": "Http1"
    }"#;

    fs::write(&file_path, config_json).unwrap();

    // Load the configuration from the file
    let config = HessraConfig::from_file(file_path).unwrap();

    assert_eq!(config.base_url, "https://json.example.com");
    assert_eq!(config.port, Some(9443));
    assert_eq!(
        config.mtls_cert,
        Some("-----BEGIN CERTIFICATE-----\nJSON CERT\n-----END CERTIFICATE-----".to_string())
    );
    assert_eq!(
        config.mtls_key,
        Some("-----BEGIN PRIVATE KEY-----\nJSON KEY\n-----END PRIVATE KEY-----".to_string())
    );
    assert_eq!(
        config.server_ca,
        "-----BEGIN CERTIFICATE-----\nJSON CA\n-----END CERTIFICATE-----"
    );
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }
}

#[test]
#[cfg(feature = "toml")]
fn test_config_from_toml() {
    // Create a temporary TOML file
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("config.toml");

    let config_toml = r#"
        base_url = "toml.example.com"
        port = 7443
        mtls_cert = "-----BEGIN CERTIFICATE-----\nTOML CERT\n-----END CERTIFICATE-----"
        mtls_key = "-----BEGIN PRIVATE KEY-----\nTOML KEY\n-----END PRIVATE KEY-----"
        server_ca = "-----BEGIN CERTIFICATE-----\nTOML CA\n-----END CERTIFICATE-----"
        protocol = "Http1"
    "#;

    fs::write(&file_path, config_toml).unwrap();

    // Load the configuration from the file
    let config = HessraConfig::from_toml(file_path).unwrap();

    assert_eq!(config.base_url, "toml.example.com");
    assert_eq!(config.port, Some(7443));
    assert_eq!(
        config.mtls_cert,
        Some("-----BEGIN CERTIFICATE-----\nTOML CERT\n-----END CERTIFICATE-----".to_string())
    );
    assert_eq!(
        config.mtls_key,
        Some("-----BEGIN PRIVATE KEY-----\nTOML KEY\n-----END PRIVATE KEY-----".to_string())
    );
    assert_eq!(
        config.server_ca,
        "-----BEGIN CERTIFICATE-----\nTOML CA\n-----END CERTIFICATE-----"
    );
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }
}

#[test]
fn test_config_from_env() {
    // Create PEM content and base64 encode it
    let cert_content = "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----";
    let key_content = "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----";
    let ca_content = "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----";

    let cert_b64 = create_base64_pem(cert_content);
    let key_b64 = create_base64_pem(key_content);
    let ca_b64 = create_base64_pem(ca_content);

    // Set environment variables with base64-encoded values
    env::set_var("TEST_BASE_URL", "https://env.example.com");
    env::set_var("TEST_PORT", "6443");
    env::set_var("TEST_MTLS_CERT", cert_b64);
    env::set_var("TEST_MTLS_KEY", key_b64);
    env::set_var("TEST_SERVER_CA", ca_b64);
    env::set_var("TEST_PROTOCOL", "http1");

    // Load the configuration from environment variables
    let config = HessraConfig::from_env("TEST").unwrap();

    assert_eq!(config.base_url, "https://env.example.com");
    assert_eq!(config.port, Some(6443));
    assert_eq!(config.mtls_cert, Some(cert_content.to_string()));
    assert_eq!(config.mtls_key, Some(key_content.to_string()));
    assert_eq!(config.server_ca, ca_content);
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }

    // Clean up
    env::remove_var("TEST_BASE_URL");
    env::remove_var("TEST_PORT");
    env::remove_var("TEST_MTLS_CERT");
    env::remove_var("TEST_MTLS_KEY");
    env::remove_var("TEST_SERVER_CA");
    env::remove_var("TEST_PROTOCOL");
}

#[test]
fn test_config_from_env_or_file() {
    // Create a temporary directory
    let temp_dir = tempfile::tempdir().unwrap();

    // Create certificate files
    let cert_path = temp_dir.path().join("client.crt");
    let key_path = temp_dir.path().join("client.key");
    let ca_path = temp_dir.path().join("ca.crt");

    let cert_content = "-----BEGIN CERTIFICATE-----\nFILE CERT CONTENT\n-----END CERTIFICATE-----";
    let key_content = "-----BEGIN PRIVATE KEY-----\nFILE KEY CONTENT\n-----END PRIVATE KEY-----";
    let ca_content = "-----BEGIN CERTIFICATE-----\nFILE CA CONTENT\n-----END CERTIFICATE-----";

    fs::write(&cert_path, cert_content).unwrap();
    fs::write(&key_path, key_content).unwrap();
    fs::write(&ca_path, ca_content).unwrap();

    // Set environment variables with base64-encoded values
    env::set_var("FILE_TEST_BASE_URL", "https://file.example.com");
    env::set_var("FILE_TEST_PORT", "5443");
    env::set_var("FILE_TEST_MTLS_CERT", create_base64_pem(cert_content));
    env::set_var("FILE_TEST_MTLS_KEY", create_base64_pem(key_content));
    env::set_var("FILE_TEST_SERVER_CA", create_base64_pem(ca_content));
    env::set_var("FILE_TEST_PROTOCOL", "http1");

    // Load the configuration from environment variables with file paths
    let config = HessraConfig::from_env_or_file("FILE_TEST").unwrap();

    assert_eq!(config.base_url, "https://file.example.com");
    assert_eq!(config.port, Some(5443));
    assert_eq!(config.mtls_cert, Some(cert_content.to_string()));
    assert_eq!(config.mtls_key, Some(key_content.to_string()));
    assert_eq!(config.server_ca, ca_content);
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }

    // Clean up
    env::remove_var("FILE_TEST_BASE_URL");
    env::remove_var("FILE_TEST_PORT");
    env::remove_var("FILE_TEST_MTLS_CERT");
    env::remove_var("FILE_TEST_MTLS_KEY");
    env::remove_var("FILE_TEST_SERVER_CA");
    env::remove_var("FILE_TEST_PROTOCOL");
}

#[test]
fn test_default_config() {
    // Create a valid configuration
    let config = HessraConfig::new(
        "https://default.example.com",
        Some(4443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nDEFAULT CERT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nDEFAULT KEY\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nDEFAULT CA\n-----END CERTIFICATE-----",
    );

    // No default config should be set yet
    assert!(get_default_config().is_none());

    // Set the default configuration
    set_default_config(config.clone()).unwrap();

    // Get the default configuration
    let default_config = get_default_config().unwrap();

    assert_eq!(default_config.base_url, "https://default.example.com");
    assert_eq!(default_config.port, Some(4443));
    assert_eq!(
        default_config.mtls_cert,
        Some("-----BEGIN CERTIFICATE-----\nDEFAULT CERT\n-----END CERTIFICATE-----".to_string())
    );
    assert_eq!(
        default_config.mtls_key,
        Some("-----BEGIN PRIVATE KEY-----\nDEFAULT KEY\n-----END PRIVATE KEY-----".to_string())
    );
    assert_eq!(
        default_config.server_ca,
        "-----BEGIN CERTIFICATE-----\nDEFAULT CA\n-----END CERTIFICATE-----"
    );

    // Trying to set the default configuration again should fail
    let another_config = HessraConfig::new(
        "https://another.example.com",
        Some(3443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nANOTHER CERT\n-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----\nANOTHER KEY\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nANOTHER CA\n-----END CERTIFICATE-----",
    );

    match set_default_config(another_config) {
        Err(ConfigError::AlreadyInitialized) => {}
        _ => panic!("Expected AlreadyInitialized error"),
    }
}

#[test]
fn test_tls_only_config() {
    // Test creating a TLS-only configuration (no mTLS certificates)
    let config = HessraConfig::new_tls_only(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );

    assert_eq!(config.base_url, "https://test.example.com");
    assert_eq!(config.port, Some(8443));
    assert_eq!(config.mtls_cert, None);
    assert_eq!(config.mtls_key, None);
    assert_eq!(
        config.server_ca,
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----"
    );

    // Validate TLS-only config should succeed
    assert!(config.validate().is_ok());
}

#[test]
fn test_mixed_mtls_config_validation() {
    // Test that having only cert without key fails validation
    let mut config = HessraConfig::new_tls_only(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );

    // Add only cert, not key
    config.mtls_cert =
        Some("-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----".to_string());

    match config.validate() {
        Err(ConfigError::MissingKey) => {}
        _ => panic!("Expected MissingKey error when cert present without key"),
    }

    // Test that having only key without cert fails validation
    let mut config2 = HessraConfig::new_tls_only(
        "https://test.example.com",
        Some(8443),
        Protocol::Http1,
        "-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----",
    );

    // Add only key, not cert
    config2.mtls_key =
        Some("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----".to_string());

    match config2.validate() {
        Err(ConfigError::MissingCertificate) => {}
        _ => panic!("Expected MissingCertificate error when key present without cert"),
    }
}

#[cfg(feature = "http3")]
#[test]
fn test_http3_protocol() {
    // Create PEM content and base64 encode it
    let cert_content = "-----BEGIN CERTIFICATE-----\nHTTP3 CERT\n-----END CERTIFICATE-----";
    let key_content = "-----BEGIN PRIVATE KEY-----\nHTTP3 KEY\n-----END PRIVATE KEY-----";
    let ca_content = "-----BEGIN CERTIFICATE-----\nHTTP3 CA\n-----END CERTIFICATE-----";

    let cert_b64 = create_base64_pem(cert_content);
    let key_b64 = create_base64_pem(key_content);
    let ca_b64 = create_base64_pem(ca_content);

    // Set environment variables with base64-encoded values
    env::set_var("HTTP3_TEST_BASE_URL", "https://http3.example.com");
    env::set_var("HTTP3_TEST_MTLS_CERT", cert_b64);
    env::set_var("HTTP3_TEST_MTLS_KEY", key_b64);
    env::set_var("HTTP3_TEST_SERVER_CA", ca_b64);
    env::set_var("HTTP3_TEST_PROTOCOL", "http3");

    // Load the configuration
    let config = HessraConfig::from_env("HTTP3_TEST").unwrap();

    match config.protocol {
        Protocol::Http1 => panic!("Expected HTTP/3"),
        Protocol::Http3 => {}
    }

    // Clean up
    env::remove_var("HTTP3_TEST_BASE_URL");
    env::remove_var("HTTP3_TEST_MTLS_CERT");
    env::remove_var("HTTP3_TEST_MTLS_KEY");
    env::remove_var("HTTP3_TEST_SERVER_CA");
    env::remove_var("HTTP3_TEST_PROTOCOL");
}
