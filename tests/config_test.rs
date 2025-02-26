use hessra_sdk::{get_default_config, set_default_config, ConfigError, HessraConfig, Protocol};
use std::env;
use std::fs;

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
    assert_eq!(config.mtls_cert, "CERT CONTENT");
    assert_eq!(config.mtls_key, "KEY CONTENT");
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
        "-----BEGIN CERTIFICATE-----\nJSON CERT\n-----END CERTIFICATE-----"
    );
    assert_eq!(
        config.mtls_key,
        "-----BEGIN PRIVATE KEY-----\nJSON KEY\n-----END PRIVATE KEY-----"
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

#[cfg(feature = "toml")]
#[test]
fn test_config_from_toml() {
    // Create a temporary TOML file
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("config.toml");

    let config_toml = r#"
        base_url = "toml.example.com"
        port = 7443
        mtls_cert = "TOML CERT"
        mtls_key = "TOML KEY"
        server_ca = "TOML CA"
        protocol = "Http1"
    "#;

    fs::write(&file_path, config_toml).unwrap();

    // Load the configuration from the file
    let config = HessraConfig::from_toml(file_path).unwrap();

    assert_eq!(config.base_url, "toml.example.com");
    assert_eq!(config.port, Some(7443));
    assert_eq!(config.mtls_cert, "TOML CERT");
    assert_eq!(config.mtls_key, "TOML KEY");
    assert_eq!(config.server_ca, "TOML CA");
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }
}

#[test]
fn test_config_from_env() {
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
    env::set_var("TEST_PROTOCOL", "http1");

    // Load the configuration from environment variables
    let config = HessraConfig::from_env("TEST").unwrap();

    assert_eq!(config.base_url, "https://env.example.com");
    assert_eq!(config.port, Some(6443));
    assert_eq!(
        config.mtls_cert,
        "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----"
    );
    assert_eq!(
        config.mtls_key,
        "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----"
    );
    assert_eq!(
        config.server_ca,
        "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----"
    );
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

    fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nFILE CERT CONTENT\n-----END CERTIFICATE-----",
    )
    .unwrap();
    fs::write(
        &key_path,
        "-----BEGIN PRIVATE KEY-----\nFILE KEY CONTENT\n-----END PRIVATE KEY-----",
    )
    .unwrap();
    fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nFILE CA CONTENT\n-----END CERTIFICATE-----",
    )
    .unwrap();

    // Set environment variables
    env::set_var("FILE_TEST_BASE_URL", "https://file.example.com");
    env::set_var("FILE_TEST_PORT", "5443");
    env::set_var("FILE_TEST_MTLS_CERT_FILE", cert_path.to_str().unwrap());
    env::set_var("FILE_TEST_MTLS_KEY_FILE", key_path.to_str().unwrap());
    env::set_var("FILE_TEST_SERVER_CA_FILE", ca_path.to_str().unwrap());
    env::set_var("FILE_TEST_PROTOCOL", "http1");

    // Load the configuration from environment variables with file paths
    let config = HessraConfig::from_env_or_file("FILE_TEST").unwrap();

    assert_eq!(config.base_url, "https://file.example.com");
    assert_eq!(config.port, Some(5443));
    assert_eq!(
        config.mtls_cert,
        "-----BEGIN CERTIFICATE-----\nFILE CERT CONTENT\n-----END CERTIFICATE-----"
    );
    assert_eq!(
        config.mtls_key,
        "-----BEGIN PRIVATE KEY-----\nFILE KEY CONTENT\n-----END PRIVATE KEY-----"
    );
    assert_eq!(
        config.server_ca,
        "-----BEGIN CERTIFICATE-----\nFILE CA CONTENT\n-----END CERTIFICATE-----"
    );
    match config.protocol {
        Protocol::Http1 => {}
        #[cfg(feature = "http3")]
        Protocol::Http3 => panic!("Expected HTTP/1"),
    }

    // Clean up
    env::remove_var("FILE_TEST_BASE_URL");
    env::remove_var("FILE_TEST_PORT");
    env::remove_var("FILE_TEST_MTLS_CERT_FILE");
    env::remove_var("FILE_TEST_MTLS_KEY_FILE");
    env::remove_var("FILE_TEST_SERVER_CA_FILE");
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
        "-----BEGIN CERTIFICATE-----\nDEFAULT CERT\n-----END CERTIFICATE-----"
    );
    assert_eq!(
        default_config.mtls_key,
        "-----BEGIN PRIVATE KEY-----\nDEFAULT KEY\n-----END PRIVATE KEY-----"
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

#[cfg(feature = "http3")]
#[test]
fn test_http3_protocol() {
    // Test HTTP/3 protocol with environment variables
    env::set_var("HTTP3_TEST_BASE_URL", "https://http3.example.com");
    env::set_var(
        "HTTP3_TEST_MTLS_CERT",
        "-----BEGIN CERTIFICATE-----\nHTTP3 CERT\n-----END CERTIFICATE-----",
    );
    env::set_var(
        "HTTP3_TEST_MTLS_KEY",
        "-----BEGIN PRIVATE KEY-----\nHTTP3 KEY\n-----END PRIVATE KEY-----",
    );
    env::set_var(
        "HTTP3_TEST_SERVER_CA",
        "-----BEGIN CERTIFICATE-----\nHTTP3 CA\n-----END CERTIFICATE-----",
    );
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
