//! # Hessra Config
//!
//! Configuration management for Hessra SDK.
//!
//! This crate provides structures and utilities for loading and managing
//! configuration for the Hessra authentication system. It supports loading
//! configuration from various sources including environment variables,
//! files, and programmatic configuration.
//!
//! ## Features
//!
//! - Configuration loading from JSON files
//! - Configuration loading from environment variables
//! - Optional TOML file support
//! - Builder pattern for programmatic configuration
//! - Validation of configuration parameters

use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protocol options for Hessra client communication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Protocol {
    /// HTTP/1.1 protocol (always available)
    Http1,
    /// HTTP/3 protocol (only available with the "http3" feature)
    #[cfg(feature = "http3")]
    Http3,
}

fn default_protocol() -> Protocol {
    Protocol::Http1
}

/// Configuration for Hessra SDK client
///
/// This structure contains all the configuration parameters needed
/// to create a Hessra client. It can be created manually or loaded
/// from various sources.
///
/// # Examples
///
/// ## Creating a configuration manually
///
/// ```
/// use hessra_config::{HessraConfig, Protocol};
///
/// let config = HessraConfig::new(
///     "https://test.hessra.net", // base URL
///     Some(443),                  // port (optional)
///     Protocol::Http1,            // protocol
///     "client-cert-content",      // mTLS certificate
///     "client-key-content",       // mTLS key
///     "ca-cert-content",          // Server CA certificate
/// );
/// ```
///
/// ## Loading from a JSON file
///
/// ```no_run
/// use hessra_config::HessraConfig;
/// use std::path::Path;
///
/// let config = HessraConfig::from_file(Path::new("./config.json"))
///     .expect("Failed to load configuration");
/// ```
///
/// ## Loading from environment variables
///
/// ```no_run
/// use hessra_config::HessraConfig;
///
/// // Assuming the following environment variables are set:
/// // HESSRA_BASE_URL=https://test.hessra.net
/// // HESSRA_PORT=443
/// // HESSRA_MTLS_CERT=<certificate content>
/// // HESSRA_MTLS_KEY=<key content>
/// // HESSRA_SERVER_CA=<CA certificate content>
/// let config = HessraConfig::from_env("HESSRA")
///     .expect("Failed to load configuration from environment");
/// ```
///
/// ## Using the global configuration
///
/// ```no_run
/// use hessra_config::{HessraConfig, Protocol, set_default_config, get_default_config};
///
/// // Set up the global configuration
/// let config = HessraConfig::new(
///     "https://test.hessra.net",
///     Some(443),
///     Protocol::Http1,
///     "<certificate content>",
///     "<key content>",
///     "<CA certificate content>",
/// );
///
/// // Set as the default configuration
/// set_default_config(config).expect("Failed to set default configuration");
///
/// // Later in your code, get the default configuration
/// let default_config = get_default_config()
///     .expect("No default configuration set");
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HessraConfig {
    pub base_url: String,
    pub port: Option<u16>,
    /// Optional mTLS client certificate in PEM format
    /// Required for mTLS authentication, optional for identity token authentication
    #[serde(default)]
    pub mtls_cert: Option<String>,
    /// Optional mTLS private key in PEM format
    /// Required for mTLS authentication, optional for identity token authentication
    #[serde(default)]
    pub mtls_key: Option<String>,
    pub server_ca: String,
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// The server's public key for token verification
    /// as a PEM formatted string
    #[serde(default)]
    pub public_key: Option<String>,
    /// The personal keypair for the user as a PEM formatted string
    ///
    /// This is used for service chain attestations. When acting as a node in a service chain,
    /// this keypair is used to sign attestations that this node has processed the request.
    /// The private key should be kept secret and only the public key should be shared with
    /// the authorization service.
    #[serde(default)]
    pub personal_keypair: Option<String>,
}

/// Errors that can occur when working with Hessra configuration
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Base URL is required but was not provided")]
    MissingBaseUrl,
    #[error("Invalid port number. Port must be a valid number between 1-65535")]
    InvalidPort,
    #[error("mTLS certificate is required but was not provided")]
    MissingCertificate,
    #[error("mTLS key is required but was not provided")]
    MissingKey,
    #[error("Server CA certificate is required but was not provided")]
    MissingServerCA,
    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),
    #[error("I/O error occurred while reading configuration: {0}")]
    IOError(String),
    #[error("Failed to parse configuration data: {0}")]
    ParseError(String),
    #[error("Global configuration has already been initialized")]
    AlreadyInitialized,
    #[error("Environment variable error: {0}")]
    EnvVarError(String),
}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        ConfigError::IOError(error.to_string())
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(error: serde_json::Error) -> Self {
        ConfigError::ParseError(error.to_string())
    }
}

#[cfg(feature = "toml")]
impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        ConfigError::ParseError(error.to_string())
    }
}

impl From<std::env::VarError> for ConfigError {
    fn from(error: std::env::VarError) -> Self {
        ConfigError::EnvVarError(error.to_string())
    }
}

/// Builder for HessraConfig
///
/// This struct provides a more flexible way to construct a HessraConfig object.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use hessra_config::{HessraConfigBuilder, Protocol};
///
/// // Create a new config using the builder pattern
/// let config = HessraConfigBuilder::new()
///     .base_url("https://test.hessra.net")
///     .port(443)
///     .protocol(Protocol::Http1)
///     .mtls_cert("client-cert-content")
///     .mtls_key("client-key-content")
///     .server_ca("ca-cert-content")
///     .build()?;
///
/// # Ok(())
/// # }
/// ```
///
/// You can also modify an existing configuration:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use hessra_config::{HessraConfig, Protocol};
/// # let config = HessraConfig::new(
/// #     "https://test.hessra.net",
/// #     Some(443),
/// #     Protocol::Http1,
/// #     "CERT",
/// #     "KEY",
/// #     "CA"
/// # );
/// // Convert existing config to a builder
/// let new_config = config.to_builder()
///     .port(8443)  // Change the port
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Default, Debug)]
pub struct HessraConfigBuilder {
    base_url: Option<String>,
    port: Option<u16>,
    mtls_cert: Option<String>,
    mtls_key: Option<String>,
    server_ca: Option<String>,
    protocol: Option<Protocol>,
    public_key: Option<String>,
    personal_keypair: Option<String>,
}

impl HessraConfigBuilder {
    /// Create a new HessraConfigBuilder with default values
    pub fn new() -> Self {
        Self {
            base_url: None,
            port: None,
            mtls_cert: None,
            mtls_key: None,
            server_ca: None,
            protocol: None,
            public_key: None,
            personal_keypair: None,
        }
    }

    /// Create a new HessraConfigBuilder from an existing HessraConfig
    ///
    /// # Arguments
    ///
    /// * `config` - The existing HessraConfig to use as a starting point
    pub fn from_config(config: &HessraConfig) -> Self {
        Self {
            base_url: Some(config.base_url.clone()),
            port: config.port,
            mtls_cert: config.mtls_cert.clone(),
            mtls_key: config.mtls_key.clone(),
            server_ca: Some(config.server_ca.clone()),
            protocol: Some(config.protocol.clone()),
            public_key: config.public_key.clone(),
            personal_keypair: config.personal_keypair.clone(),
        }
    }

    /// Set the base URL for the Hessra service
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the Hessra service, e.g. "test.hessra.net"
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the port for the Hessra service
    ///
    /// # Arguments
    ///
    /// * `port` - The port to use for the Hessra service, e.g. 443
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the mTLS certificate for client authentication
    ///
    /// # Arguments
    ///
    /// * `cert` - The client certificate in PEM format, e.g. "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----"
    pub fn mtls_cert(mut self, cert: impl Into<String>) -> Self {
        self.mtls_cert = Some(cert.into());
        self
    }

    /// Set the mTLS private key for client authentication
    ///
    /// # Arguments
    ///
    /// * `key` - The client private key in PEM format, e.g. "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----"
    pub fn mtls_key(mut self, key: impl Into<String>) -> Self {
        self.mtls_key = Some(key.into());
        self
    }

    /// Set the server CA certificate for server validation
    ///
    /// # Arguments
    ///
    /// * `ca` - The server CA certificate in PEM format, e.g. "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----"
    pub fn server_ca(mut self, ca: impl Into<String>) -> Self {
        self.server_ca = Some(ca.into());
        self
    }

    /// Set the protocol to use for the Hessra service
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol to use (HTTP/1.1 or HTTP/3)
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Set the server's public key for token verification
    ///
    /// # Arguments
    ///
    /// * `public_key` - The server's public key in PEM format
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// Set the ed25519 or P-256 personal keypair if this is a service node in a service chain
    ///
    /// # Arguments
    ///
    /// * `personal_keypair` - The personal keypair in PEM format, e.g. "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----"
    ///   Note: Only ed25519 or P-256 keypairs are supported.
    pub fn personal_keypair(mut self, personal_keypair: impl Into<String>) -> Self {
        self.personal_keypair = Some(personal_keypair.into());
        self
    }

    /// Build a HessraConfig from this builder
    ///
    /// # Returns
    ///
    /// A Result containing either the built HessraConfig or a ConfigError
    pub fn build(self) -> Result<HessraConfig, ConfigError> {
        let base_url = self.base_url.ok_or(ConfigError::MissingBaseUrl)?;
        let server_ca = self.server_ca.ok_or(ConfigError::MissingServerCA)?;

        // mTLS is now optional - both cert and key must be provided together if any
        match (&self.mtls_cert, &self.mtls_key) {
            (Some(_), None) => return Err(ConfigError::MissingKey),
            (None, Some(_)) => return Err(ConfigError::MissingCertificate),
            _ => {}
        }

        let config = HessraConfig {
            base_url,
            port: self.port,
            protocol: self.protocol.unwrap_or_else(default_protocol),
            mtls_cert: self.mtls_cert,
            mtls_key: self.mtls_key,
            server_ca,
            public_key: self.public_key,
            personal_keypair: self.personal_keypair,
        };

        config.validate()?;
        Ok(config)
    }
}

// Global configuration instance
static GLOBAL_CONFIG: OnceLock<HessraConfig> = OnceLock::new();

impl HessraConfig {
    /// Create a new HessraConfig with the given parameters
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the Hessra service, e.g. "test.hessra.net"
    /// * `port` - Optional port to use for the Hessra service, e.g. 443
    /// * `protocol` - The protocol to use (HTTP/1.1 or HTTP/3)
    /// * `mtls_cert` - The client certificate in PEM format, e.g. "-----BEGIN CERTIFICATE-----\nENV CERT\n-----END CERTIFICATE-----"
    /// * `mtls_key` - The client private key in PEM format, e.g. "-----BEGIN PRIVATE KEY-----\nENV KEY\n-----END PRIVATE KEY-----"
    /// * `server_ca` - The server CA certificate in PEM format, e.g. "-----BEGIN CERTIFICATE-----\nENV CA\n-----END CERTIFICATE-----"
    pub fn new(
        base_url: impl Into<String>,
        port: Option<u16>,
        protocol: Protocol,
        mtls_cert: impl Into<String>,
        mtls_key: impl Into<String>,
        server_ca: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            port,
            protocol,
            mtls_cert: Some(mtls_cert.into()),
            mtls_key: Some(mtls_key.into()),
            server_ca: server_ca.into(),
            public_key: None,
            personal_keypair: None,
        }
    }

    /// Create a new HessraConfig for TLS-only connections (no mTLS)
    ///
    /// This is useful when using identity tokens for authentication
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the Hessra service, e.g. "test.hessra.net"
    /// * `port` - The port to use for the Hessra service, e.g. 443
    /// * `protocol` - The protocol to use, Http1 or Http3 (with the "http3" feature)
    /// * `server_ca` - The CA certificate for verifying the server
    pub fn new_tls_only(
        base_url: impl Into<String>,
        port: Option<u16>,
        protocol: Protocol,
        server_ca: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            port,
            protocol,
            mtls_cert: None,
            mtls_key: None,
            server_ca: server_ca.into(),
            public_key: None,
            personal_keypair: None,
        }
    }

    /// Create a new HessraConfigBuilder
    pub fn builder() -> HessraConfigBuilder {
        HessraConfigBuilder::new()
    }

    /// Convert this config to a builder for modification
    pub fn to_builder(&self) -> HessraConfigBuilder {
        HessraConfigBuilder::from_config(self)
    }

    /// Load configuration from a JSON file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON configuration file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: HessraConfig = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a TOML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    #[cfg(feature = "toml")]
    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: HessraConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix for environment variables (e.g., "HESSRA")
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used (with the given prefix):
    ///
    /// * `{PREFIX}_BASE_URL` - Base URL for the Hessra service
    /// * `{PREFIX}_PORT` - Port for the Hessra service (optional)
    /// * `{PREFIX}_PROTOCOL` - Protocol to use ("http1" or "http3")
    /// * `{PREFIX}_MTLS_CERT` - Base64-encoded client certificate in PEM format
    /// * `{PREFIX}_MTLS_KEY` - Base64-encoded client private key in PEM format
    /// * `{PREFIX}_SERVER_CA` - Base64-encoded server CA certificate in PEM format
    /// * `{PREFIX}_PUBLIC_KEY` - Base64-encoded server's public key for token verification (optional)
    /// * `{PREFIX}_PERSONAL_KEYPAIR` - Base64-encoded personal keypair in PEM format (optional)
    ///
    /// The certificate and key values can also be loaded from files by using:
    ///
    /// * `{PREFIX}_MTLS_CERT_FILE` - Path to client certificate file
    /// * `{PREFIX}_MTLS_KEY_FILE` - Path to client private key file
    /// * `{PREFIX}_SERVER_CA_FILE` - Path to server CA certificate file
    /// * `{PREFIX}_PUBLIC_KEY_FILE` - Path to server's public key file
    /// * `{PREFIX}_PERSONAL_KEYPAIR_FILE` - Path to personal keypair file
    ///
    /// Note: When using environment variables for certificates and keys, the PEM content should be
    /// base64-encoded to avoid issues with newlines and special characters in environment variables.
    pub fn from_env(prefix: &str) -> Result<Self, ConfigError> {
        let mut builder = HessraConfigBuilder::new();

        // Base URL is required
        if let Ok(base_url) = env::var(format!("{prefix}_BASE_URL")) {
            builder = builder.base_url(base_url);
        }

        // Port is optional
        if let Ok(port_str) = env::var(format!("{prefix}_PORT")) {
            if let Ok(port) = port_str.parse::<u16>() {
                builder = builder.port(port);
            } else {
                return Err(ConfigError::InvalidPort);
            }
        }

        // Protocol is optional (defaults to HTTP/1.1)
        if let Ok(protocol_str) = env::var(format!("{prefix}_PROTOCOL")) {
            let protocol = match protocol_str.to_lowercase().as_str() {
                "http1" => Protocol::Http1,
                #[cfg(feature = "http3")]
                "http3" => Protocol::Http3,
                _ => {
                    return Err(ConfigError::ParseError(format!(
                        "Invalid protocol: {protocol_str}"
                    )))
                }
            };
            builder = builder.protocol(protocol);
        }

        // Helper function to decode base64 and validate PEM format
        fn decode_base64_pem(value: &str) -> Result<String, ConfigError> {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|e| ConfigError::ParseError(format!("Invalid base64 encoding: {e}")))
                .and_then(|decoded| {
                    String::from_utf8(decoded)
                        .map_err(|e| ConfigError::ParseError(format!("Invalid UTF-8: {e}")))
                })
        }

        // Client certificate (either direct or from file)
        if let Ok(mtls_cert) = env::var(format!("{prefix}_MTLS_CERT")) {
            let decoded_cert = decode_base64_pem(&mtls_cert)?;
            builder = builder.mtls_cert(decoded_cert);
        } else if let Ok(mtls_cert_file) = env::var(format!("{prefix}_MTLS_CERT_FILE")) {
            let cert_content = fs::read_to_string(mtls_cert_file)?;
            builder = builder.mtls_cert(cert_content);
        }

        // Client key (either direct or from file)
        if let Ok(mtls_key) = env::var(format!("{prefix}_MTLS_KEY")) {
            let decoded_key = decode_base64_pem(&mtls_key)?;
            builder = builder.mtls_key(decoded_key);
        } else if let Ok(mtls_key_file) = env::var(format!("{prefix}_MTLS_KEY_FILE")) {
            let key_content = fs::read_to_string(mtls_key_file)?;
            builder = builder.mtls_key(key_content);
        }

        // Server CA certificate (either direct or from file)
        if let Ok(server_ca) = env::var(format!("{prefix}_SERVER_CA")) {
            let decoded_ca = decode_base64_pem(&server_ca)?;
            builder = builder.server_ca(decoded_ca);
        } else if let Ok(server_ca_file) = env::var(format!("{prefix}_SERVER_CA_FILE")) {
            let ca_content = fs::read_to_string(server_ca_file)?;
            builder = builder.server_ca(ca_content);
        }

        // Public key (optional, either direct or from file)
        if let Ok(public_key) = env::var(format!("{prefix}_PUBLIC_KEY")) {
            let decoded_key = decode_base64_pem(&public_key)?;
            builder = builder.public_key(decoded_key);
        } else if let Ok(public_key_file) = env::var(format!("{prefix}_PUBLIC_KEY_FILE")) {
            let key_content = fs::read_to_string(public_key_file)?;
            builder = builder.public_key(key_content);
        }

        // Personal keypair (optional, either direct or from file)
        if let Ok(personal_keypair) = env::var(format!("{prefix}_PERSONAL_KEYPAIR")) {
            let decoded_keypair = decode_base64_pem(&personal_keypair)?;
            builder = builder.personal_keypair(decoded_keypair);
        } else if let Ok(personal_keypair_file) =
            env::var(format!("{prefix}_PERSONAL_KEYPAIR_FILE"))
        {
            let keypair_content = fs::read_to_string(personal_keypair_file)?;
            builder = builder.personal_keypair(keypair_content);
        }

        builder.build()
    }

    /// Load configuration from environment variables or fall back to a config file
    ///
    /// This method will first attempt to load the configuration from environment variables.
    /// If that fails, it will look for a configuration file in the following locations:
    ///
    /// 1. Path specified in the `{PREFIX}_CONFIG_FILE` environment variable
    /// 2. `./hessra.json` in the current directory
    /// 3. `~/.config/hessra/config.json` in the user's home directory
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix for environment variables (e.g., "HESSRA")
    pub fn from_env_or_file(prefix: &str) -> Result<Self, ConfigError> {
        // First try to load from environment variables
        match Self::from_env(prefix) {
            Ok(config) => return Ok(config),
            Err(e) => {
                if !matches!(
                    e,
                    ConfigError::MissingBaseUrl
                        | ConfigError::MissingCertificate
                        | ConfigError::MissingKey
                        | ConfigError::MissingServerCA
                ) {
                    return Err(e);
                }
                // If the error is just missing required fields, try loading from file
            }
        }

        // Check if a config file path is specified in the environment
        if let Ok(config_file) = env::var(format!("{prefix}_CONFIG_FILE")) {
            return Self::load_from_file(&config_file);
        }

        // Try current directory
        if let Ok(config) = Self::load_from_file("./hessra.json") {
            return Ok(config);
        }

        // Try user's config directory
        if let Some(mut config_dir) = dirs::config_dir() {
            config_dir.push("hessra");
            config_dir.push("config.json");
            if let Ok(config) = Self::load_from_file(config_dir) {
                return Ok(config);
            }
        }

        // Couldn't find a valid configuration
        Err(ConfigError::MissingBaseUrl)
    }

    // Helper method to load from either JSON or TOML file based on extension
    fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if let Some(ext) = path.extension() {
            match ext.to_str() {
                Some("json") => Self::from_file(path),
                #[cfg(feature = "toml")]
                Some("toml") | Some("tml") => Self::from_toml(path),
                _ => Self::from_file(path), // Default to JSON if extension is unknown
            }
        } else {
            // No extension, try as JSON
            Self::from_file(path)
        }
    }

    /// Validate the current configuration
    ///
    /// Checks that all required fields are present and have valid values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check required fields
        if self.base_url.is_empty() {
            return Err(ConfigError::MissingBaseUrl);
        }

        // Validate mTLS certificates if provided
        // Both cert and key must be provided together
        match (&self.mtls_cert, &self.mtls_key) {
            (Some(cert), Some(key)) => {
                if cert.is_empty() {
                    return Err(ConfigError::MissingCertificate);
                }
                if key.is_empty() {
                    return Err(ConfigError::MissingKey);
                }
            }
            (Some(_), None) => return Err(ConfigError::MissingKey),
            (None, Some(_)) => return Err(ConfigError::MissingCertificate),
            (None, None) => {} // TLS-only mode, no mTLS required
        }

        if self.server_ca.is_empty() {
            return Err(ConfigError::MissingServerCA);
        }

        // Validate PEM formats if mTLS is configured
        if let Some(cert) = &self.mtls_cert {
            if !cert.contains("-----BEGIN CERTIFICATE-----") {
                return Err(ConfigError::InvalidCertificate(
                    "Client certificate does not appear to be in PEM format".into(),
                ));
            }
        }

        if let Some(key) = &self.mtls_key {
            if !key.contains("-----BEGIN") {
                return Err(ConfigError::InvalidCertificate(
                    "Client key does not appear to be in PEM format".into(),
                ));
            }
        }

        // Validate PEM CA certificate format (basic check)
        if !self.server_ca.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ConfigError::InvalidCertificate(
                "Server CA certificate does not appear to be in PEM format".into(),
            ));
        }

        // If a public key is provided, validate its format
        if let Some(public_key) = &self.public_key {
            if !public_key.contains("-----BEGIN PUBLIC KEY-----") {
                return Err(ConfigError::InvalidCertificate(
                    "Server public key does not appear to be in PEM format".into(),
                ));
            }
        }

        // If a personal keypair is provided, validate its format
        if let Some(keypair) = &self.personal_keypair {
            if !keypair.contains("-----BEGIN") {
                return Err(ConfigError::InvalidCertificate(
                    "Personal keypair does not appear to be in PEM format".into(),
                ));
            }
        }

        Ok(())
    }
}

/// Set the global default configuration
///
/// This function sets a global configuration that can be used across the application.
/// It can only be set once; attempting to set it again will result in an error.
///
/// # Arguments
///
/// * `config` - The configuration to set as the global default
pub fn set_default_config(config: HessraConfig) -> Result<(), ConfigError> {
    if GLOBAL_CONFIG.set(config).is_err() {
        return Err(ConfigError::AlreadyInitialized);
    }
    Ok(())
}

/// Get the global default configuration, if set
///
/// # Returns
///
/// An Option containing a reference to the global configuration, or None if not set
pub fn get_default_config() -> Option<&'static HessraConfig> {
    GLOBAL_CONFIG.get()
}

/// Try to load a default configuration from environment or files
///
/// This function attempts to load a configuration from the environment or from
/// standard configuration file locations. It does not set the global configuration.
///
/// # Returns
///
/// An Option containing the loaded configuration, or None if no valid configuration could be found
pub fn try_load_default_config() -> Option<HessraConfig> {
    // Try to load from HESSRA_ environment variables or standard file locations
    HessraConfig::from_env_or_file("HESSRA").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICZjCCAc+gAwIBAgIUJlq+zz4mN3zoNfbMkKqLQ9BS79UwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA0MTUwMDAwMDBaFw0yNDA0
MTUwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBAONH4+1QZPmY3zWP/Yjt5UJeuR0IGF5q8TYHTGw2kzbTPLTa
XMo/JohB/duKFRYvZEbGlmK0xQtLrLhBF8MUoN+kUxG9UkbQHk5xNL0eLmDOy4bm
OLtIfCIoQZyKMJFIRAgLcNv6Z9q1l+mfBCz9ZIPzVZRyCv/YsHEJUkJfrfg9AgMB
AAGjUzBRMB0GA1UdDgQWBBQCQ7Ui9CeMRzZzLeTHzYJbPT9rkjAfBgNVHSMEGDAW
gBQCQ7Ui9CeMRzZzLeTHzYJbPT9rkjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4GBADbM7a5bQjQK7JKaFaXqiueiv4qM7fhZ1O3icLzLYBzrO8vGRQo9
FM9zgPOiqpjzLGfDhbUJvN3hbjPZmzJzyyRM9XHdKKwYH/ErY6vRbciuO7qbD6Hx
CKZ0ORbMdmc0TRF6+5s6p3bhDvZ2ZpUVsXzMz5ZxMnpQMpfh3AbEV2Yw
-----END CERTIFICATE-----"#;

    const VALID_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAONH4+1QZPmY3zWP
/Yjt5UJeuR0IGF5q8TYHTGw2kzbTPLTaXMo/JohB/duKFRYvZEbGlmK0xQtLrLhB
F8MUoN+kUxG9UkbQHk5xNL0eLmDOy4bmOLtIfCIoQZyKMJFIRAgLcNv6Z9q1l+mf
BCz9ZIPzVZRyCv/YsHEJUkJfrfg9AgMBAAECgYEAw5tgq6t1QRUDNaZsNQ4QYkgI
CjVekg0XMR/WK6NmmKUkOI2aTaA+CwU0ZYERLvGZMLOVPHJKQZdLLbsl8CvhDtT1
HXpxKR1EJ8vuCPlfZ3LVdUVQeV3QcUpBQGvzWGHl2R3LM/RrW4cS4eP4SMNdVVF4
jdmGpMDvPm/0VoUtRwECQQD/EY/RTGlU9oXnSwEUfK9Gg0OBXDVEPGrNJ4JAoMHn
MJQywP0IZxHfr8A9uk9U8L+5LCFgXcFZ8fgYOFvrElxBAkEA5Ca+Tq5k4IEpyW+Q
wPrKu77SmAKiT3JlIslGUO0OXUHYqZbRHWCAQTZWZuaOJG8I82I5EWyLrVaJbA4X
OgbebQJABHBmZA3TF1zRci73OWUc7pK2K8PSx38tPPAIg5dP5y8SGpiKpf+8HijD
EjKvY+0K1Py1Q7nHU4GbqE9juOS0AQJAFDIYzaGuJwdNZRIAS2h5uqZmIpKieLfc
5c3JVVzkBFXfKQME6KsAdIrlpwCmzU5vUEQzGWNXCes2uBGp2XpXxQJAGvf5IVWF
+ZkVB5GKbj0DGOw3rH7QYhbJVAeCJbzBqI+euvtVK4xrDdWZsK8IGy6NCxMA//Qf
Tz0nftszeCrCGw==
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_config_builder() {
        let config = HessraConfigBuilder::new()
            .base_url("https://test.hessra.net")
            .port(443)
            .protocol(Protocol::Http1)
            .mtls_cert(VALID_CERT)
            .mtls_key(VALID_KEY)
            .server_ca(VALID_CERT)
            .build()
            .unwrap();

        assert_eq!(config.base_url, "https://test.hessra.net");
        assert_eq!(config.port, Some(443));
        assert!(matches!(config.protocol, Protocol::Http1));
    }

    #[test]
    fn test_config_validation() {
        // Missing base URL
        let result = HessraConfigBuilder::new()
            .mtls_cert(VALID_CERT)
            .mtls_key(VALID_KEY)
            .server_ca(VALID_CERT)
            .build();
        assert!(matches!(result, Err(ConfigError::MissingBaseUrl)));

        // Missing certificate
        let result = HessraConfigBuilder::new()
            .base_url("https://test.hessra.net")
            .mtls_key(VALID_KEY)
            .server_ca(VALID_CERT)
            .build();
        assert!(matches!(result, Err(ConfigError::MissingCertificate)));

        // Invalid certificate format
        let result = HessraConfigBuilder::new()
            .base_url("https://test.hessra.net")
            .mtls_cert("not-a-cert")
            .mtls_key(VALID_KEY)
            .server_ca(VALID_CERT)
            .build();
        assert!(matches!(result, Err(ConfigError::InvalidCertificate(_))));
    }

    #[test]
    fn test_load_from_json() {
        let config_json = r#"{
            "base_url": "https://test.hessra.net",
            "port": 443,
            "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIICZjCCAc+gAwIBAgIUJlq+zz4mN3zoNfbMkKqLQ9BS79UwDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----",
            "mtls_key": "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAONH4+1QZPmY3zWP\n-----END PRIVATE KEY-----",
            "server_ca": "-----BEGIN CERTIFICATE-----\nMIICZjCCAc+gAwIBAgIUJlq+zz4mN3zoNfbMkKqLQ9BS79UwDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"
        }"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_json.as_bytes()).unwrap();

        let config = HessraConfig::from_file(temp_file.path()).unwrap();
        assert_eq!(config.base_url, "https://test.hessra.net");
        assert_eq!(config.port, Some(443));
    }

    #[test]
    fn test_from_env() {
        // This test would set environment variables, but that's not ideal for unit tests
        // Instead, we'll just test the builder conversion

        let original = HessraConfig::new(
            "https://test.hessra.net",
            Some(443),
            Protocol::Http1,
            VALID_CERT,
            VALID_KEY,
            VALID_CERT,
        );

        let builder = original.to_builder();
        let new_config = builder.port(8443).build().unwrap();

        assert_eq!(new_config.base_url, original.base_url);
        assert_eq!(new_config.port, Some(8443));
    }

    #[test]
    fn test_global_config() {
        // Test setting and getting global config
        // Note: this test is not ideal since it modifies global state
        // In a real test suite, you'd want to run these in isolation

        let config = HessraConfig::new(
            "https://test.hessra.net",
            Some(443),
            Protocol::Http1,
            VALID_CERT,
            VALID_KEY,
            VALID_CERT,
        );

        // First time should succeed
        assert!(set_default_config(config.clone()).is_ok());

        // Second time should fail
        assert!(matches!(
            set_default_config(config.clone()),
            Err(ConfigError::AlreadyInitialized)
        ));

        // Getting should return our config
        let global = get_default_config().unwrap();
        assert_eq!(global.base_url, "https://test.hessra.net");
    }
}
