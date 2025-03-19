use crate::{HessraClient, Protocol};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

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
/// use hessra_sdk::{HessraConfig, Protocol};
///
/// let config = HessraConfig::new(
///     "https://test.hessra.net", // base URL
///     Some(443),                  // port (optional)
///     Protocol::Http1,            // protocol
///     include_str!("../certs/client.crt"), // mTLS certificate
///     include_str!("../certs/client.key"),  // mTLS key
///     include_str!("../certs/ca.crt"),      // Server CA certificate
/// );
/// ```
///
/// ## Loading from a JSON file
///
/// ```no_run
/// use hessra_sdk::HessraConfig;
/// use std::path::Path;
///
/// let config = HessraConfig::from_file(Path::new("./config.json"))
///     .expect("Failed to load configuration");
/// ```
///
/// ## Loading from environment variables
///
/// ```no_run
/// use hessra_sdk::HessraConfig;
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
/// use hessra_sdk::{HessraConfig, Protocol, set_default_config, get_default_config};
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
    pub mtls_cert: String,
    pub mtls_key: String,
    pub server_ca: String,
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// The server's public key for token verification
    #[serde(default)]
    pub public_key: Option<String>,
    /// The personal keypair for the user in PEM format
    ///
    /// This is used for service chain attestations. When acting as a node in a service chain,
    /// this keypair is used to sign attestations that this node has processed the request.
    /// The private key should be kept secret and only the public key should be shared with
    /// the authentication service.
    #[serde(default)]
    pub personal_keypair: Option<String>,
}

fn default_protocol() -> Protocol {
    Protocol::Http1
}

/// Builder for HessraConfig
///
/// This struct provides a more flexible way to construct a HessraConfig object.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use hessra_sdk::{HessraConfigBuilder, Protocol};
///
/// // Create a new config using the builder pattern
/// let config = HessraConfigBuilder::new()
///     .base_url("https://test.hessra.net")
///     .port(443)
///     .protocol(Protocol::Http1)
///     .mtls_cert(include_str!("../certs/client.crt"))
///     .mtls_key(include_str!("../certs/client.key"))
///     .server_ca(include_str!("../certs/ca.crt"))
///     .build()?;
///
/// // Use the config to create a client
/// let client = config.create_client()?;
/// # Ok(())
/// # }
/// ```
///
/// You can also modify an existing configuration:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use hessra_sdk::{HessraConfig, Protocol};
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
            mtls_cert: Some(config.mtls_cert.clone()),
            mtls_key: Some(config.mtls_key.clone()),
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
    /// * `base_url` - The base URL for the Hessra service
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the port for the Hessra service
    ///
    /// # Arguments
    ///
    /// * `port` - The port to use for the Hessra service
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the mTLS certificate for client authentication
    ///
    /// # Arguments
    ///
    /// * `cert` - The client certificate in PEM format
    pub fn mtls_cert(mut self, cert: impl Into<String>) -> Self {
        self.mtls_cert = Some(cert.into());
        self
    }

    /// Set the mTLS private key for client authentication
    ///
    /// # Arguments
    ///
    /// * `key` - The client private key in PEM format
    pub fn mtls_key(mut self, key: impl Into<String>) -> Self {
        self.mtls_key = Some(key.into());
        self
    }

    /// Set the server CA certificate for server validation
    ///
    /// # Arguments
    ///
    /// * `ca` - The server CA certificate in PEM format
    pub fn server_ca(mut self, ca: impl Into<String>) -> Self {
        self.server_ca = Some(ca.into());
        self
    }

    /// Set the protocol to use for the Hessra service
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol to use (HTTP/1.1 or HTTP/2)
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Set the public key for token verification
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key in PEM format
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// Set the personal keypair for the user PEM formatted string
    ///
    /// # Arguments
    ///
    /// * `personal_keypair` - The personal keypair in PEM formatted string
    pub fn personal_keypair(mut self, personal_keypair: impl Into<String>) -> Self {
        self.personal_keypair = Some(personal_keypair.into());
        self
    }

    /// Build the HessraConfig
    ///
    /// # Returns
    ///
    /// A Result containing either the built HessraConfig or a ConfigError
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing or invalid
    pub fn build(self) -> Result<HessraConfig, ConfigError> {
        let config = HessraConfig {
            base_url: self.base_url.ok_or(ConfigError::MissingBaseUrl)?,
            port: self.port,
            mtls_cert: self.mtls_cert.ok_or(ConfigError::MissingCertificate)?,
            mtls_key: self.mtls_key.ok_or(ConfigError::MissingKey)?,
            server_ca: self.server_ca.ok_or(ConfigError::MissingServerCA)?,
            protocol: self.protocol.unwrap_or_else(default_protocol),
            public_key: self.public_key,
            personal_keypair: self.personal_keypair,
        };

        // Validate the config to ensure all fields are valid
        config.validate()?;

        Ok(config)
    }
}

/// Errors that can occur when working with Hessra configuration
#[derive(Debug)]
pub enum ConfigError {
    MissingBaseUrl,
    InvalidPort,
    MissingCertificate,
    MissingKey,
    MissingServerCA,
    InvalidCertificate(String),
    IOError(String),
    ParseError(String),
    AlreadyInitialized,
    EnvVarError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingBaseUrl => {
                write!(f, "Base URL is required but was not provided. Please specify a valid URL for the Hessra service.")
            }
            ConfigError::InvalidPort => {
                write!(
                    f,
                    "Invalid port number. Port must be a valid number between 1-65535."
                )
            }
            ConfigError::MissingCertificate => {
                write!(f, "mTLS certificate is required but was not provided. Please provide a valid PEM-encoded certificate.")
            }
            ConfigError::MissingKey => {
                write!(f, "mTLS key is required but was not provided. Please provide a valid PEM-encoded private key.")
            }
            ConfigError::MissingServerCA => {
                write!(f, "Server CA certificate is required but was not provided. Please provide a valid PEM-encoded CA certificate.")
            }
            ConfigError::InvalidCertificate(e) => {
                write!(f, "Invalid certificate format: {}. Please ensure the certificate is properly PEM-encoded.", e)
            }
            ConfigError::IOError(e) => {
                write!(f, "I/O error occurred while reading configuration: {}. Please check file permissions and paths.", e)
            }
            ConfigError::ParseError(e) => {
                write!(f, "Failed to parse configuration data: {}. Please ensure the configuration format is correct.", e)
            }
            ConfigError::AlreadyInitialized => {
                write!(f, "Global configuration has already been initialized. Call get_default_config() to access it or create a new local configuration.")
            }
            ConfigError::EnvVarError(e) => {
                write!(f, "Environment variable error: {}. Please ensure all required environment variables are set correctly.", e)
            }
        }
    }
}

impl Error for ConfigError {}

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

impl HessraConfig {
    /// Create a new configuration with the specified parameters
    pub fn new(
        base_url: impl Into<String>,
        port: Option<u16>,
        protocol: Protocol,
        mtls_cert: impl Into<String>,
        mtls_key: impl Into<String>,
        server_ca: impl Into<String>,
    ) -> Self {
        HessraConfig {
            base_url: base_url.into(),
            port,
            protocol,
            mtls_cert: mtls_cert.into(),
            mtls_key: mtls_key.into(),
            server_ca: server_ca.into(),
            public_key: None,
            personal_keypair: None,
        }
    }

    pub fn builder() -> HessraConfigBuilder {
        HessraConfigBuilder::new()
    }

    /// Convert this configuration to a builder for modification
    pub fn to_builder(&self) -> HessraConfigBuilder {
        HessraConfigBuilder::from_config(self)
    }

    /// Create a configuration from a JSON file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_content = fs::read_to_string(path)?;
        let config: HessraConfig = serde_json::from_str(&file_content)?;
        config.validate()?;
        Ok(config)
    }

    /// Create a configuration from a TOML file
    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_content = fs::read_to_string(path)?;
        let config: HessraConfig = toml::from_str(&file_content)?;
        config.validate()?;
        Ok(config)
    }

    /// Create a configuration from environment variables
    ///
    /// The environment variables should be named with the given prefix followed by:
    /// - BASE_URL: The base URL of the Hessra service
    /// - PORT: The port to connect to (optional)
    /// - MTLS_CERT: The mTLS certificate (content, not path)
    /// - MTLS_KEY: The mTLS key (content, not path)
    /// - SERVER_CA: The server CA certificate (content, not path)
    /// - PROTOCOL: Either "http1" or "http3" (optional, defaults to "http1")
    ///
    /// For example, with the prefix "HESSRA", the environment variables would be:
    /// - HESSRA_BASE_URL
    /// - HESSRA_PORT
    /// - HESSRA_MTLS_CERT
    /// - HESSRA_MTLS_KEY
    /// - HESSRA_SERVER_CA
    /// - HESSRA_PROTOCOL
    /// - HESSRA_PERSONAL_KEYPAIR
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hessra_sdk::HessraConfig;
    /// use std::env;
    ///
    /// // Set environment variables (in a real app, these would be set externally)
    /// env::set_var("APP_BASE_URL", "https://test.hessra.net");
    /// env::set_var("APP_PORT", "443");
    /// env::set_var("APP_MTLS_CERT", "-----BEGIN CERTIFICATE-----\n...");
    /// env::set_var("APP_MTLS_KEY", "-----BEGIN PRIVATE KEY-----\n...");
    /// env::set_var("APP_SERVER_CA", "-----BEGIN CERTIFICATE-----\n...");
    /// env::set_var("APP_PROTOCOL", "http1");
    ///
    /// // Load configuration from environment variables
    /// let config = HessraConfig::from_env("APP")
    ///     .expect("Failed to load configuration from environment");
    ///
    /// // Use the configuration
    /// let client = config.create_client()
    ///     .expect("Failed to create client");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a `ConfigError` if any required environment variable is missing or invalid.
    pub fn from_env(prefix: &str) -> Result<Self, ConfigError> {
        let base_url = env::var(format!("{}_BASE_URL", prefix))?;

        let port = match env::var(format!("{}_PORT", prefix)) {
            Ok(port_str) => Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| ConfigError::InvalidPort)?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(e.into()),
        };

        let mtls_cert = env::var(format!("{}_MTLS_CERT", prefix))?;
        let mtls_key = env::var(format!("{}_MTLS_KEY", prefix))?;
        let server_ca = env::var(format!("{}_SERVER_CA", prefix))?;

        let protocol = match env::var(format!("{}_PROTOCOL", prefix)) {
            Ok(protocol_str) => match protocol_str.to_lowercase().as_str() {
                "http1" => Protocol::Http1,
                #[cfg(feature = "http3")]
                "http3" => Protocol::Http3,
                _ => {
                    return Err(ConfigError::ParseError(format!(
                        "Invalid protocol: {}",
                        protocol_str
                    )))
                }
            },
            Err(std::env::VarError::NotPresent) => Protocol::Http1,
            Err(e) => return Err(e.into()),
        };

        // Try to load public key from environment variable
        let public_key = match env::var(format!("{}_PUBLIC_KEY", prefix)) {
            Ok(key) => Some(key),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(e.into()),
        };

        let personal_keypair = match env::var(format!("{}_PERSONAL_KEYPAIR", prefix)) {
            Ok(key) => Some(key),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(e.into()),
        };

        let config = HessraConfig {
            base_url,
            port,
            protocol,
            mtls_cert,
            mtls_key,
            server_ca,
            public_key,
            personal_keypair,
        };

        config.validate()?;
        Ok(config)
    }

    /// Create a configuration from environment variables or files
    ///
    /// This is similar to `from_env`, but it also supports loading certificates
    /// and keys from files. If an environment variable with the suffix `_FILE`
    /// is present, the contents of the file at that path will be loaded.
    ///
    /// For example, with the prefix "HESSRA", the environment variables could be:
    /// - HESSRA_BASE_URL
    /// - HESSRA_PORT
    /// - HESSRA_MTLS_CERT or HESSRA_MTLS_CERT_FILE
    /// - HESSRA_MTLS_KEY or HESSRA_MTLS_KEY_FILE
    /// - HESSRA_SERVER_CA or HESSRA_SERVER_CA_FILE
    /// - HESSRA_PROTOCOL
    /// - HESSRA_PERSONAL_KEYPAIR or HESSRA_PERSONAL_KEYPAIR_FILE
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hessra_sdk::HessraConfig;
    /// use std::env;
    /// use std::fs::File;
    /// use std::io::Write;
    ///
    /// // In this example, we'll load the certificate data from files
    /// // First, write the certificate data to files (in a real app, these would already exist)
    /// let cert_path = "/tmp/client.crt";
    /// let key_path = "/tmp/client.key";
    /// let ca_path = "/tmp/ca.crt";
    ///
    /// // Create and write to the files (demonstration only)
    /// File::create(cert_path).unwrap().write_all(b"-----BEGIN CERTIFICATE-----\n...").unwrap();
    /// File::create(key_path).unwrap().write_all(b"-----BEGIN PRIVATE KEY-----\n...").unwrap();
    /// File::create(ca_path).unwrap().write_all(b"-----BEGIN CERTIFICATE-----\n...").unwrap();
    ///
    /// // Set environment variables pointing to the files
    /// env::set_var("SERVICE_BASE_URL", "https://test.hessra.net");
    /// env::set_var("SERVICE_PORT", "443");
    /// env::set_var("SERVICE_MTLS_CERT_FILE", cert_path);
    /// env::set_var("SERVICE_MTLS_KEY_FILE", key_path);
    /// env::set_var("SERVICE_SERVER_CA_FILE", ca_path);
    /// env::set_var("SERVICE_PROTOCOL", "http1");
    ///
    /// // Load configuration from environment variables with file paths
    /// let config = HessraConfig::from_env_or_file("SERVICE")
    ///     .expect("Failed to load configuration from environment");
    ///
    /// // Use the configuration
    /// let client = config.create_client()
    ///     .expect("Failed to create client");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a `ConfigError` if any required environment variable or file is missing or invalid.
    pub fn from_env_or_file(prefix: &str) -> Result<Self, ConfigError> {
        let base_url = env::var(format!("{}_BASE_URL", prefix))?;

        let port = match env::var(format!("{}_PORT", prefix)) {
            Ok(port_str) => Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| ConfigError::InvalidPort)?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(e.into()),
        };

        // Try to get mTLS certificate from file or directly
        let mtls_cert = match env::var(format!("{}_MTLS_CERT_FILE", prefix)) {
            Ok(cert_file) => fs::read_to_string(cert_file).map_err(|e| {
                ConfigError::IOError(format!("Failed to read certificate file: {}", e))
            })?,
            Err(std::env::VarError::NotPresent) => env::var(format!("{}_MTLS_CERT", prefix))?,
            Err(e) => return Err(e.into()),
        };

        // Try to get mTLS key from file or directly
        let mtls_key = match env::var(format!("{}_MTLS_KEY_FILE", prefix)) {
            Ok(key_file) => fs::read_to_string(key_file)
                .map_err(|e| ConfigError::IOError(format!("Failed to read key file: {}", e)))?,
            Err(std::env::VarError::NotPresent) => env::var(format!("{}_MTLS_KEY", prefix))?,
            Err(e) => return Err(e.into()),
        };

        // Try to get server CA from file or directly
        let server_ca = match env::var(format!("{}_SERVER_CA_FILE", prefix)) {
            Ok(ca_file) => fs::read_to_string(ca_file)
                .map_err(|e| ConfigError::IOError(format!("Failed to read CA file: {}", e)))?,
            Err(std::env::VarError::NotPresent) => env::var(format!("{}_SERVER_CA", prefix))?,
            Err(e) => return Err(e.into()),
        };

        // Try to get protocol from environment variable
        let protocol = match env::var(format!("{}_PROTOCOL", prefix)) {
            Ok(protocol_str) => match protocol_str.to_lowercase().as_str() {
                "http1" => Protocol::Http1,
                #[cfg(feature = "http3")]
                "http3" => Protocol::Http3,
                _ => {
                    return Err(ConfigError::ParseError(format!(
                        "Invalid protocol: {}",
                        protocol_str
                    )))
                }
            },
            Err(std::env::VarError::NotPresent) => Protocol::Http1,
            Err(e) => return Err(e.into()),
        };

        // Try to get public key from file or directly
        let public_key = match env::var(format!("{}_PUBLIC_KEY_FILE", prefix)) {
            Ok(key_file) => Some(fs::read_to_string(key_file).map_err(|e| {
                ConfigError::IOError(format!("Failed to read public key file: {}", e))
            })?),
            Err(std::env::VarError::NotPresent) => match env::var(format!("{}_PUBLIC_KEY", prefix))
            {
                Ok(key) => Some(key),
                Err(std::env::VarError::NotPresent) => None,
                Err(e) => return Err(e.into()),
            },
            Err(e) => return Err(e.into()),
        };

        let personal_keypair = match env::var(format!("{}_PERSONAL_KEYPAIR_FILE", prefix)) {
            Ok(key_file) => Some(fs::read_to_string(key_file).map_err(|e| {
                ConfigError::IOError(format!("Failed to read personal key file: {}", e))
            })?),
            Err(std::env::VarError::NotPresent) => {
                match env::var(format!("{}_PERSONAL_KEYPAIR", prefix)) {
                    Ok(key) => Some(key),
                    Err(std::env::VarError::NotPresent) => None,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };

        let config = HessraConfig {
            base_url,
            port,
            protocol,
            mtls_cert,
            mtls_key,
            server_ca,
            public_key,
            personal_keypair,
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    ///
    /// Checks that all required fields are present and valid.
    /// Performs basic validation of the configuration parameters.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_url.is_empty() {
            return Err(ConfigError::MissingBaseUrl);
        }

        // Validate port if specified
        if let Some(port) = self.port {
            if port == 0 {
                return Err(ConfigError::InvalidPort);
            }
        }

        if self.mtls_cert.is_empty() {
            return Err(ConfigError::MissingCertificate);
        }

        // Basic certificate validation
        if !self.mtls_cert.contains("BEGIN CERTIFICATE") {
            return Err(ConfigError::InvalidCertificate(
                "Certificate does not contain 'BEGIN CERTIFICATE' marker".to_string(),
            ));
        }

        if self.mtls_key.is_empty() {
            return Err(ConfigError::MissingKey);
        }

        // Basic key validation
        if !self.mtls_key.contains("BEGIN")
            || (!self.mtls_key.contains("PRIVATE KEY") && !self.mtls_key.contains("ENCRYPTED"))
        {
            return Err(ConfigError::InvalidCertificate(
                "Key does not contain proper PEM markers".to_string(),
            ));
        }

        if self.server_ca.is_empty() {
            return Err(ConfigError::MissingServerCA);
        }

        // Basic CA validation
        if !self.server_ca.contains("BEGIN CERTIFICATE") {
            return Err(ConfigError::InvalidCertificate(
                "CA certificate does not contain 'BEGIN CERTIFICATE' marker".to_string(),
            ));
        }

        if let Some(personal_keypair) = &self.personal_keypair {
            if !personal_keypair.contains("BEGIN")
                || (!personal_keypair.contains("PRIVATE KEY")
                    && !personal_keypair.contains("ENCRYPTED"))
            {
                return Err(ConfigError::InvalidCertificate(
                    "Personal key does not contain proper PEM markers".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Create a Hessra client from this configuration
    pub fn create_client(&self) -> Result<HessraClient, Box<dyn Error>> {
        HessraClient::builder()
            .base_url(&self.base_url)
            .port(self.port.unwrap_or(443))
            .protocol(self.protocol.clone())
            .mtls_cert(&self.mtls_cert)
            .mtls_key(&self.mtls_key)
            .server_ca(&self.server_ca)
            .build()
    }

    /// Fetch and store the public key from the server
    ///
    /// This method retrieves the public key from the Hessra service
    /// and stores it in the configuration for later use.
    ///
    /// # Returns
    ///
    /// The fetched public key as a string, or an error if the request failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use hessra_sdk::HessraConfig;
    ///
    /// let mut config = HessraConfig::new(
    ///     "https://test.hessra.net",
    ///     Some(443),
    ///     hessra_sdk::Protocol::Http1,
    ///     "CERT",
    ///     "KEY",
    ///     "CA"
    /// );
    ///
    /// // Fetch and store the public key
    /// let public_key = config.fetch_and_store_public_key().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_and_store_public_key(&mut self) -> Result<String, Box<dyn Error>> {
        let url_host =
            if self.base_url.starts_with("http://") || self.base_url.starts_with("https://") {
                let url_parts: Vec<&str> = self.base_url.split("://").collect();
                url_parts[1].to_string()
            } else {
                self.base_url.clone()
            };

        let public_key =
            HessraClient::fetch_public_key(url_host, self.port, self.server_ca.as_str()).await?;
        self.public_key = Some(public_key.clone());
        Ok(public_key)
    }

    /// Get the stored public key, or fetch it if not available
    ///
    /// This method returns the stored public key if available,
    /// or fetches it from the server if not.
    ///
    /// # Returns
    ///
    /// The public key as a string, or an error if the request failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use hessra_sdk::HessraConfig;
    ///
    /// let mut config = HessraConfig::new(
    ///     "https://test.hessra.net",
    ///     Some(443),
    ///     hessra_sdk::Protocol::Http1,
    ///     "CERT",
    ///     "KEY",
    ///     "CA"
    /// );
    ///
    /// // Get the public key, fetching it if necessary
    /// let public_key = config.get_or_fetch_public_key().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_or_fetch_public_key(&mut self) -> Result<String, Box<dyn Error>> {
        match &self.public_key {
            Some(key) => Ok(key.clone()),
            None => self.fetch_and_store_public_key().await,
        }
    }
}

// Global configuration singleton
static DEFAULT_CONFIG: OnceLock<HessraConfig> = OnceLock::new();

/// Set the default global configuration
///
/// This configuration will be used by the macros when no explicit
/// configuration is provided. Returns an error if a default
/// configuration is already set.
pub fn set_default_config(config: HessraConfig) -> Result<(), ConfigError> {
    config.validate()?;
    DEFAULT_CONFIG
        .set(config)
        .map_err(|_| ConfigError::AlreadyInitialized)
}

/// Get the default global configuration, if set
pub fn get_default_config() -> Option<&'static HessraConfig> {
    DEFAULT_CONFIG.get()
}

/// Try to load a default configuration from standard locations
///
/// This function attempts to load a configuration from:
/// 1. Environment variables with the prefix "HESSRA"
/// 2. A file at ./hessra.json
/// 3. A file at ~/.hessra/config.json
/// 4. A file at /etc/hessra/config.json
/// 5. If the "toml" feature is enabled, it also tries TOML files with the same paths
///
/// Returns None if no configuration could be found.
///
/// # Example
///
/// ```no_run
/// use hessra_sdk::{try_load_default_config, set_default_config};
///
/// // Try to load a default configuration from standard locations
/// if let Some(config) = try_load_default_config() {
///     // Use the loaded configuration
///     set_default_config(config).expect("Failed to set default configuration");
/// } else {
///     eprintln!("No configuration found in standard locations");
/// }
/// ```
pub fn try_load_default_config() -> Option<HessraConfig> {
    // Try to load from environment variables
    if let Ok(config) = HessraConfig::from_env_or_file("HESSRA") {
        return Some(config);
    }

    // Try to load from common file locations
    let paths = [
        "./hessra.json",
        "~/.hessra/config.json",
        "/etc/hessra/config.json",
    ];

    for path in paths.iter() {
        let expanded_path = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                home.join(stripped)
            } else {
                continue;
            }
        } else {
            Path::new(path).to_path_buf()
        };

        if expanded_path.exists() {
            if let Ok(config) = HessraConfig::from_file(&expanded_path) {
                return Some(config);
            }
        }
    }

    {
        // Try to load from TOML files
        let toml_paths = [
            "./hessra.toml",
            "~/.hessra/config.toml",
            "/etc/hessra/config.toml",
        ];

        for path in toml_paths.iter() {
            let expanded_path = if let Some(stripped) = path.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(stripped)
                } else {
                    continue;
                }
            } else {
                Path::new(path).to_path_buf()
            };

            if expanded_path.exists() {
                if let Ok(config) = HessraConfig::from_toml(&expanded_path) {
                    return Some(config);
                }
            }
        }
    }

    None
}
