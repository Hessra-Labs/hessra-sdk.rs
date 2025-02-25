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
///     "https://auth.example.com", // base URL
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
/// // HESSRA_BASE_URL=https://auth.example.com
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
///     "https://auth.example.com",
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
}

fn default_protocol() -> Protocol {
    Protocol::Http1
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
        }
    }

    /// Create a configuration from a JSON file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_content = fs::read_to_string(path)?;
        let config: HessraConfig = serde_json::from_str(&file_content)?;
        config.validate()?;
        Ok(config)
    }

    /// Create a configuration from a TOML file
    #[cfg(feature = "toml")]
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
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hessra_sdk::HessraConfig;
    /// use std::env;
    ///
    /// // Set environment variables (in a real app, these would be set externally)
    /// env::set_var("APP_BASE_URL", "https://auth.example.com");
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

        let config = HessraConfig {
            base_url,
            port,
            protocol,
            mtls_cert,
            mtls_key,
            server_ca,
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
    /// env::set_var("SERVICE_BASE_URL", "https://auth.example.com");
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

        // Try to load certificate from environment variable or file
        let mtls_cert = match env::var(format!("{}_MTLS_CERT", prefix)) {
            Ok(cert) => cert,
            Err(std::env::VarError::NotPresent) => {
                // Try to load from file
                match env::var(format!("{}_MTLS_CERT_FILE", prefix)) {
                    Ok(file_path) => fs::read_to_string(file_path)?,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };

        // Try to load key from environment variable or file
        let mtls_key = match env::var(format!("{}_MTLS_KEY", prefix)) {
            Ok(key) => key,
            Err(std::env::VarError::NotPresent) => {
                // Try to load from file
                match env::var(format!("{}_MTLS_KEY_FILE", prefix)) {
                    Ok(file_path) => fs::read_to_string(file_path)?,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };

        // Try to load server CA from environment variable or file
        let server_ca = match env::var(format!("{}_SERVER_CA", prefix)) {
            Ok(ca) => ca,
            Err(std::env::VarError::NotPresent) => {
                // Try to load from file
                match env::var(format!("{}_SERVER_CA_FILE", prefix)) {
                    Ok(file_path) => fs::read_to_string(file_path)?,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };

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

        let config = HessraConfig {
            base_url,
            port,
            protocol,
            mtls_cert,
            mtls_key,
            server_ca,
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

        // Validate URL format
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(ConfigError::ParseError(format!(
                "Base URL must start with http:// or https://: {}",
                self.base_url
            )));
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

    #[cfg(feature = "toml")]
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
