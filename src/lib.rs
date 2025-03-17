//! # Hessra SDK
//!
//! A Rust client library for interacting with Hessra authentication services.
//!
//! The Hessra SDK provides a robust and flexible way to request and verify authentication tokens
//! for protected resources using mutual TLS (mTLS) for secure client authentication.
//!
//! ## Features
//!
//! - **Flexible configuration**: Load configuration from various sources (environment variables, files, etc.)
//! - **Protocol support**: HTTP/1.1 support with optional HTTP/3 via feature flag
//! - **Mutual TLS**: Strong security with client and server certificate validation
//! - **Token management**: Request and verify authorization tokens
//! - **Local verification**: Retrieve and store public keys for local token verification
//! - **Procedural macros**: Easy function protection with authorization macros
//!
//! ## Feature Flags
//!
//! - `http3`: Enables HTTP/3 protocol support
//! - `toml`: Enables configuration loading from TOML files
//!
//! ## Basic Usage
//!
//! ```rust
//! use hessra_sdk::{HessraClient, Protocol};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a client with HTTP/1.1
//! let client = HessraClient::builder()
//!     .base_url("test.hessra.net")
//!     .port(443)
//!     .protocol(Protocol::Http1)
//!     .mtls_cert(include_str!("../certs/client.crt"))
//!     .mtls_key(include_str!("../certs/client.key"))
//!     .server_ca(include_str!("../certs/ca.crt"))
//!     .build()?;
//!
//! // Request a token for a specific resource
//! let resource = "my-protected-resource".to_string();
//! let token = client.request_token(resource.clone()).await?;
//!
//! // Later, verify the token
//! let verification_result = client.verify_token(token, resource).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuration
//!
//! The SDK offers multiple ways to configure the client:
//!
//! ### Using HessraConfigBuilder
//!
//! ```rust
//! use hessra_sdk::{HessraConfigBuilder, Protocol};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a configuration using the builder pattern
//! let config = HessraConfigBuilder::new()
//!     .base_url("https://test.hessra.net")
//!     .port(443)
//!     .protocol(Protocol::Http1)
//!     .mtls_cert(include_str!("../certs/client.crt"))
//!     .mtls_key(include_str!("../certs/client.key"))
//!     .server_ca(include_str!("../certs/ca.crt"))
//!     .build()?;
//!
//! // Use the configuration to create a client
//! let client = config.create_client()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Using environment variables
//!
//! When using `from_env()` or `from_env_or_file()`, the following variables are expected:
//!
//! ```text
//! ${PREFIX}_BASE_URL     - Base URL of the Hessra service
//! ${PREFIX}_PORT         - Optional port number
//! ${PREFIX}_CERT         - Client certificate (PEM) or path to certificate file
//! ${PREFIX}_KEY          - Client private key (PEM) or path to key file
//! ${PREFIX}_SERVER_CA    - Server CA certificate (PEM) or path to CA file
//! ${PREFIX}_PROTOCOL     - Optional protocol (HTTP1 or HTTP3)
//! ```
//!
//! When using `from_env()` or `from_env_or_file()`, the following variables are expected:
//!
//! - `{PREFIX}_BASE_URL`: The base URL of the Hessra service
//! - `{PREFIX}_PORT`: The port to connect to (optional)
//! - `{PREFIX}_MTLS_CERT` or `{PREFIX}_MTLS_CERT_FILE`: The mTLS certificate
//! - `{PREFIX}_MTLS_KEY` or `{PREFIX}_MTLS_KEY_FILE`: The mTLS key
//! - `{PREFIX}_SERVER_CA` or `{PREFIX}_SERVER_CA_FILE`: The server CA certificate
//! - `{PREFIX}_PROTOCOL`: Either "http1" or "http3" (optional, defaults to "http1")
//! - `{PREFIX}_PUBLIC_KEY` or `{PREFIX}_PUBLIC_KEY_FILE`: The server's public key for token verification (optional)
//!
//! ### Using direct instantiation
//!
//! ```rust
//! use hessra_sdk::{HessraConfig, Protocol, set_default_config};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Manual configuration
//! let config = HessraConfig::new(
//!     "https://test.hessra.net",
//!     Some(443),
//!     Protocol::Http1,
//!     include_str!("../certs/client.crt"),
//!     include_str!("../certs/client.key"),
//!     include_str!("../certs/ca.crt"),
//! );
//!
//! // 2. From a JSON file
//! let config = HessraConfig::from_file("./config.json")?;
//!
//! // 3. From environment variables
//! let config = HessraConfig::from_env("HESSRA")?;
//!
//! // 4. From environment variables with file references
//! let config = HessraConfig::from_env_or_file("HESSRA")?;
//!
//! // 5. Global configuration
//! set_default_config(config.clone())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Public Key for Token Verification
//!
//! The SDK provides methods to obtain and manage the public key used by the Hessra service for signing tokens:
//!
//! ```rust
//! use hessra_sdk::{HessraClient, HessraConfig, Protocol};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Method 1: Fetch the public key without creating a client (no mTLS required)
//! let public_key = HessraClient::fetch_public_key("test.hessra.net", Some(443), include_str!("../certs/ca.crt")).await?;
//!
//! // Method 2: Use an existing client to fetch the public key
//! let client = HessraClient::builder()
//!     .base_url("test.hessra.net")
//!     .port(443)
//!     .protocol(Protocol::Http1)
//!     .mtls_cert(include_str!("../certs/client.crt"))
//!     .mtls_key(include_str!("../certs/client.key"))
//!     .server_ca(include_str!("../certs/ca.crt"))
//!     .build()?;
//!
//! let public_key = client.get_public_key().await?;
//!
//! // Method 3: Store the public key in the configuration
//! let mut config = HessraConfig::new(
//!     "https://test.hessra.net",
//!     Some(443),
//!     Protocol::Http1,
//!     include_str!("../certs/client.crt"),
//!     include_str!("../certs/client.key"),
//!     include_str!("../certs/ca.crt"),
//! );
//!
//! // Fetch and store the public key
//! config.fetch_and_store_public_key().await?;
//!
//! // Later, use the stored public key or fetch it if not available
//! let public_key = config.get_or_fetch_public_key().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Using Procedural Macros
//!
//! The `hessra-macros` crate provides macros for easy integration:
//!
//! ```rust
//! use hessra_macros::{request_authorization, authorize};
//! use hessra_sdk::HessraConfig;
//!
//! // Request authorization before executing a function
//! #[request_authorization("my-resource", config)]
//! async fn protected_function(config: &HessraConfig) {
//!     // Function is called after token is obtained
//! }
//!
//! // Verify token before executing a function
//! #[authorize("my-resource")]
//! async fn authorized_function(token: String) {
//!     // Function is called only if token is valid
//! }
//! ```
//!

//use crate::config::get_default_config;
use crate::verify::verify_biscuit_local;
use base64::prelude::*;
use biscuit_auth::PublicKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

// Re-export configuration module
mod config;
pub use config::*;

// Import verification module
mod verify;

/// Request payload for requesting an authorization token
#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    /// The resource identifier to request authorization for
    pub resource: String,
}

/// Request payload for verifying an authorization token
#[derive(Serialize, Deserialize)]
pub struct VerifyTokenRequest {
    /// The authorization token to verify
    pub token: String,
    /// The resource identifier to verify authorization against
    pub resource: String,
}

/// Response from a token request operation
#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    /// Response message from the server
    pub response_msg: String,
    /// The issued token, if successful
    pub token: Option<String>,
}

/// Response from a token verification operation
#[derive(Serialize, Deserialize)]
pub struct VerifyTokenResponse {
    /// Response message from the server
    pub response_msg: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub response_msg: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyServiceChainTokenRequest {
    pub token: String,
    pub resource: String,
    pub component: Option<String>,
}

#[cfg(feature = "http3")]
use {
    bytes::{Buf, Bytes},
    h3_quinn::quinn::{self, Endpoint},
    quinn_proto::crypto::rustls::QuicClientConfig,
    rustls::pki_types::CertificateDer,
    rustls::RootCertStore,
    rustls_pemfile::certs,
    std::io::BufReader,
    std::net::SocketAddr,
    std::sync::Arc,
};

/// Base configuration for Hessra clients
///
/// This struct contains the common configuration parameters used by all Hessra client types.
/// It includes connection details and certificates for mutual TLS authentication.
#[derive(Clone)]
pub struct BaseConfig {
    /// Base URL of the Hessra service (without protocol scheme)
    base_url: String,
    /// Optional port to connect to
    port: Option<u16>,
    /// mTLS private key in PEM format
    mtls_key: String,
    /// mTLS client certificate in PEM format
    mtls_cert: String,
    /// Server CA certificate in PEM format
    server_ca: String,
    /// Public key for token verification in PEM format
    public_key: Option<String>,
}

impl BaseConfig {
    /// Get the formatted base URL, with port if specified
    fn get_base_url(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.base_url, port),
            None => self.base_url.clone(),
        }
    }
}

/// HTTP/1.1 client implementation
pub struct Http1Client {
    /// Base configuration
    config: BaseConfig,
    /// reqwest HTTP client with mTLS configured
    client: Client,
}

/// HTTP/3 client implementation (only available with the "http3" feature)
#[cfg(feature = "http3")]
pub struct Http3Client {
    /// Base configuration
    config: BaseConfig,
    /// QUIC endpoint for HTTP/3 connections
    endpoint: Endpoint,
}

/// The main Hessra client type providing token request and verification
///
/// This client handles the communication with the Hessra service.
/// It can use either HTTP/1.1 or HTTP/3 (if the feature is enabled).
///
/// # Example
///
/// ```
/// use hessra_sdk::{HessraClient, Protocol};
/// use std::error::Error;
///
/// # async fn example() -> Result<(), Box<dyn Error>> {
/// // Create a client using the builder pattern
/// let client = HessraClient::builder()
///     .base_url("test.hessra.net")
///     .port(443)
///     .protocol(Protocol::Http1)
///     .mtls_cert("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
///     .mtls_key("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
///     .server_ca("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
///     .build()?;
///
/// // Request a token
/// let token = client.request_token("my-resource".to_string()).await?;
///
/// // Verify a token
/// let result = client.verify_token(token, "my-resource".to_string()).await?;
/// # Ok(())
/// # }
/// ```
pub enum HessraClient {
    /// HTTP/1.1 client
    Http1(Http1Client),
    /// HTTP/3 client (only available with the "http3" feature)
    #[cfg(feature = "http3")]
    Http3(Http3Client),
}

/// Builder for creating Hessra clients
///
/// Provides a fluent interface for configuring and creating a `HessraClient`.
///
/// # Example
///
/// ```
/// use hessra_sdk::{HessraClient, Protocol};
///
/// # fn example() {
/// let client_builder = HessraClient::builder()
///     .base_url("test.example.com")
///     .port(8443)
///     .protocol(Protocol::Http1)
///     .mtls_cert("CERT")
///     .mtls_key("KEY")
///     .server_ca("CA");
///
/// // Build the client
/// let client = client_builder.build().expect("Failed to build client");
/// # }
/// ```
pub struct HessraClientBuilder {
    /// Base configuration being built
    config: BaseConfig,
    /// Protocol to use for the client
    protocol: Protocol,
}

/// Protocol options for Hessra client communication
///
/// Determines which protocol the client will use to communicate with
/// the Hessra service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Protocol {
    /// HTTP/1.1 protocol (always available)
    Http1,
    /// HTTP/3 protocol (only available with the "http3" feature)
    #[cfg(feature = "http3")]
    Http3,
}

// Add HTTP/3 ALPN constant
#[cfg(feature = "http3")]
static ALPN_QUIC_HTTP3: &[u8] = b"h3";

impl HessraClientBuilder {
    /// Create a new client builder with default configuration
    pub fn new() -> Self {
        HessraClientBuilder {
            config: BaseConfig {
                base_url: "".to_string(),
                port: None,
                mtls_key: "".to_string(),
                mtls_cert: "".to_string(),
                server_ca: "".to_string(),
                public_key: None,
            },
            protocol: Protocol::Http1,
        }
    }

    /// Create a new client builder from a HessraConfig
    pub fn from_config(mut self, config: &HessraConfig) -> Self {
        self.config = BaseConfig {
            base_url: config.base_url.clone(),
            port: config.port,
            mtls_key: config.mtls_key.clone(),
            mtls_cert: config.mtls_cert.clone(),
            server_ca: config.server_ca.clone(),
            public_key: config.public_key.clone(),
        };
        self
    }

    /// Set the base URL for the Hessra service
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = base_url.into();
        self
    }

    /// Set the mTLS private key (in PEM format)
    pub fn mtls_key(mut self, mtls_key: impl Into<String>) -> Self {
        self.config.mtls_key = mtls_key.into();
        self
    }

    /// Set the mTLS client certificate (in PEM format)
    pub fn mtls_cert(mut self, mtls_cert: impl Into<String>) -> Self {
        self.config.mtls_cert = mtls_cert.into();
        self
    }

    /// Set the server CA certificate (in PEM format)
    pub fn server_ca(mut self, server_ca: impl Into<String>) -> Self {
        self.config.server_ca = server_ca.into();
        self
    }

    /// Set the port for the Hessra service
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = Some(port);
        self
    }

    /// Set the protocol to use (HTTP/1.1 or HTTP/3)
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Build an HTTP/1.1 client from the configuration
    fn build_http1(&self) -> Result<Http1Client, Box<dyn Error>> {
        let mut identity_pem = Vec::new();
        identity_pem.extend(self.config.mtls_cert.as_bytes());
        identity_pem.extend(self.config.mtls_key.as_bytes());

        let client = Client::builder()
            .identity(reqwest::Identity::from_pem(&identity_pem)?)
            .add_root_certificate(reqwest::Certificate::from_pem(
                self.config.server_ca.as_bytes(),
            )?)
            .use_rustls_tls()
            .build()?;

        Ok(Http1Client {
            config: self.config.clone(),
            client,
        })
    }

    /// Build an HTTP/3 client from the configuration (only available with the "http3" feature)
    #[cfg(feature = "http3")]
    fn build_http3(&self) -> Result<Http3Client, Box<dyn Error>> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        // Parse root certificate
        let mut root_store = RootCertStore::empty();
        let mut reader = BufReader::new(self.config.server_ca.as_bytes());
        let certs = certs(&mut reader);
        for cert in certs {
            root_store.add(cert?)?;
        }

        // Parse client certificate chain
        let cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.config.mtls_cert.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| format!("invalid PEM-encoded certificate: {}", e))?;

        if cert_chain.is_empty() {
            return Err("No client certificates found".into());
        }

        // Parse private key
        let key = rustls_pemfile::private_key(&mut self.config.mtls_key.as_bytes())
            .map_err(|e| format!("malformed private key: {}", e))?
            .ok_or_else(|| Box::<dyn Error>::from("no private keys found"))?;

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| format!("Failed to build client crypto: {}", e))?;

        // Set ALPN protocol
        client_crypto.alpn_protocols = vec![ALPN_QUIC_HTTP3.into()];
        client_crypto.enable_early_data = true;

        let client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .map_err(|e| format!("Failed to create QUIC config: {}", e))?,
        ));

        let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Http3Client {
            config: self.config.clone(),
            endpoint,
        })
    }

    /// Build a Hessra client from the configuration
    ///
    /// Creates either an HTTP/1.1 or HTTP/3 client based on the protocol setting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate or key data is invalid
    /// - TLS configuration fails
    /// - Network binding fails
    /// - Other system errors occur
    pub fn build(self) -> Result<HessraClient, Box<dyn Error>> {
        match self.protocol {
            Protocol::Http1 => Ok(HessraClient::Http1(self.build_http1()?)),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Ok(HessraClient::Http3(self.build_http3()?)),
        }
    }
}

impl Default for HessraClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http3")]
impl Http3Client {
    async fn send_request<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
    ) -> Result<R, Box<dyn Error>>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let addr = tokio::net::lookup_host((
            self.config.base_url.as_str(),
            self.config.port.unwrap_or(443),
        ))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

        let connection = self
            .endpoint
            .connect(addr, &self.config.base_url)?
            .await
            .map_err(|e| format!("Failed to connect: {}", e))?;

        let quinn_conn = h3_quinn::Connection::new(connection);
        let (_driver, mut send_request) = h3::client::new(quinn_conn).await?;

        let request = http::Request::builder()
            .uri(format!(
                "https://{}/{}",
                self.config.get_base_url(),
                endpoint
            ))
            .header("content-type", "application/json")
            .body(())?;

        let mut stream = send_request.send_request(request).await?;
        let body = serde_json::to_string(request_body)?;
        stream.send_data(Bytes::from(body)).await?;
        stream.finish().await?;

        let _response = stream.recv_response().await?;
        let mut response_data = Vec::new();

        while let Some(chunk) = stream.recv_data().await? {
            response_data.extend_from_slice(chunk.chunk());
        }

        let response: R = serde_json::from_slice(&response_data)?;
        Ok(response)
    }
}

impl Http1Client {
    async fn send_request<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
    ) -> Result<R, Box<dyn Error>>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(format!(
                "https://{}/{}",
                self.config.get_base_url(),
                endpoint
            ))
            .json(request_body)
            .send()
            .await?
            .json::<R>()
            .await?;

        Ok(response)
    }
}

impl HessraClient {
    /// Create a new client builder
    ///
    /// This is the recommended way to create a new Hessra client.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hessra_sdk::{HessraClient, Protocol};
    ///
    /// let client = HessraClient::builder()
    ///     .base_url("test.hessra.net")
    ///     .port(443)
    ///     .protocol(Protocol::Http1)
    ///     .mtls_cert("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
    ///     .mtls_key("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
    ///     .server_ca("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
    ///     .build()
    ///     .expect("Failed to build client");
    /// ```
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::new()
    }

    /// Fetch the public key from the Hessra service
    ///
    /// This method retrieves the public key used by the Hessra service to sign tokens.
    /// Unlike other methods, this endpoint does not require mTLS authentication.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Hessra service
    /// * `port` - Optional port to connect to
    /// * `server_ca` - Server CA certificate in PEM format for server validation
    ///
    /// # Returns
    ///
    /// The public key as a string, or an error if the request failed
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server_ca = include_str!("../certs/ca.crt");
    /// let public_key = hessra_sdk::HessraClient::fetch_public_key(
    ///     "test.hessra.net",
    ///     Some(443),
    ///     server_ca,
    /// ).await?;
    /// // Store the public key for later use
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_public_key(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, Box<dyn Error>> {
        let base_url = base_url.into();
        let url = match port {
            Some(port) => format!("https://{}:{}/public_key", base_url, port),
            None => format!("https://{}/public_key", base_url),
        };

        // Create a client builder
        let mut client_builder = reqwest::Client::builder().use_rustls_tls();

        // Add server CA
        let ca_str = server_ca.into();
        client_builder =
            client_builder.add_root_certificate(reqwest::Certificate::from_pem(ca_str.as_bytes())?);

        // Build the client
        let client = client_builder.build()?;

        let response = client
            .get(&url)
            .send()
            .await?
            .json::<PublicKeyResponse>()
            .await?;

        Ok(response.public_key)
    }

    /// Fetch the public key using HTTP/3
    ///
    /// This is an alternative implementation that uses HTTP/3 to fetch
    /// the public key from the Hessra service.
    #[cfg(feature = "http3")]
    pub async fn fetch_public_key_http3(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, Box<dyn Error>> {
        use {
            bytes::Buf,
            h3_quinn::quinn::{ClientConfig, Endpoint},
            quinn_proto::crypto::rustls::QuicClientConfig,
            rustls::{pki_types::CertificateDer, RootCertStore},
            std::net::SocketAddr,
            std::sync::Arc,
        };

        let base_url = base_url.into();
        let url = match port {
            Some(port) => format!("https://{}:{}/public_key", base_url, port),
            None => format!("https://{}/public_key", base_url),
        };

        // Set up client config
        let mut root_store = RootCertStore::empty();

        // Add server CA
        let ca_str = server_ca.into();
        let mut ca_reader = std::io::Cursor::new(ca_str);

        let certs = rustls_pemfile::certs(&mut ca_reader)
            .filter_map(Result::ok)
            .map(CertificateDer::from)
            .collect::<Vec<_>>();

        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed to add cert: {}", e))?;
        }

        // Create rustls client config
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocol
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];

        // Convert to quinn client config
        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .map_err(|e| format!("Failed to create QUIC config: {}", e))?,
        ));

        // Create endpoint
        let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        // Connect to server
        let port = port.unwrap_or(443);
        let remote_addr = format!("{}:{}", base_url, port).parse()?;

        let connection = endpoint
            .connect(remote_addr, &base_url)?
            .await
            .map_err(|e| format!("Failed to connect: {}", e))?;

        // Set up HTTP/3 client
        let h3_connection = h3_quinn::Connection::new(connection);
        let (driver, mut send_request) = h3::client::new(h3_connection).await?;

        // Spawn driver task to process connection events
        tokio::spawn(async move {
            let _ = driver; // Driver runs when dropped
        });

        // Create request
        let request = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("content-type", "application/json")
            .body(())?;

        // Send request
        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;

        // Get response
        let response = stream.recv_response().await?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()).into());
        }

        // Read response body
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            body.extend_from_slice(chunk.chunk());
        }

        // Parse response
        let response: PublicKeyResponse = serde_json::from_slice(&body)?;
        Ok(response.public_key)
    }

    /// Request an authorization token for a resource
    ///
    /// Sends a request to the Hessra service to obtain an authorization token
    /// for the specified resource.
    ///
    /// # Arguments
    ///
    /// * `resource` - The resource identifier to request authorization for
    ///
    /// # Returns
    ///
    /// The authorization token as a string, or an error if the request failed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection to the server fails
    /// - The server returns an error response
    /// - The response cannot be parsed
    /// - No token is returned in the response
    pub async fn request_token(&self, resource: String) -> Result<String, Box<dyn Error>> {
        let token_request = TokenRequest { resource };

        let response: TokenResponse = match self {
            HessraClient::Http1(client) => {
                client.send_request("request_token", &token_request).await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client.send_request("request_token", &token_request).await?
            }
        };

        response
            .token
            .ok_or_else(|| "Failed to obtain token: server returned empty token".into())
    }

    /// Verify an authorization token for a resource
    ///
    /// Sends a request to the Hessra service to verify an authorization token
    /// for the specified resource.
    ///
    /// # Arguments
    ///
    /// * `token` - The authorization token to verify, Base64 encoded
    /// * `resource` - The resource identifier to verify authorization against
    ///
    /// # Returns
    ///
    /// The verification response message, or an error if verification failed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection to the server fails
    /// - The server returns an error response
    /// - The response cannot be parsed
    pub async fn verify_token(
        &self,
        token: String,
        resource: String,
    ) -> Result<String, Box<dyn Error>> {
        // First try to get the public key for local verification
        let public_key = match self {
            HessraClient::Http1(client) => client.config.public_key.clone(),
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => client.config.public_key.clone(),
        };

        // If we have a public key, try local verification
        if let Some(pk_str) = public_key {
            // Try to parse the public key
            match PublicKey::from_pem(&pk_str) {
                Ok(public_key) => {
                    // Convert the token string to bytes
                    let token_bytes = match BASE64_STANDARD.decode(token.clone()) {
                        Ok(token) => token,
                        Err(e) => {
                            return Err(format!("Failed to decode token from Base64: {}", e).into());
                        }
                    };

                    // Try local verification
                    match verify_biscuit_local(
                        token_bytes,
                        public_key,
                        "user".to_string(),
                        resource.clone(),
                    ) {
                        Ok(_) => return Ok("Token verified locally".to_string()),
                        Err(e) => {
                            // If local verification fails due to a token error, return the error
                            // Otherwise, fall back to remote verification
                            if e.to_string().contains("token") {
                                return Err(
                                    format!("Local token verification failed: {}", e).into()
                                );
                            }
                            // If the error is not token-related, we'll fall back to remote verification
                        }
                    }
                }
                Err(_) => {
                    // Failed to parse public key, fall back to remote verification
                    // This is a silent fallback as it's a recoverable situation
                }
            }
        }

        // Fall back to remote verification if local verification is not possible or failed
        let verify_token_request = VerifyTokenRequest {
            token,
            resource: resource.clone(),
        };

        let response: VerifyTokenResponse = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request("verify_token", &verify_token_request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request("verify_token", &verify_token_request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Get the public key from the Hessra service
    ///
    /// This method fetches the public key used by the Hessra service to sign tokens.
    /// Unlike other methods, this endpoint does not require mTLS authentication.
    ///
    /// # Returns
    ///
    /// The public key as a string, or an error if the request failed
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use hessra_sdk::{HessraClient, Protocol};
    /// # let client = HessraClient::builder()
    /// #    .base_url("test.hessra.net")
    /// #    .port(443)
    /// #    .protocol(Protocol::Http1)
    /// #    .mtls_cert("CERT")
    /// #    .mtls_key("KEY")
    /// #    .server_ca("CA")
    /// #    .build()?;
    /// let public_key = client.get_public_key().await?;
    /// // Store the public key for later use
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_public_key(&self) -> Result<String, Box<dyn Error>> {
        let server = self.get_base_url();
        let port = self.get_port();
        let server_ca = match self {
            HessraClient::Http1(client) => client.config.server_ca.clone(),
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => client.config.server_ca.clone(),
        };

        #[cfg(feature = "http3")]
        {
            match self {
                HessraClient::Http1(_) => Self::fetch_public_key(server, port, server_ca).await,
                HessraClient::Http3(_) => {
                    Self::fetch_public_key_http3(server, port, server_ca).await
                }
            }
        }

        #[cfg(not(feature = "http3"))]
        {
            Self::fetch_public_key(server, port, server_ca).await
        }
    }

    /// Get the base URL for the Hessra service
    fn get_base_url(&self) -> String {
        match self {
            HessraClient::Http1(client) => client.config.base_url.clone(),
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => client.config.base_url.clone(),
        }
    }

    /// Get the port for the Hessra service
    fn get_port(&self) -> Option<u16> {
        match self {
            HessraClient::Http1(client) => client.config.port,
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => client.config.port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_config_get_base_url_with_port() {
        let config = BaseConfig {
            base_url: "example.com".to_string(),
            port: Some(8443),
            mtls_key: "".to_string(),
            mtls_cert: "".to_string(),
            server_ca: "".to_string(),
            public_key: None,
        };

        assert_eq!(config.get_base_url(), "example.com:8443");
    }

    #[test]
    fn test_base_config_get_base_url_without_port() {
        let config = BaseConfig {
            base_url: "example.com".to_string(),
            port: None,
            mtls_key: "".to_string(),
            mtls_cert: "".to_string(),
            server_ca: "".to_string(),
            public_key: None,
        };

        assert_eq!(config.get_base_url(), "example.com");
    }

    #[test]
    fn test_builder_methods() {
        let builder = HessraClientBuilder::new()
            .base_url("test.example.com")
            .port(8443)
            .mtls_cert("CERT")
            .mtls_key("KEY")
            .server_ca("CA");

        assert_eq!(builder.config.base_url, "test.example.com");
        assert_eq!(builder.config.port, Some(8443));
        assert_eq!(builder.config.mtls_cert, "CERT");
        assert_eq!(builder.config.mtls_key, "KEY");
        assert_eq!(builder.config.server_ca, "CA");
    }

    #[tokio::test]
    #[ignore] // Ignore this test by default as it requires a real server
    async fn test_fetch_public_key() {
        // This test requires a real server to be running
        let public_key = HessraClient::fetch_public_key("test.hessra.net", Some(443), "CA")
            .await
            .expect("Failed to fetch public key");

        assert!(!public_key.is_empty(), "Public key should not be empty");
    }
}
