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
//! let subject = "user123".to_string();
//! let verification_result = client.verify_token(token, subject, resource).await?;
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
/// # Service Chain Authorization
///
/// Service chains allow for a token to pass through multiple service nodes,
/// with each node attesting that it has processed the request. This is useful
/// for building secure microservice architectures where each service in a
/// chain must validate and attest to the request before it proceeds to the next service.
///
/// ## Example: Verifying a Service Chain Token
///
/// ```rust
/// use hessra_sdk::{HessraClient, Protocol, ServiceNode, ServiceChain};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a client
/// let client = HessraClient::builder()
///     .base_url("test.hessra.net")
///     .port(443)
///     .protocol(Protocol::Http1)
///     .mtls_cert(include_str!("../certs/client.crt"))
///     .mtls_key(include_str!("../certs/client.key"))
///     .server_ca(include_str!("../certs/ca.crt"))
///     .public_key(include_str!("../certs/service_public_key.pem"))
///     .personal_keypair(include_str!("../certs/node1.key"))
///     .build()?;
///
/// // Define the service chain nodes (order matters)
/// let service_chain = ServiceChain::new()
///     .with_node(ServiceNode::new(
///         "auth-service",
///         "ed25519/1234567890abcdef"
///     ))
///     .with_node(ServiceNode::new(
///         "payment-service",
///         "ed25519/abcdef1234567890"
///     ));
///
/// // Alternatively, you can use the builder pattern:
/// // let auth_node = ServiceNode::builder()
/// //     .name("auth-service")
/// //     .public_key("ed25519/1234567890abcdef")
/// //     .build()?;
/// // let payment_node = ServiceNode::builder()
/// //     .name("payment-service")
/// //     .public_key("ed25519/abcdef1234567890")
/// //     .build()?;
/// // let service_chain = ServiceChain::with_nodes(vec![auth_node, payment_node]);
///
/// // Verify a service chain token - this will verify nodes up to but not including "payment-service"
/// let token = "base64-encoded-token".to_string();
/// let resource = "my-protected-resource".to_string();
/// let subject = "user123".to_string();
/// let component = Some("payment-service".to_string()); // Current node in the chain
///
/// let result = client.verify_service_chain_token(
///     token.clone(),
///     subject.clone(),
///     resource.clone(),
///     component,
///     Some(&service_chain)
/// ).await?;
///
/// // For the last node in the chain, verify the entire chain
/// let result = client.verify_service_chain_token(
///     token,
///     subject,
///     resource,
///     None, // No current component means verify the entire chain
///     Some(&service_chain)
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Example: Attenuating a Service Chain Token
///
/// ```rust
/// use hessra_sdk::{HessraClient, Protocol, ServiceNode, ServiceChain};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a client with a personal keypair
/// let client = HessraClient::builder()
///     .base_url("test.hessra.net")
///     .port(443)
///     .protocol(Protocol::Http1)
///     .mtls_cert(include_str!("../certs/client.crt"))
///     .mtls_key(include_str!("../certs/client.key"))
///     .server_ca(include_str!("../certs/ca.crt"))
///     .public_key(include_str!("../certs/service_public_key.pem"))
///     .personal_keypair(include_str!("../certs/node1.key"))
///     .build()?;
///
/// // Define the service chain
/// let service_chain = ServiceChain::new()
///     .with_node(ServiceNode::new("auth-service", "ed25519/1234567890abcdef"))
///     .with_node(ServiceNode::new("payment-service", "ed25519/abcdef1234567890"));
///
/// // First, verify the token for the current component
/// let token = "base64-encoded-token".to_string();
/// let subject = "user123".to_string();
/// let resource = "my-protected-resource".to_string();
/// let component = "payment-service".to_string();
///
/// // Verify the token for this component
/// client.verify_service_chain_token(
///     token.clone(),
///     subject.clone(),
///     resource.clone(),
///     Some(component.clone()),
///     Some(&service_chain)
/// ).await?;
///
/// // Add this component's attestation to the token
/// let attenuated_token = client.attenuate_service_chain_token(
///     token,
///     resource,
/// )?;
///
/// // Now the attenuated token can be passed to the next service in the chain
/// // The next service will be able to verify that this service has processed the request
/// # Ok(())
/// # }
/// ```
//use crate::config::get_default_config;
use crate::verify::verify_biscuit_local;
use base64::prelude::*;
use biscuit_auth::{KeyPair, PublicKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

// Re-export configuration module
mod config;
pub use config::*;

// Import verification module
mod verify;
use crate::verify::verify_service_chain_biscuit_local;

// Import attestation module for service chains
mod attenuate;
use crate::attenuate::add_service_node_attenuation;

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
    /// The subject identifier to verify against
    pub subject: String,
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
    /// Personal keypair for service chain attestation
    personal_keypair: Option<String>,
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
/// let subject = "user123".to_string();
/// let result = client.verify_token(token, subject, "my-resource".to_string()).await?;
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
                personal_keypair: None,
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
            personal_keypair: config.personal_keypair.clone(),
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

    /// Set the public key for token verification (in PEM format)
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.config.public_key = Some(public_key.into());
        self
    }

    /// Set the personal keypair for service chain attestation
    pub fn personal_keypair(mut self, keypair: impl Into<String>) -> Self {
        self.config.personal_keypair = Some(keypair.into());
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
    /// * `subject` - The subject identifier to verify against
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
        subject: String,
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
                        subject.clone(),
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
            subject: subject.clone(),
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

    /// Verify a service chain token
    ///
    /// This method verifies a service chain token either locally or by calling the server.
    /// It first attempts local verification if a public key and service chain are provided.
    /// If local verification fails or can't be performed, it falls back to remote verification.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to verify
    /// * `resource` - The resource identifier the token is for
    /// * `component` - Optional component name of the current node in the chain
    /// * `service_chain` - Optional service chain configuration
    ///
    /// # Returns
    ///
    /// A result containing the verification response or an error
    pub async fn verify_service_chain_token(
        &self,
        token: String,
        subject: String,
        resource: String,
        component: Option<String>,
        service_chain: Option<&ServiceChain>,
    ) -> Result<String, Box<dyn Error>> {
        // Try local verification first if we have all the necessary data
        let public_key = match self {
            HessraClient::Http1(client) => client.config.public_key.clone(),
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => client.config.public_key.clone(),
        };

        // If we have a public key and service nodes, try local verification
        if let (Some(pk_str), Some(chain)) = (public_key, service_chain) {
            let nodes = chain.to_internal();

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
                    match verify_service_chain_biscuit_local(
                        token_bytes,
                        public_key,
                        subject,
                        resource.clone(),
                        nodes,
                        component.clone(),
                    ) {
                        Ok(_) => return Ok("Service chain token verified locally".to_string()),
                        Err(e) => {
                            // If it's a token-related error, return it
                            if e.to_string().contains("token") {
                                return Err(
                                    format!("Local token verification failed: {}", e).into()
                                );
                            }
                            // Otherwise fall back to remote verification
                        }
                    }
                }
                Err(_) => {
                    // Failed to parse public key, fall back to remote verification
                }
            }
        }

        // Fall back to remote verification
        let verify_request = VerifyServiceChainTokenRequest {
            token,
            resource,
            component,
        };

        let response: VerifyTokenResponse = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request("verify_service_chain_token", &verify_request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request("verify_service_chain_token", &verify_request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Attenuate a token with service chain information for the current node
    ///
    /// This method adds the current node's attestation to a service chain token
    /// using the node's personal keypair.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to attenuate
    /// * `service` - The service identifier
    /// * `node_name` - The name of the current node
    ///
    /// # Returns
    ///
    /// A result containing the attenuated token or an error
    pub fn attenuate_service_chain_token(
        &self,
        token: String,
        service: String,
    ) -> Result<String, Box<dyn Error>> {
        // Get the node's personal keypair and the token's public key
        let (personal_keypair, public_key) = match self {
            HessraClient::Http1(client) => (
                client.config.personal_keypair.clone(),
                client.config.public_key.clone(),
            ),
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => (
                client.config.personal_keypair.clone(),
                client.config.public_key.clone(),
            ),
        };

        // Check if we have all the required data
        let personal_keypair = personal_keypair.ok_or_else(|| {
            "Personal keypair is required for service chain attestation but was not configured"
                .to_string()
        })?;

        let public_key = public_key.ok_or_else(|| {
            "Token public key is required for service chain attestation but was not configured"
                .to_string()
        })?;

        // Parse the private key and token public key
        let keypair = KeyPair::from_private_key_pem(&personal_keypair)?;
        let token_public_key = PublicKey::from_pem(&public_key)?;

        // Decode the token
        let token_bytes = BASE64_STANDARD.decode(token)?;

        // Add the service node attestation
        let attenuated_token =
            add_service_node_attenuation(token_bytes, token_public_key, &service, &keypair)?;

        // Encode the attenuated token
        let encoded_token = BASE64_STANDARD.encode(attenuated_token);
        Ok(encoded_token)
    }
}

/// A node in a service chain
///
/// Represents a component in a service chain with its associated public key.
/// Each service node has a unique name and a public key that is used to validate
/// attestations from this node.
///
/// # Examples
///
/// ```
/// use hessra_sdk::ServiceNode;
///
/// // Create a service node directly
/// let auth_node = ServiceNode::new("auth-service", "ed25519/1234567890abcdef");
///
/// // Or use the builder pattern
/// let payment_node = ServiceNode::builder()
///     .name("payment-service")
///     .public_key("ed25519/abcdef1234567890")
///     .build()
///     .expect("Failed to build service node");
/// ```
#[derive(Clone, Debug)]
pub struct ServiceNode {
    /// The name of the component
    pub name: String,
    /// The public key of the component in the format "algorithm/hexkey"
    pub public_key: String,
}

/// Builder for ServiceNode
///
/// Provides a fluent interface for constructing a ServiceNode.
#[derive(Default)]
pub struct ServiceNodeBuilder {
    name: Option<String>,
    public_key: Option<String>,
}

impl ServiceNodeBuilder {
    /// Create a new ServiceNodeBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the name of the service node
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the public key of the service node
    ///
    /// The key should be in the format "algorithm/hexkey", e.g. "ed25519/1234567890abcdef"
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// Build the ServiceNode
    ///
    /// # Errors
    ///
    /// Returns an error if the name or public key is not set
    pub fn build(self) -> Result<ServiceNode, Box<dyn Error>> {
        let name = self
            .name
            .ok_or_else(|| "Service node name is required".to_string())?;
        let public_key = self
            .public_key
            .ok_or_else(|| "Service node public key is required".to_string())?;

        Ok(ServiceNode { name, public_key })
    }
}

impl ServiceNode {
    /// Create a new service node
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the component
    /// * `public_key` - The public key in the format "algorithm/hexkey"
    pub fn new(name: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            public_key: public_key.into(),
        }
    }

    /// Create a new builder for a service node
    pub fn builder() -> ServiceNodeBuilder {
        ServiceNodeBuilder::new()
    }

    /// Convert to the internal ServiceNode type used by verification
    fn to_internal(&self) -> verify::ServiceNode {
        verify::ServiceNode {
            component: self.name.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

/// A chain of service nodes
///
/// Represents an ordered sequence of service nodes that form a processing chain.
/// The order of nodes in the chain is significant - it defines the expected
/// order of processing and attestation.
///
/// # Examples
///
/// ```
/// use hessra_sdk::{ServiceNode, ServiceChain};
///
/// // Create an empty chain and add nodes
/// let mut chain = ServiceChain::new();
/// chain.add_node(ServiceNode::new("auth", "ed25519/auth"))
///      .add_node(ServiceNode::new("payment", "ed25519/payment"));
///
/// // Or use builder-style chaining
/// let chain = ServiceChain::new()
///     .with_node(ServiceNode::new("auth", "ed25519/auth"))
///     .with_node(ServiceNode::new("payment", "ed25519/payment"));
///
/// // Create from a vector of nodes
/// let nodes = vec![
///     ServiceNode::new("auth", "ed25519/auth"),
///     ServiceNode::new("payment", "ed25519/payment"),
/// ];
/// let chain = ServiceChain::with_nodes(nodes);
///
/// // Use the builder pattern
/// let chain = ServiceChain::builder()
///     .add_node(ServiceNode::new("auth", "ed25519/auth"))
///     .add_node(ServiceNode::new("payment", "ed25519/payment"))
///     .build();
///
/// // Access the nodes
/// for node in chain.nodes() {
///     println!("Node: {}, Key: {}", node.name, node.public_key);
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct ServiceChain {
    /// The nodes in the chain, in order
    nodes: Vec<ServiceNode>,
}

impl ServiceChain {
    /// Create a new empty service chain
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Create a new service chain with the given nodes
    pub fn with_nodes(nodes: Vec<ServiceNode>) -> Self {
        Self { nodes }
    }

    /// Create a new builder for a service chain
    pub fn builder() -> ServiceChainBuilder {
        ServiceChainBuilder::new()
    }

    /// Add a node to the end of the chain
    pub fn add_node(&mut self, node: ServiceNode) -> &mut Self {
        self.nodes.push(node);
        self
    }

    /// Add a node to the end of the chain (builder style)
    pub fn with_node(mut self, node: ServiceNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Get the nodes in the chain
    pub fn nodes(&self) -> &[ServiceNode] {
        &self.nodes
    }

    /// Convert to a vector of internal ServiceNode types used by verification
    fn to_internal(&self) -> Vec<verify::ServiceNode> {
        self.nodes.iter().map(|node| node.to_internal()).collect()
    }
}

/// Builder for ServiceChain
pub struct ServiceChainBuilder {
    nodes: Vec<ServiceNode>,
}

impl Default for ServiceChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceChainBuilder {
    /// Create a new ServiceChainBuilder
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add a node to the chain
    pub fn add_node(mut self, node: ServiceNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Build the ServiceChain
    pub fn build(self) -> ServiceChain {
        ServiceChain { nodes: self.nodes }
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
            personal_keypair: None,
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
            personal_keypair: None,
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

    // Tests for ServiceNode

    #[test]
    fn test_service_node_creation() {
        // Test direct creation
        let node = ServiceNode::new("auth-service", "ed25519/1234567890abcdef");
        assert_eq!(node.name, "auth-service");
        assert_eq!(node.public_key, "ed25519/1234567890abcdef");

        // Test builder pattern
        let node = ServiceNode::builder()
            .name("payment-service")
            .public_key("ed25519/abcdef1234567890")
            .build()
            .unwrap();

        assert_eq!(node.name, "payment-service");
        assert_eq!(node.public_key, "ed25519/abcdef1234567890");
    }

    #[test]
    fn test_service_node_builder_validation() {
        // Missing name
        let result = ServiceNode::builder()
            .public_key("ed25519/1234567890abcdef")
            .build();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Service node name is required"
        );

        // Missing public key
        let result = ServiceNode::builder().name("auth-service").build();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Service node public key is required"
        );
    }

    #[test]
    fn test_service_node_to_internal() {
        let node = ServiceNode::new("auth-service", "ed25519/1234567890abcdef");
        let internal = node.to_internal();

        assert_eq!(internal.component, "auth-service");
        assert_eq!(internal.public_key, "ed25519/1234567890abcdef");
    }

    // Tests for ServiceChain

    #[test]
    fn test_service_chain_creation() {
        // Test empty chain
        let chain = ServiceChain::new();
        assert_eq!(chain.nodes().len(), 0);

        // Test with_nodes constructor
        let nodes = vec![
            ServiceNode::new("auth", "ed25519/auth"),
            ServiceNode::new("payment", "ed25519/payment"),
        ];
        let chain = ServiceChain::with_nodes(nodes);

        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(chain.nodes()[0].name, "auth");
        assert_eq!(chain.nodes()[1].name, "payment");

        // Test with_node builder method
        let chain = ServiceChain::new()
            .with_node(ServiceNode::new("auth", "ed25519/auth"))
            .with_node(ServiceNode::new("payment", "ed25519/payment"));

        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(chain.nodes()[0].name, "auth");
        assert_eq!(chain.nodes()[1].name, "payment");

        // Test add_node method
        let mut chain = ServiceChain::new();
        chain
            .add_node(ServiceNode::new("auth", "ed25519/auth"))
            .add_node(ServiceNode::new("payment", "ed25519/payment"));

        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(chain.nodes()[0].name, "auth");
        assert_eq!(chain.nodes()[1].name, "payment");
    }

    #[test]
    fn test_service_chain_builder() {
        let chain = ServiceChain::builder()
            .add_node(ServiceNode::new("auth", "ed25519/auth"))
            .add_node(ServiceNode::new("payment", "ed25519/payment"))
            .build();

        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(chain.nodes()[0].name, "auth");
        assert_eq!(chain.nodes()[1].name, "payment");
    }

    #[test]
    fn test_service_chain_to_internal() {
        let chain = ServiceChain::new()
            .with_node(ServiceNode::new("auth", "ed25519/auth"))
            .with_node(ServiceNode::new("payment", "ed25519/payment"));

        let internal = chain.to_internal();

        assert_eq!(internal.len(), 2);
        assert_eq!(internal[0].component, "auth");
        assert_eq!(internal[0].public_key, "ed25519/auth");
        assert_eq!(internal[1].component, "payment");
        assert_eq!(internal[1].public_key, "ed25519/payment");
    }
}
