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
//!     .base_url("auth.example.com")
//!     .port(443)
//!     .protocol(Protocol::Http1)
//!     .mtls_cert(include_str!("../certs/client.crt"))
//!     .mtls_key(include_str!("../certs/client.key"))
//!     .server_ca(include_str!("../certs/ca.pem"))
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
//! ```rust
//! use hessra_sdk::{HessraConfig, Protocol, set_default_config};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Manual configuration
//! let config = HessraConfig::new(
//!     "https://auth.example.com",
//!     Some(443),
//!     Protocol::Http1,
//!     include_str!("../certs/client.crt"),
//!     include_str!("../certs/client.key"),
//!     include_str!("../certs/ca.pem"),
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
//! ## Environment Variables
//!
//! When using `from_env()` or `from_env_or_file()`, the following variables are expected:
//!
//! - `{PREFIX}_BASE_URL`: The base URL of the Hessra service
//! - `{PREFIX}_PORT`: The port to connect to (optional)
//! - `{PREFIX}_MTLS_CERT` or `{PREFIX}_MTLS_CERT_FILE`: The mTLS certificate
//! - `{PREFIX}_MTLS_KEY` or `{PREFIX}_MTLS_KEY_FILE`: The mTLS key
//! - `{PREFIX}_SERVER_CA` or `{PREFIX}_SERVER_CA_FILE`: The server CA certificate
//! - `{PREFIX}_PROTOCOL`: Either "http1" or "http3" (optional, defaults to "http1")
//!

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

// Re-export configuration module
mod config;
pub use config::*;

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

/// Base configuration parameters for Hessra clients
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
///     .base_url("auth.example.com")
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
///     .base_url("auth.example.com")
///     .port(443)
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
            },
            protocol: Protocol::Http1,
        }
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
    /// ```
    /// use hessra_sdk::{HessraClient, Protocol};
    ///
    /// let client = HessraClient::builder()
    ///     .base_url("auth.example.com")
    ///     .port(443)
    ///     .protocol(Protocol::Http1)
    ///     .mtls_cert("CERT CONTENT")
    ///     .mtls_key("KEY CONTENT")
    ///     .server_ca("CA CONTENT")
    ///     .build()
    ///     .expect("Failed to build client");
    /// ```
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::new()
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

        response.token.ok_or_else(|| "No token in response".into())
    }

    /// Verify an authorization token for a resource
    ///
    /// Sends a request to the Hessra service to verify an authorization token
    /// for the specified resource.
    ///
    /// # Arguments
    ///
    /// * `token` - The authorization token to verify
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
        let verify_token_request = VerifyTokenRequest { token, resource };

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
}
