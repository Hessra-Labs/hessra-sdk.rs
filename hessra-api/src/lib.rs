//! # Hessra API
//!
//! HTTP client for Hessra authentication services.
//!
//! This crate provides a client for making HTTP requests to the Hessra
//! authorization service. It supports both HTTP/1.1 and HTTP/3 (as an optional feature)
//! and implements the OpenAPI specification for the Hessra service.
//!
//! ## Features
//!
//! - HTTP/1.1 client for Hessra services
//! - Optional HTTP/3 support
//! - Implementation of all Hessra API endpoints
//! - Mutual TLS (mTLS) for secure client authentication
//! - Identity token support for authentication without mTLS (except initial issuance)
//! - Bearer token authentication using identity tokens

use serde::{Deserialize, Serialize};
use thiserror::Error;

use hessra_config::{HessraConfig, Protocol};

/// Parse a server address string into (host, port) components.
///
/// Handles various address formats:
/// - IP:Port (e.g., "127.0.0.1:4433")
/// - IP alone (e.g., "127.0.0.1")
/// - hostname:port (e.g., "test.hessra.net:443")
/// - hostname alone (e.g., "test.hessra.net")
/// - IPv6 with brackets and port (e.g., "[::1]:443")
/// - IPv6 with brackets, no port (e.g., "[::1]")
/// - URLs with protocol (e.g., "https://host:port/path")
///
/// Returns (host, Option<port>) where host is just the hostname/IP part
/// without any embedded port or protocol.
pub fn parse_server_address(address: &str) -> (String, Option<u16>) {
    let address = address.trim();

    // Strip protocol prefix if present
    let without_protocol = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .unwrap_or(address);

    // Strip path if present (everything after first /)
    let host_port = without_protocol
        .split('/')
        .next()
        .unwrap_or(without_protocol);

    // Handle IPv6 addresses with brackets
    if host_port.starts_with('[') {
        // IPv6 format: [::1]:port or [::1]
        if let Some(bracket_end) = host_port.find(']') {
            let host = &host_port[1..bracket_end]; // Get the IPv6 address without brackets
            let after_bracket = &host_port[bracket_end + 1..];

            if let Some(port_str) = after_bracket.strip_prefix(':') {
                // Has port after bracket
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host.to_string(), Some(port));
                }
            }
            // No port or invalid port
            return (host.to_string(), None);
        }
        // Malformed IPv6, return as-is without brackets
        return (host_port.trim_start_matches('[').to_string(), None);
    }

    // Handle IPv4 or hostname with optional port
    // Count colons to distinguish IPv6 from host:port
    let colon_count = host_port.chars().filter(|c| *c == ':').count();

    if colon_count == 1 {
        // Single colon means host:port format
        let parts: Vec<&str> = host_port.splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[1].parse::<u16>() {
                return (parts[0].to_string(), Some(port));
            }
        }
    }

    // No colon or multiple colons (unbracketed IPv6) - treat as host only
    (host_port.to_string(), None)
}

// Error type for the API client
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("SSL configuration error: {0}")]
    SslConfig(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Token request error: {0}")]
    TokenRequest(String),

    #[error("Token verification error: {0}")]
    TokenVerification(String),

    #[error("Service chain error: {0}")]
    ServiceChain(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Signoff failed: {0}")]
    SignoffFailed(String),

    #[error("Missing signoff configuration for service: {0}")]
    MissingSignoffConfig(String),

    #[error("Invalid signoff response from {service}: {reason}")]
    InvalidSignoffResponse { service: String, reason: String },

    #[error("Signoff collection incomplete: {missing_signoffs} signoffs remaining")]
    IncompleteSignoffs { missing_signoffs: usize },
}

// Request and response structures
/// Request payload for requesting an authorization token
#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    /// The resource identifier to request authorization for
    pub resource: String,
    /// The operation to request authorization for
    pub operation: String,
    /// Optional domain for domain-restricted identity token verification.
    /// When provided, enables enhanced verification with ensure_subject_in_domain().
    /// This parameter is used when the client is authenticating with a domain-restricted
    /// identity token and wants the server to verify the subject is truly associated with the domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
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
    /// The operation to verify authorization for
    pub operation: String,
}

/// Information about required signoffs for multi-party tokens
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignoffInfo {
    pub component: String,
    pub authorization_service: String,
    pub public_key: String,
}

/// Request structure for token signing operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignTokenRequest {
    pub token: String,
    pub resource: String,
    pub operation: String,
}

/// Response structure for token signing operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignTokenResponse {
    pub response_msg: String,
    pub signed_token: Option<String>,
}

/// Enhanced token response that may include pending signoffs
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenResponse {
    /// Response message from the server
    pub response_msg: String,
    /// The issued token, if successful
    pub token: Option<String>,
    /// Pending signoffs required for multi-party tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_signoffs: Option<Vec<SignoffInfo>>,
}

/// Response from a token verification operation
#[derive(Serialize, Deserialize)]
pub struct VerifyTokenResponse {
    /// Response message from the server
    pub response_msg: String,
}

/// Response from a public key request
#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub response_msg: String,
    pub public_key: String,
}

/// Response from a CA certificate request
#[derive(Serialize, Deserialize)]
pub struct CaCertResponse {
    pub response_msg: String,
    pub ca_cert_pem: String,
}

/// Request payload for verifying a service chain token
#[derive(Serialize, Deserialize)]
pub struct VerifyServiceChainTokenRequest {
    pub token: String,
    pub subject: String,
    pub resource: String,
    pub component: Option<String>,
}

/// Request for minting a new identity token
#[derive(Serialize, Deserialize)]
pub struct IdentityTokenRequest {
    /// Optional identifier - required for token-only auth, optional for mTLS
    pub identifier: Option<String>,
}

/// Request for refreshing an existing identity token
#[derive(Serialize, Deserialize)]
pub struct RefreshIdentityTokenRequest {
    /// The current identity token to refresh
    pub current_token: String,
    /// Optional identifier - required for token-only auth, optional for mTLS
    pub identifier: Option<String>,
}

/// Response from identity token operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityTokenResponse {
    /// Response message from the server
    pub response_msg: String,
    /// The issued identity token, if successful
    pub token: Option<String>,
    /// Time until expiration in seconds
    pub expires_in: Option<u64>,
    /// The identity contained in the token
    pub identity: Option<String>,
}

/// Request for minting a new domain-restricted identity token
#[derive(Serialize, Deserialize)]
pub struct MintIdentityTokenRequest {
    /// The subject identifier for the new identity token
    pub subject: String,
    /// Optional duration in seconds (server will use default if not provided)
    pub duration: Option<u64>,
}

/// Response from minting a domain-restricted identity token
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MintIdentityTokenResponse {
    /// Response message from the server
    pub response_msg: String,
    /// The minted identity token, if successful
    pub token: Option<String>,
    /// Time until expiration in seconds
    pub expires_in: Option<u64>,
    /// The identity contained in the token
    pub identity: Option<String>,
}

/// Request to mint a stub token that requires prefix attestation before use.
///
/// Stub tokens are minted by a realm identity on behalf of a target identity
/// within their domain. The token requires a trusted third party (identified by
/// the prefix_attenuator_key) to add a prefix restriction before the token
/// can be used.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StubTokenRequest {
    /// The identity who will use this token (must be in minter's domain)
    pub target_identity: String,
    /// The resource the stub token grants access to
    pub resource: String,
    /// The operation allowed on the resource
    pub operation: String,
    /// Public key that will attest the prefix (format: "ed25519/..." or "secp256r1/...")
    pub prefix_attenuator_key: String,
    /// Optional token duration in seconds (defaults to minter's configured duration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
}

/// Response from minting a stub token.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StubTokenResponse {
    /// Response message from the server
    pub response_msg: String,
    /// The stub token (requires prefix attestation before use)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Duration until expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The target identity encoded in the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_identity: Option<String>,
    /// The prefix attenuator key that must attest this token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_attenuator_key: Option<String>,
}

/// Base configuration for Hessra clients
#[derive(Clone)]
pub struct BaseConfig {
    /// Base URL of the Hessra service (without protocol scheme)
    pub base_url: String,
    /// Optional port to connect to
    pub port: Option<u16>,
    /// Optional mTLS private key in PEM format (required for mTLS auth)
    pub mtls_key: Option<String>,
    /// Optional mTLS client certificate in PEM format (required for mTLS auth)
    pub mtls_cert: Option<String>,
    /// Server CA certificate in PEM format
    pub server_ca: String,
    /// Public key for token verification in PEM format
    pub public_key: Option<String>,
    /// Personal keypair for service chain attestation
    pub personal_keypair: Option<String>,
}

impl BaseConfig {
    /// Get the formatted base URL, with port if specified.
    ///
    /// Handles cases where base_url might already contain an embedded port.
    /// If both an embedded port and self.port are present, self.port takes precedence.
    pub fn get_base_url(&self) -> String {
        // Parse the base_url to extract host and any embedded port
        let (host, embedded_port) = parse_server_address(&self.base_url);

        // Explicitly set port takes precedence, then embedded port
        let resolved_port = self.port.or(embedded_port);

        match resolved_port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }
}

/// HTTP/1.1 client implementation
pub struct Http1Client {
    /// Base configuration
    config: BaseConfig,
    /// reqwest HTTP client with mTLS configured
    client: reqwest::Client,
}

impl Http1Client {
    /// Create a new HTTP/1.1 client with the given configuration
    pub fn new(config: BaseConfig) -> Result<Self, ApiError> {
        // Parse the CA certificate chain (may contain root + intermediates + leaf)
        let certs =
            reqwest::Certificate::from_pem_bundle(config.server_ca.as_bytes()).map_err(|e| {
                ApiError::SslConfig(format!("Failed to parse CA certificate chain: {e}"))
            })?;

        // Build the client with or without mTLS depending on configuration
        let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();

        // Add all certificates from the chain as trusted roots
        for cert in certs {
            client_builder = client_builder.add_root_certificate(cert);
        }

        // Add mTLS identity if both cert and key are provided
        if let (Some(cert), Some(key)) = (&config.mtls_cert, &config.mtls_key) {
            let identity_str = format!("{cert}{key}");
            let identity = reqwest::Identity::from_pem(identity_str.as_bytes()).map_err(|e| {
                ApiError::SslConfig(format!(
                    "Failed to create identity from certificate and key: {e}"
                ))
            })?;
            client_builder = client_builder.identity(identity);
        }

        let client = client_builder
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        Ok(Self { config, client })
    }

    /// Send a request to the remote Hessra authorization service
    pub async fn send_request<T, R>(&self, endpoint: &str, request_body: &T) -> Result<R, ApiError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let base_url = self.config.get_base_url();
        let url = format!("https://{base_url}/{endpoint}");

        let response = self
            .client
            .post(&url)
            .json(request_body)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        let result = response
            .json::<R>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result)
    }

    pub async fn send_request_with_auth<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
        auth_header: &str,
    ) -> Result<R, ApiError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let base_url = self.config.get_base_url();
        let url = format!("https://{base_url}/{endpoint}");

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .json(request_body)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        let result = response
            .json::<R>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result)
    }
}

/// HTTP/3 client implementation (only available with the "http3" feature)
#[cfg(feature = "http3")]
pub struct Http3Client {
    /// Base configuration
    config: BaseConfig,
    /// QUIC endpoint for HTTP/3 connections
    client: reqwest::Client,
}

#[cfg(feature = "http3")]
impl Http3Client {
    /// Create a new HTTP/3 client with the given configuration
    pub fn new(config: BaseConfig) -> Result<Self, ApiError> {
        // Parse the CA certificate chain (may contain root + intermediates + leaf)
        let certs =
            reqwest::Certificate::from_pem_bundle(config.server_ca.as_bytes()).map_err(|e| {
                ApiError::SslConfig(format!("Failed to parse CA certificate chain: {e}"))
            })?;

        // Build the client with or without mTLS depending on configuration
        let mut client_builder = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .http3_prior_knowledge();

        // Add all certificates from the chain as trusted roots
        for cert in certs {
            client_builder = client_builder.add_root_certificate(cert);
        }

        // Add mTLS identity if both cert and key are provided
        if let (Some(cert), Some(key)) = (&config.mtls_cert, &config.mtls_key) {
            let identity_str = format!("{}{}", cert, key);
            let identity = reqwest::Identity::from_pem(identity_str.as_bytes()).map_err(|e| {
                ApiError::SslConfig(format!(
                    "Failed to create identity from certificate and key: {e}"
                ))
            })?;
            client_builder = client_builder.identity(identity);
        }

        let client = client_builder
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        Ok(Self { config, client })
    }

    /// Send a request to the Hessra service
    pub async fn send_request<T, R>(&self, endpoint: &str, request_body: &T) -> Result<R, ApiError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let base_url = self.config.get_base_url();
        let url = format!("https://{base_url}/{endpoint}");

        let response = self
            .client
            .post(&url)
            .json(request_body)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        let result = response
            .json::<R>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result)
    }

    pub async fn send_request_with_auth<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
        auth_header: &str,
    ) -> Result<R, ApiError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let base_url = self.config.get_base_url();
        let url = format!("https://{base_url}/{endpoint}");

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .json(request_body)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        let result = response
            .json::<R>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result)
    }
}

/// The main Hessra client type providing token request and verification
pub enum HessraClient {
    /// HTTP/1.1 client
    Http1(Http1Client),
    /// HTTP/3 client (only available with the "http3" feature)
    #[cfg(feature = "http3")]
    Http3(Http3Client),
}

/// Builder for creating Hessra clients
pub struct HessraClientBuilder {
    /// Base configuration being built
    config: BaseConfig,
    /// Protocol to use for the client
    protocol: hessra_config::Protocol,
}

impl HessraClientBuilder {
    /// Create a new client builder with default values
    pub fn new() -> Self {
        Self {
            config: BaseConfig {
                base_url: String::new(),
                port: None,
                mtls_key: None,
                mtls_cert: None,
                server_ca: String::new(),
                public_key: None,
                personal_keypair: None,
            },
            protocol: Protocol::Http1,
        }
    }

    /// Create a client builder from a HessraConfig
    pub fn from_config(mut self, config: &HessraConfig) -> Self {
        self.config.base_url = config.base_url.clone();
        self.config.port = config.port;
        self.config.mtls_key = config.mtls_key.clone();
        self.config.mtls_cert = config.mtls_cert.clone();
        self.config.server_ca = config.server_ca.clone();
        self.config.public_key = config.public_key.clone();
        self.config.personal_keypair = config.personal_keypair.clone();
        self.protocol = config.protocol.clone();
        self
    }

    /// Set the base URL for the client, e.g. "test.hessra.net"
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = base_url.into();
        self
    }

    /// Set the mTLS private key for the client
    /// PEM formatted string
    pub fn mtls_key(mut self, mtls_key: impl Into<String>) -> Self {
        self.config.mtls_key = Some(mtls_key.into());
        self
    }

    /// Set the mTLS certificate for the client
    /// PEM formatted string
    pub fn mtls_cert(mut self, mtls_cert: impl Into<String>) -> Self {
        self.config.mtls_cert = Some(mtls_cert.into());
        self
    }

    /// Set the server CA certificate for the client
    /// PEM formatted string
    pub fn server_ca(mut self, server_ca: impl Into<String>) -> Self {
        self.config.server_ca = server_ca.into();
        self
    }

    /// Set the port for the client
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = Some(port);
        self
    }

    /// Set the protocol for the client
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the public key for token verification
    /// PEM formatted string. note, this is JUST the public key, not the entire keypair.
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.config.public_key = Some(public_key.into());
        self
    }

    /// Set the personal keypair for service chain attestation
    /// PEM formatted string. note, this is the entire keypair
    /// and needs to be kept secret.
    pub fn personal_keypair(mut self, keypair: impl Into<String>) -> Self {
        self.config.personal_keypair = Some(keypair.into());
        self
    }

    /// Build the HTTP/1.1 client
    fn build_http1(&self) -> Result<Http1Client, ApiError> {
        Http1Client::new(self.config.clone())
    }

    /// Build the HTTP/3 client
    #[cfg(feature = "http3")]
    fn build_http3(&self) -> Result<Http3Client, ApiError> {
        Http3Client::new(self.config.clone())
    }

    /// Build the client
    pub fn build(self) -> Result<HessraClient, ApiError> {
        match self.protocol {
            Protocol::Http1 => Ok(HessraClient::Http1(self.build_http1()?)),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Ok(HessraClient::Http3(self.build_http3()?)),
            #[allow(unreachable_patterns)]
            _ => Err(ApiError::Internal("Unsupported protocol".to_string())),
        }
    }
}

impl Default for HessraClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HessraClient {
    /// Create a new client builder
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::new()
    }

    /// Fetch the public key from the Hessra service without creating a client
    /// The public_key endpoint is available as both an authenticated and unauthenticated
    /// request.
    pub async fn fetch_public_key(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, ApiError> {
        let base_url_str = base_url.into();
        let server_ca = server_ca.into();

        // Parse the base_url to handle addresses with embedded ports
        let (host, embedded_port) = parse_server_address(&base_url_str);
        // Use embedded port if present, otherwise use the provided port parameter
        let resolved_port = embedded_port.or(port);

        // Create a regular reqwest client (no mTLS)
        let cert_pem = server_ca.as_bytes();
        let certs = reqwest::Certificate::from_pem_bundle(cert_pem)
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
        for cert in certs {
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL using the parsed host and resolved port
        let url = match resolved_port {
            Some(port) => format!("https://{host}:{port}/public_key"),
            None => format!("https://{host}/public_key"),
        };

        // Make the request
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        // Parse the response
        let result = response
            .json::<PublicKeyResponse>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result.public_key)
    }

    /// Fetch the CA certificate from the Hessra service without authentication
    ///
    /// This function makes an unauthenticated request to the `/ca_cert` endpoint
    /// to retrieve the server's CA certificate in PEM format. This is useful for
    /// bootstrapping trust when setting up a new client.
    ///
    /// # Bootstrap Trust Considerations
    ///
    /// This function uses the system CA store for the initial connection. If the
    /// server uses a self-signed certificate, consider using `fetch_ca_cert_insecure`
    /// instead (with appropriate warnings to users).
    pub async fn fetch_ca_cert(
        base_url: impl Into<String>,
        port: Option<u16>,
    ) -> Result<String, ApiError> {
        let base_url_str = base_url.into();

        // Parse the base_url to handle addresses with embedded ports
        let (host, embedded_port) = parse_server_address(&base_url_str);
        // Use embedded port if present, otherwise use the provided port parameter
        let resolved_port = embedded_port.or(port);

        // Create a reqwest client using system CA store
        let client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL using the parsed host and resolved port
        let url = match resolved_port {
            Some(port) => format!("https://{host}:{port}/ca_cert"),
            None => format!("https://{host}/ca_cert"),
        };

        // Make the request
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        // Parse the response
        let result = response
            .json::<CaCertResponse>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        // Validate it's a non-empty PEM certificate
        if result.ca_cert_pem.is_empty() {
            return Err(ApiError::InvalidResponse(
                "Server returned empty CA certificate".to_string(),
            ));
        }

        if !result.ca_cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ApiError::InvalidResponse(
                "Server returned invalid PEM format".to_string(),
            ));
        }

        Ok(result.ca_cert_pem)
    }

    #[cfg(feature = "http3")]
    pub async fn fetch_public_key_http3(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, ApiError> {
        let base_url_str = base_url.into();
        let server_ca = server_ca.into();

        // Parse the base_url to handle addresses with embedded ports
        let (host, embedded_port) = parse_server_address(&base_url_str);
        // Use embedded port if present, otherwise use the provided port parameter
        let resolved_port = embedded_port.or(port);

        // Create a regular reqwest client (no mTLS)
        let cert_pem = server_ca.as_bytes();
        let certs = reqwest::Certificate::from_pem_bundle(cert_pem)
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        let mut client_builder = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .http3_prior_knowledge();
        for cert in certs {
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL using the parsed host and resolved port
        let url = match resolved_port {
            Some(port) => format!("https://{host}:{port}/public_key"),
            None => format!("https://{host}/public_key"),
        };

        // Make the request
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(ApiError::HttpClient)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ApiError::InvalidResponse(format!(
                "HTTP error: {status} - {error_text}"
            )));
        }

        // Parse the response
        let result = response
            .json::<PublicKeyResponse>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {e}")))?;

        Ok(result.public_key)
    }

    /// Request a token for a resource
    /// Returns the full TokenResponse which may include pending signoffs for multi-party tokens
    ///
    /// # Arguments
    /// * `resource` - The resource identifier to request authorization for
    /// * `operation` - The operation to request authorization for
    /// * `domain` - Optional domain for domain-restricted identity token verification
    pub async fn request_token(
        &self,
        resource: String,
        operation: String,
        domain: Option<String>,
    ) -> Result<TokenResponse, ApiError> {
        let request = TokenRequest {
            resource,
            operation,
            domain,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, TokenResponse>("request_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, TokenResponse>("request_token", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Request a token for a resource using an identity token for authentication
    /// The identity token will be sent in the Authorization header as a Bearer token
    /// Returns the full TokenResponse which may include pending signoffs for multi-party tokens
    ///
    /// # Arguments
    /// * `resource` - The resource identifier to request authorization for
    /// * `operation` - The operation to request authorization for
    /// * `identity_token` - The identity token to use for authentication
    /// * `domain` - Optional domain for domain-restricted identity token verification
    pub async fn request_token_with_identity(
        &self,
        resource: String,
        operation: String,
        identity_token: String,
        domain: Option<String>,
    ) -> Result<TokenResponse, ApiError> {
        let request = TokenRequest {
            resource,
            operation,
            domain,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request_with_auth::<_, TokenResponse>(
                        "request_token",
                        &request,
                        &format!("Bearer {identity_token}"),
                    )
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request_with_auth::<_, TokenResponse>(
                        "request_token",
                        &request,
                        &format!("Bearer {identity_token}"),
                    )
                    .await?
            }
        };

        Ok(response)
    }

    /// Request a token for a resource (legacy method)
    /// This method returns just the token string for backward compatibility
    pub async fn request_token_simple(
        &self,
        resource: String,
        operation: String,
    ) -> Result<String, ApiError> {
        let response = self.request_token(resource, operation, None).await?;

        match response.token {
            Some(token) => Ok(token),
            None => Err(ApiError::TokenRequest(format!(
                "Failed to get token: {}",
                response.response_msg
            ))),
        }
    }

    /// Verify a token for subject doing operation on resource.
    /// This will verify the token using the remote authorization service API.
    pub async fn verify_token(
        &self,
        token: String,
        subject: String,
        resource: String,
        operation: String,
    ) -> Result<String, ApiError> {
        let request = VerifyTokenRequest {
            token,
            subject,
            resource,
            operation,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify_token", &request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Verify a service chain token. If no component is provided,
    /// the entire service chain will be used to verify the token.
    /// If a component name is provided, the service chain up to and
    /// excluding the component will be used to verify the token. This
    /// is useful for a node in the middle of the service chain
    /// verifying a token has been attested by all previous nodes.
    pub async fn verify_service_chain_token(
        &self,
        token: String,
        subject: String,
        resource: String,
        component: Option<String>,
    ) -> Result<String, ApiError> {
        let request = VerifyServiceChainTokenRequest {
            token,
            subject,
            resource,
            component,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify_service_chain_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify_service_chain_token", &request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Sign a multi-party token by calling an authorization service's signoff endpoint
    pub async fn sign_token(
        &self,
        token: &str,
        resource: &str,
        operation: &str,
    ) -> Result<SignTokenResponse, ApiError> {
        let request = SignTokenRequest {
            token: token.to_string(),
            resource: resource.to_string(),
            operation: operation.to_string(),
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, SignTokenResponse>("sign_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, SignTokenResponse>("sign_token", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Get the public key from the server
    pub async fn get_public_key(&self) -> Result<String, ApiError> {
        let url_path = "public_key";

        let response = match self {
            HessraClient::Http1(client) => {
                // For this endpoint, we just need a GET request, not a POST with a body
                let base_url = client.config.get_base_url();
                let full_url = format!("https://{base_url}/{url_path}");

                let response = client
                    .client
                    .get(&full_url)
                    .send()
                    .await
                    .map_err(ApiError::HttpClient)?;

                if !response.status().is_success() {
                    let status = response.status();
                    let error_text = response.text().await.unwrap_or_default();
                    return Err(ApiError::InvalidResponse(format!(
                        "HTTP error: {status} - {error_text}"
                    )));
                }

                response.json::<PublicKeyResponse>().await.map_err(|e| {
                    ApiError::InvalidResponse(format!("Failed to parse response: {e}"))
                })?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                let base_url = client.config.get_base_url();
                let full_url = format!("https://{base_url}/{url_path}");

                let response = client
                    .client
                    .get(&full_url)
                    .send()
                    .await
                    .map_err(ApiError::HttpClient)?;

                if !response.status().is_success() {
                    let status = response.status();
                    let error_text = response.text().await.unwrap_or_default();
                    return Err(ApiError::InvalidResponse(format!(
                        "HTTP error: {status} - {error_text}"
                    )));
                }

                response.json::<PublicKeyResponse>().await.map_err(|e| {
                    ApiError::InvalidResponse(format!("Failed to parse response: {e}"))
                })?
            }
        };

        Ok(response.public_key)
    }

    /// Request a new identity token from the authorization service
    ///
    /// This endpoint requires mTLS authentication as it's the initial issuance of an identity token.
    /// The identifier parameter is optional when using mTLS, as the identity can be derived from the client certificate.
    ///
    /// # Arguments
    /// * `identifier` - Optional identifier for the identity. Required for non-mTLS future requests, optional with mTLS.
    pub async fn request_identity_token(
        &self,
        identifier: Option<String>,
    ) -> Result<IdentityTokenResponse, ApiError> {
        let request = IdentityTokenRequest { identifier };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, IdentityTokenResponse>("request_identity_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, IdentityTokenResponse>("request_identity_token", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Refresh an existing identity token
    ///
    /// This endpoint can use either mTLS or the current identity token for authentication.
    /// When using identity token authentication (no mTLS), the identifier parameter is required.
    /// The current token will be validated and a new token with updated expiration will be issued.
    ///
    /// # Arguments
    /// * `current_token` - The existing identity token to refresh
    /// * `identifier` - Optional identifier. Required when not using mTLS authentication.
    pub async fn refresh_identity_token(
        &self,
        current_token: String,
        identifier: Option<String>,
    ) -> Result<IdentityTokenResponse, ApiError> {
        let request = RefreshIdentityTokenRequest {
            current_token,
            identifier,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, IdentityTokenResponse>("refresh_identity_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, IdentityTokenResponse>("refresh_identity_token", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Mint a new domain-restricted identity token
    ///
    /// This endpoint requires mTLS authentication from a "realm" identity (one without domain restriction).
    /// The minted token will be restricted to the minting identity's domain and cannot mint further sub-identities.
    /// Permissions are determined by domain roles configured on the server.
    ///
    /// # Arguments
    /// * `subject` - The subject identifier for the new identity (e.g., "uri:urn:test:argo-cli1:user123")
    /// * `duration` - Optional duration in seconds. If None, server uses configured default.
    pub async fn mint_domain_restricted_identity_token(
        &self,
        subject: String,
        duration: Option<u64>,
    ) -> Result<MintIdentityTokenResponse, ApiError> {
        let request = MintIdentityTokenRequest { subject, duration };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, MintIdentityTokenResponse>("mint_identity_token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, MintIdentityTokenResponse>("mint_identity_token", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Request a stub token that requires prefix attestation before use.
    ///
    /// This endpoint requires mTLS authentication from a "realm" identity.
    /// The minted stub token will be for a target identity within the realm's domain
    /// and will require a trusted third party (identified by prefix_attenuator_key)
    /// to add a prefix restriction before the token can be used.
    ///
    /// # Arguments
    /// * `target_identity` - The identity who will use this token (must be in minter's domain)
    /// * `resource` - The resource the stub token grants access to
    /// * `operation` - The operation allowed on the resource
    /// * `prefix_attenuator_key` - Public key that will attest the prefix (format: "ed25519/..." or "secp256r1/...")
    /// * `duration` - Optional token duration in seconds (defaults to minter's configured duration)
    pub async fn request_stub_token(
        &self,
        target_identity: String,
        resource: String,
        operation: String,
        prefix_attenuator_key: String,
        duration: Option<u64>,
    ) -> Result<StubTokenResponse, ApiError> {
        let request = StubTokenRequest {
            target_identity,
            resource,
            operation,
            prefix_attenuator_key,
            duration,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, StubTokenResponse>("request_stub", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, StubTokenResponse>("request_stub", &request)
                    .await?
            }
        };

        Ok(response)
    }

    /// Request a stub token using an identity token for authentication.
    ///
    /// This is similar to `request_stub_token` but uses an identity token
    /// instead of mTLS for authentication. The identity token will be sent
    /// in the Authorization header as a Bearer token.
    ///
    /// # Arguments
    /// * `target_identity` - The identity who will use this token (must be in minter's domain)
    /// * `resource` - The resource the stub token grants access to
    /// * `operation` - The operation allowed on the resource
    /// * `prefix_attenuator_key` - Public key that will attest the prefix (format: "ed25519/..." or "secp256r1/...")
    /// * `identity_token` - The identity token to use for authentication
    /// * `duration` - Optional token duration in seconds (defaults to minter's configured duration)
    pub async fn request_stub_token_with_identity(
        &self,
        target_identity: String,
        resource: String,
        operation: String,
        prefix_attenuator_key: String,
        identity_token: String,
        duration: Option<u64>,
    ) -> Result<StubTokenResponse, ApiError> {
        let request = StubTokenRequest {
            target_identity,
            resource,
            operation,
            prefix_attenuator_key,
            duration,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request_with_auth::<_, StubTokenResponse>(
                        "request_stub",
                        &request,
                        &format!("Bearer {identity_token}"),
                    )
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request_with_auth::<_, StubTokenResponse>(
                        "request_stub",
                        &request,
                        &format!("Bearer {identity_token}"),
                    )
                    .await?
            }
        };

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test BaseConfig get_base_url method
    #[test]
    fn test_base_config_get_base_url_with_port() {
        let config = BaseConfig {
            base_url: "test.hessra.net".to_string(),
            port: Some(443),
            mtls_key: None,
            mtls_cert: None,
            server_ca: "".to_string(),
            public_key: None,
            personal_keypair: None,
        };

        assert_eq!(config.get_base_url(), "test.hessra.net:443");
    }

    #[test]
    fn test_base_config_get_base_url_without_port() {
        let config = BaseConfig {
            base_url: "test.hessra.net".to_string(),
            port: None,
            mtls_key: None,
            mtls_cert: None,
            server_ca: "".to_string(),
            public_key: None,
            personal_keypair: None,
        };

        assert_eq!(config.get_base_url(), "test.hessra.net");
    }

    // Test HessraClientBuilder methods
    #[test]
    fn test_client_builder_methods() {
        let builder = HessraClientBuilder::new()
            .base_url("test.hessra.net")
            .port(443)
            .protocol(Protocol::Http1)
            .mtls_cert("CERT")
            .mtls_key("KEY")
            .server_ca("CA")
            .public_key("PUBKEY")
            .personal_keypair("KEYPAIR");

        assert_eq!(builder.config.base_url, "test.hessra.net");
        assert_eq!(builder.config.port, Some(443));
        assert_eq!(builder.config.mtls_cert, Some("CERT".to_string()));
        assert_eq!(builder.config.mtls_key, Some("KEY".to_string()));
        assert_eq!(builder.config.server_ca, "CA");
        assert_eq!(builder.config.public_key, Some("PUBKEY".to_string()));
        assert_eq!(builder.config.personal_keypair, Some("KEYPAIR".to_string()));
    }

    // Test parse_server_address function
    #[test]
    fn test_parse_server_address_ip_with_port() {
        let (host, port) = parse_server_address("127.0.0.1:4433");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, Some(4433));
    }

    #[test]
    fn test_parse_server_address_ip_only() {
        let (host, port) = parse_server_address("127.0.0.1");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_server_address_hostname_with_port() {
        let (host, port) = parse_server_address("test.hessra.net:443");
        assert_eq!(host, "test.hessra.net");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn test_parse_server_address_hostname_only() {
        let (host, port) = parse_server_address("test.hessra.net");
        assert_eq!(host, "test.hessra.net");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_server_address_with_https_protocol() {
        let (host, port) = parse_server_address("https://example.com:8443");
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_parse_server_address_with_https_protocol_no_port() {
        let (host, port) = parse_server_address("https://example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_server_address_with_path() {
        let (host, port) = parse_server_address("https://example.com:8443/some/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_parse_server_address_ipv6_with_brackets_and_port() {
        let (host, port) = parse_server_address("[::1]:8443");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_parse_server_address_ipv6_with_brackets_no_port() {
        let (host, port) = parse_server_address("[::1]");
        assert_eq!(host, "::1");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_server_address_ipv6_full_with_port() {
        let (host, port) = parse_server_address("[2001:db8::1]:4433");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, Some(4433));
    }

    #[test]
    fn test_parse_server_address_with_whitespace() {
        let (host, port) = parse_server_address("  127.0.0.1:4433  ");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, Some(4433));
    }

    #[test]
    fn test_base_config_get_base_url_with_embedded_port() {
        // Test that BaseConfig::get_base_url handles embedded ports correctly
        let config = BaseConfig {
            base_url: "127.0.0.1:4433".to_string(),
            port: None, // No explicit port set
            mtls_key: None,
            mtls_cert: None,
            server_ca: "".to_string(),
            public_key: None,
            personal_keypair: None,
        };
        // Should extract the embedded port and use it
        assert_eq!(config.get_base_url(), "127.0.0.1:4433");
    }

    #[test]
    fn test_base_config_get_base_url_explicit_port_overrides_embedded() {
        // Test that explicitly set port takes precedence over embedded port
        let config = BaseConfig {
            base_url: "127.0.0.1:4433".to_string(),
            port: Some(8080), // Explicit port should override
            mtls_key: None,
            mtls_cert: None,
            server_ca: "".to_string(),
            public_key: None,
            personal_keypair: None,
        };
        assert_eq!(config.get_base_url(), "127.0.0.1:8080");
    }
}
