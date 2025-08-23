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
    /// Get the formatted base URL, with port if specified
    pub fn get_base_url(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.base_url),
            None => self.base_url.clone(),
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
        // Parse the CA certificate (always required for server verification)
        let cert_der = reqwest::Certificate::from_pem(config.server_ca.as_bytes())
            .map_err(|e| ApiError::SslConfig(format!("Failed to parse CA certificate: {e}")))?;

        // Build the client with or without mTLS depending on configuration
        let mut client_builder = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .add_root_certificate(cert_der);

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
        // Parse the CA certificate (always required for server verification)
        let cert_der = reqwest::Certificate::from_pem(config.server_ca.as_bytes())
            .map_err(|e| ApiError::SslConfig(format!("Failed to parse CA certificate: {e}")))?;

        // Build the client with or without mTLS depending on configuration
        let mut client_builder = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .http3_prior_knowledge()
            .add_root_certificate(cert_der);

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
        let base_url = base_url.into();
        let server_ca = server_ca.into();

        // Create a regular reqwest client (no mTLS)
        let cert_pem = server_ca.as_bytes();
        let cert_der = reqwest::Certificate::from_pem(cert_pem)
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        let client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .add_root_certificate(cert_der)
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL
        let url = match port {
            Some(port) => format!("https://{base_url}:{port}/public_key"),
            None => format!("https://{base_url}/public_key"),
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

    #[cfg(feature = "http3")]
    pub async fn fetch_public_key_http3(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, ApiError> {
        let base_url = base_url.into();
        let server_ca = server_ca.into();

        // Create a regular reqwest client (no mTLS)
        let cert_pem = server_ca.as_bytes();
        let cert_der = reqwest::Certificate::from_pem(cert_pem)
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        let client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .add_root_certificate(cert_der)
            .http3_prior_knowledge()
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL
        let url = match port {
            Some(port) => format!("https://{base_url}:{port}/public_key"),
            None => format!("https://{base_url}/public_key"),
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
    pub async fn request_token(
        &self,
        resource: String,
        operation: String,
    ) -> Result<TokenResponse, ApiError> {
        let request = TokenRequest {
            resource,
            operation,
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
    pub async fn request_token_with_identity(
        &self,
        resource: String,
        operation: String,
        identity_token: String,
    ) -> Result<TokenResponse, ApiError> {
        let request = TokenRequest {
            resource,
            operation,
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
        let response = self.request_token(resource, operation).await?;

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
}
