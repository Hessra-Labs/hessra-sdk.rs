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

    #[cfg(feature = "http3")]
    #[error("HTTP/3 error: {0}")]
    Http3(String),
}

// Request and response structures
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

/// Base configuration for Hessra clients
#[derive(Clone)]
pub struct BaseConfig {
    /// Base URL of the Hessra service (without protocol scheme)
    pub base_url: String,
    /// Optional port to connect to
    pub port: Option<u16>,
    /// mTLS private key in PEM format
    pub mtls_key: String,
    /// mTLS client certificate in PEM format
    pub mtls_cert: String,
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
    client: reqwest::Client,
}

impl Http1Client {
    /// Create a new HTTP/1.1 client with the given configuration
    pub fn new(config: BaseConfig) -> Result<Self, ApiError> {
        // Parse the PEM string into certificate and private key
        let cert = match reqwest::Identity::from_pem(
            format!("{}\n{}", config.mtls_cert, config.mtls_key).as_bytes(),
        ) {
            Ok(cert) => cert,
            Err(e) => return Err(ApiError::SslConfig(e.to_string())),
        };

        // Parse the CA certificate
        let cert_pem = config.server_ca.as_bytes();
        let cert_der = match reqwest::Certificate::from_pem(cert_pem) {
            Ok(cert) => cert,
            Err(e) => return Err(ApiError::SslConfig(e.to_string())),
        };

        // Build the reqwest client with mTLS configuration
        let client = reqwest::ClientBuilder::new()
            .identity(cert)
            .add_root_certificate(cert_der)
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
        let url = format!("https://{}/{}", base_url, endpoint);

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
                "HTTP error: {} - {}",
                status, error_text
            )));
        }

        let result = response
            .json::<R>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

        Ok(result)
    }
}

/// HTTP/3 client implementation (only available with the "http3" feature)
#[cfg(feature = "http3")]
pub struct Http3Client {
    /// Base configuration
    config: BaseConfig,
    /// QUIC endpoint for HTTP/3 connections
    endpoint: quinn::Endpoint,
}

#[cfg(feature = "http3")]
impl Http3Client {
    /// Create a new HTTP/3 client with the given configuration
    pub fn new(config: BaseConfig) -> Result<Self, ApiError> {
        use quinn::{ClientConfig, Endpoint, EndpointConfig};
        use rustls::Certificate;
        use rustls::PrivateKey;
        use rustls_pemfile::Item;
        use std::io::Cursor;
        use std::sync::Arc;

        // Parse client certificate and private key
        let cert_pem = Cursor::new(config.mtls_cert.as_bytes());
        let mut certs = Vec::new();
        for item in rustls_pemfile::read_all(cert_pem) {
            match item {
                Ok(Item::X509Certificate(cert)) => certs.push(Certificate(cert)),
                _ => {}
            }
        }

        if certs.is_empty() {
            return Err(ApiError::SslConfig(
                "Failed to parse client certificate".into(),
            ));
        }

        let key_pem = Cursor::new(config.mtls_key.as_bytes());
        let mut keys = Vec::new();
        for item in rustls_pemfile::read_all(key_pem) {
            match item {
                Ok(Item::PKCS8Key(key)) => keys.push(PrivateKey(key)),
                Ok(Item::RSAKey(key)) => keys.push(PrivateKey(key)),
                Ok(Item::ECKey(key)) => keys.push(PrivateKey(key)),
                _ => {}
            }
        }

        if keys.is_empty() {
            return Err(ApiError::SslConfig("Failed to parse private key".into()));
        }

        // Parse server CA certificate
        let server_ca_pem = Cursor::new(config.server_ca.as_bytes());
        let mut root_certs = Vec::new();
        for item in rustls_pemfile::read_all(server_ca_pem) {
            match item {
                Ok(Item::X509Certificate(cert)) => root_certs.push(Certificate(cert)),
                _ => {}
            }
        }

        if root_certs.is_empty() {
            return Err(ApiError::SslConfig(
                "Failed to parse server CA certificate".into(),
            ));
        }

        // Build client crypto config
        let mut crypto_builder = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_client_auth_cert(certs, keys[0].clone())
            .map_err(|e| ApiError::SslConfig(format!("Failed to configure TLS: {}", e)))?;

        crypto_builder.enable_early_data = true;
        crypto_builder.enable_sni = true;

        // Create QUIC client config
        let client_config = ClientConfig::new(Arc::new(crypto_builder));
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| ApiError::Http3(format!("Failed to create endpoint: {}", e)))?;

        endpoint.set_default_client_config(client_config);

        Ok(Self { config, endpoint })
    }

    /// Send a request to the Hessra service using HTTP/3
    pub async fn send_request<T, R>(&self, endpoint: &str, request_body: &T) -> Result<R, ApiError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        use bytes::Bytes;
        use h3::client::SendRequest;
        use h3_quinn::quinn::ClientConfig;
        use h3_quinn::Connection;
        use http::{Method, Request, StatusCode};

        let base_url = self.config.get_base_url();
        let server_name = self.config.base_url.clone();
        let port = self.config.port.unwrap_or(443);

        // Connect to server
        let connecting = self
            .endpoint
            .connect(
                (base_url.clone(), port).parse().expect("valid address"),
                &server_name,
            )
            .map_err(|e| ApiError::Http3(format!("Failed to connect: {}", e)))?;

        let connection = connecting
            .await
            .map_err(|e| ApiError::Http3(format!("Connection failed: {}", e)))?;

        // Establish an HTTP/3 connection
        let h3_conn = Connection::new(connection);
        let (mut driver, mut send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| ApiError::Http3(format!("H3 connection failed: {}", e)))?;

        // Spawn the driver to process connection events
        tokio::spawn(async move {
            if let Err(e) = driver.await {
                eprintln!("HTTP/3 driver error: {}", e);
            }
        });

        // Create the request
        let url = format!("https://{}/{}", base_url, endpoint);
        let body = serde_json::to_vec(request_body)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize request: {}", e)))?;

        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header("content-type", "application/json")
            .body(())
            .map_err(|e| ApiError::Http3(format!("Failed to build request: {}", e)))?;

        // Send the request
        let mut send_stream = send_request
            .send_request(request)
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to send request: {}", e)))?;

        send_stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to send request body: {}", e)))?;

        send_stream
            .finish()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to finish request: {}", e)))?;

        // Read the response
        let response = send_stream
            .recv_response()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to receive response: {}", e)))?;

        let status = response.status();

        if status != StatusCode::OK {
            return Err(ApiError::InvalidResponse(format!(
                "HTTP/3 error: {}",
                status
            )));
        }

        // Read response body
        let mut body = Vec::new();
        let mut recv_stream = send_stream;

        while let Some(data) = recv_stream
            .recv_data()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to receive data: {}", e)))?
        {
            body.extend_from_slice(&data);
        }

        // Parse the response
        let result = serde_json::from_slice::<R>(&body)
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

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
                mtls_key: String::new(),
                mtls_cert: String::new(),
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

    /// Set the base URL for the client
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = base_url.into();
        self
    }

    /// Set the mTLS private key for the client
    pub fn mtls_key(mut self, mtls_key: impl Into<String>) -> Self {
        self.config.mtls_key = mtls_key.into();
        self
    }

    /// Set the mTLS certificate for the client
    pub fn mtls_cert(mut self, mtls_cert: impl Into<String>) -> Self {
        self.config.mtls_cert = mtls_cert.into();
        self
    }

    /// Set the server CA certificate for the client
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
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.config.public_key = Some(public_key.into());
        self
    }

    /// Set the personal keypair for service chain attestation
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
            .add_root_certificate(cert_der)
            .build()
            .map_err(|e| ApiError::SslConfig(e.to_string()))?;

        // Format the URL
        let url = match port {
            Some(port) => format!("https://{}:{}/public_key", base_url, port),
            None => format!("https://{}/public_key", base_url),
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
                "HTTP error: {} - {}",
                status, error_text
            )));
        }

        // Parse the response
        let result = response
            .json::<PublicKeyResponse>()
            .await
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

        Ok(result.public_key)
    }

    #[cfg(feature = "http3")]
    pub async fn fetch_public_key_http3(
        base_url: impl Into<String>,
        port: Option<u16>,
        server_ca: impl Into<String>,
    ) -> Result<String, ApiError> {
        use bytes::Bytes;
        use h3::client::SendRequest;
        use h3_quinn::quinn::ClientConfig;
        use h3_quinn::Connection;
        use http::{Method, Request, StatusCode};
        use quinn::{Endpoint, EndpointConfig};
        use rustls::{Certificate, OwnedTrustAnchor, RootCertStore};
        use rustls_pemfile::Item;
        use std::io::Cursor;
        use std::sync::Arc;

        let base_url = base_url.into();
        let server_ca = server_ca.into();
        let port = port.unwrap_or(443);

        // Parse server CA certificate
        let server_ca_pem = Cursor::new(server_ca.as_bytes());
        let mut root_certs = Vec::new();
        for item in rustls_pemfile::read_all(server_ca_pem) {
            match item {
                Ok(Item::X509Certificate(cert)) => root_certs.push(Certificate(cert)),
                _ => {}
            }
        }

        if root_certs.is_empty() {
            return Err(ApiError::SslConfig(
                "Failed to parse server CA certificate".into(),
            ));
        }

        // Build client crypto config
        let mut crypto_builder = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        crypto_builder.enable_early_data = true;
        crypto_builder.enable_sni = true;

        // Create QUIC client config
        let client_config = ClientConfig::new(Arc::new(crypto_builder));

        // Create endpoint
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| ApiError::Http3(format!("Failed to create endpoint: {}", e)))?;

        endpoint.set_default_client_config(client_config);

        // Connect to server
        let connecting = endpoint
            .connect(
                (base_url.clone(), port).parse().expect("valid address"),
                &base_url,
            )
            .map_err(|e| ApiError::Http3(format!("Failed to connect: {}", e)))?;

        let connection = connecting
            .await
            .map_err(|e| ApiError::Http3(format!("Connection failed: {}", e)))?;

        // Establish an HTTP/3 connection
        let h3_conn = Connection::new(connection);
        let (mut driver, mut send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| ApiError::Http3(format!("H3 connection failed: {}", e)))?;

        // Spawn the driver to process connection events
        tokio::spawn(async move {
            if let Err(e) = driver.await {
                eprintln!("HTTP/3 driver error: {}", e);
            }
        });

        // Create the request
        let url = format!("https://{}:{}/public_key", base_url, port);

        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(())
            .map_err(|e| ApiError::Http3(format!("Failed to build request: {}", e)))?;

        // Send the request
        let mut send_stream = send_request
            .send_request(request)
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to send request: {}", e)))?;

        send_stream
            .finish()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to finish request: {}", e)))?;

        // Read the response
        let response = send_stream
            .recv_response()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to receive response: {}", e)))?;

        let status = response.status();

        if status != StatusCode::OK {
            return Err(ApiError::InvalidResponse(format!(
                "HTTP/3 error: {}",
                status
            )));
        }

        // Read response body
        let mut body = Vec::new();
        let mut recv_stream = send_stream;

        while let Some(data) = recv_stream
            .recv_data()
            .await
            .map_err(|e| ApiError::Http3(format!("Failed to receive data: {}", e)))?
        {
            body.extend_from_slice(&data);
        }

        // Parse the response
        let result = serde_json::from_slice::<PublicKeyResponse>(&body)
            .map_err(|e| ApiError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

        Ok(result.public_key)
    }

    /// Request a token for a resource
    pub async fn request_token(&self, resource: String) -> Result<String, ApiError> {
        let request = TokenRequest { resource };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, TokenResponse>("token", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, TokenResponse>("token", &request)
                    .await?
            }
        };

        match response.token {
            Some(token) => Ok(token),
            None => Err(ApiError::TokenRequest(format!(
                "Failed to get token: {}",
                response.response_msg
            ))),
        }
    }

    /// Verify a token for a subject and resource
    pub async fn verify_token(
        &self,
        token: String,
        subject: String,
        resource: String,
    ) -> Result<String, ApiError> {
        let request = VerifyTokenRequest {
            token,
            subject,
            resource,
        };

        let response = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify", &request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Verify a service chain token
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
                    .send_request::<_, VerifyTokenResponse>("verify_service_chain", &request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request::<_, VerifyTokenResponse>("verify_service_chain", &request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }

    /// Get the public key from the server
    pub async fn get_public_key(&self) -> Result<String, ApiError> {
        let url = "public_key";

        let response = match self {
            HessraClient::Http1(client) => {
                // For this endpoint, we just need a GET request, not a POST with a body
                let base_url = client.config.get_base_url();
                let full_url = format!("https://{}/{}", base_url, url);

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
                        "HTTP error: {} - {}",
                        status, error_text
                    )));
                }

                response.json::<PublicKeyResponse>().await.map_err(|e| {
                    ApiError::InvalidResponse(format!("Failed to parse response: {}", e))
                })?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                use bytes::Bytes;
                use h3::client::SendRequest;
                use http::{Method, Request, StatusCode};

                let base_url = client.config.get_base_url();
                let server_name = client.config.base_url.clone();
                let port = client.config.port.unwrap_or(443);

                // Connect to server
                let connecting = client
                    .endpoint
                    .connect(
                        (base_url.clone(), port).parse().expect("valid address"),
                        &server_name,
                    )
                    .map_err(|e| ApiError::Http3(format!("Failed to connect: {}", e)))?;

                let connection = connecting
                    .await
                    .map_err(|e| ApiError::Http3(format!("Connection failed: {}", e)))?;

                // Establish an HTTP/3 connection
                let h3_conn = Connection::new(connection);
                let (mut driver, mut send_request) = h3::client::new(h3_conn)
                    .await
                    .map_err(|e| ApiError::Http3(format!("H3 connection failed: {}", e)))?;

                // Spawn the driver to process connection events
                tokio::spawn(async move {
                    if let Err(e) = driver.await {
                        eprintln!("HTTP/3 driver error: {}", e);
                    }
                });

                // Create the request
                let url = format!("https://{}/{}", base_url, url);

                let request = Request::builder()
                    .method(Method::GET)
                    .uri(url)
                    .body(())
                    .map_err(|e| ApiError::Http3(format!("Failed to build request: {}", e)))?;

                // Send the request
                let mut send_stream = send_request
                    .send_request(request)
                    .await
                    .map_err(|e| ApiError::Http3(format!("Failed to send request: {}", e)))?;

                send_stream
                    .finish()
                    .await
                    .map_err(|e| ApiError::Http3(format!("Failed to finish request: {}", e)))?;

                // Read the response
                let response = send_stream
                    .recv_response()
                    .await
                    .map_err(|e| ApiError::Http3(format!("Failed to receive response: {}", e)))?;

                let status = response.status();

                if status != StatusCode::OK {
                    return Err(ApiError::InvalidResponse(format!(
                        "HTTP/3 error: {}",
                        status
                    )));
                }

                // Read response body
                let mut body = Vec::new();
                let mut recv_stream = send_stream;

                while let Some(data) = recv_stream
                    .recv_data()
                    .await
                    .map_err(|e| ApiError::Http3(format!("Failed to receive data: {}", e)))?
                {
                    body.extend_from_slice(&data);
                }

                // Parse the response
                serde_json::from_slice::<PublicKeyResponse>(&body).map_err(|e| {
                    ApiError::InvalidResponse(format!("Failed to parse response: {}", e))
                })?
            }
        };

        Ok(response.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    // Test BaseConfig get_base_url method
    #[test]
    fn test_base_config_get_base_url_with_port() {
        let config = BaseConfig {
            base_url: "test.hessra.net".to_string(),
            port: Some(443),
            mtls_key: "".to_string(),
            mtls_cert: "".to_string(),
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
            mtls_key: "".to_string(),
            mtls_cert: "".to_string(),
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
        assert_eq!(builder.config.mtls_cert, "CERT");
        assert_eq!(builder.config.mtls_key, "KEY");
        assert_eq!(builder.config.server_ca, "CA");
        assert_eq!(builder.config.public_key, Some("PUBKEY".to_string()));
        assert_eq!(builder.config.personal_keypair, Some("KEYPAIR".to_string()));
    }
}
