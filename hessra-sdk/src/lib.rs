//! # Hessra SDK
//!
//! A Rust client library for interacting with Hessra authentication services.
//!
//! The Hessra SDK provides a robust and flexible way to request and verify authentication tokens
//! for protected resources using mutual TLS (mTLS) for secure client authentication.
//!
//! This crate combines functionality from:
//! - `hessra-token`: Token verification and attestation
//! - `hessra-config`: Configuration management
//! - `hessra-api`: HTTP client for the Hessra service
//!
//! ## Features
//!
//! - **Flexible configuration**: Load configuration from various sources (environment variables, files, etc.)
//! - **Protocol support**: HTTP/1.1 support with optional HTTP/3 via feature flag
//! - **Mutual TLS**: Strong security with client and server certificate validation
//! - **Token management**: Request and verify authorization tokens
//! - **Local verification**: Retrieve and store public keys for local token verification
//! - **Service chains**: Support for service chain attestation and verification
//!
//! ## Feature Flags
//!
//! - `http3`: Enables HTTP/3 protocol support
//! - `toml`: Enables configuration loading from TOML files
//! - `wasm`: Enables WebAssembly support for token verification

use std::error::Error as StdError;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

// Re-export everything from the component crates
pub use hessra_token::{
    // Token attestation
    add_service_node_attenuation,
    // Token verification
    verify_biscuit_local,
    verify_service_chain_biscuit_local,
    // Re-exported biscuit types
    Biscuit,
    KeyPair,
    PublicKey,
    // Service chain types
    ServiceNode,
    // Token errors
    TokenError,
};

pub use hessra_config::{ConfigError, HessraConfig, Protocol};

pub use hessra_api::{
    ApiError, HessraClient, HessraClientBuilder, PublicKeyResponse, TokenRequest, TokenResponse,
    VerifyServiceChainTokenRequest, VerifyTokenRequest, VerifyTokenResponse,
};

/// Errors that can occur in the Hessra SDK
#[derive(Error, Debug)]
pub enum SdkError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// API error
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    /// Token error
    #[error("Token error: {0}")]
    Token(#[from] TokenError),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

/// A chain of service nodes
///
/// Represents an ordered sequence of service nodes that form a processing chain.
/// The order of nodes in the chain is significant - it defines the expected
/// order of processing and attestation.
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

    /// Create a service chain with the given nodes
    pub fn with_nodes(nodes: Vec<ServiceNode>) -> Self {
        Self { nodes }
    }

    /// Create a new service chain builder
    pub fn builder() -> ServiceChainBuilder {
        ServiceChainBuilder::new()
    }

    /// Add a node to the chain
    pub fn add_node(&mut self, node: ServiceNode) -> &mut Self {
        self.nodes.push(node);
        self
    }

    /// Add a node to the chain (builder style)
    pub fn with_node(mut self, node: ServiceNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Get the nodes in the chain
    pub fn nodes(&self) -> &[ServiceNode] {
        &self.nodes
    }

    /// Convert to internal representation for token verification
    fn to_internal(&self) -> Vec<hessra_token::ServiceNode> {
        self.nodes.iter().map(|node| node.clone()).collect()
    }

    /// Load a service chain from a JSON string
    pub fn from_json(json: &str) -> Result<Self, SdkError> {
        let nodes: Vec<ServiceNode> = serde_json::from_str(json)?;
        Ok(Self::with_nodes(nodes))
    }

    /// Load a service chain from a JSON file
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::from_json(&contents)
    }

    /// Load a service chain from a TOML string
    #[cfg(feature = "toml")]
    pub fn from_toml(toml_str: &str) -> Result<Self, SdkError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TomlServiceChain {
            nodes: Vec<ServiceNode>,
        }

        let chain: TomlServiceChain = toml::from_str(toml_str)
            .map_err(|e| SdkError::Generic(format!("TOML parse error: {}", e)))?;

        Ok(Self::with_nodes(chain.nodes))
    }

    /// Load a service chain from a TOML file
    #[cfg(feature = "toml")]
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::from_toml(&contents)
    }
}

/// Builder for a service chain
#[derive(Debug, Default)]
pub struct ServiceChainBuilder {
    nodes: Vec<ServiceNode>,
}

impl ServiceChainBuilder {
    /// Create a new service chain builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node to the chain
    pub fn add_node(mut self, node: ServiceNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Build the service chain
    pub fn build(self) -> ServiceChain {
        ServiceChain::with_nodes(self.nodes)
    }
}

/// Unified SDK for Hessra authentication services
///
/// This struct provides a high-level interface combining functionality
/// from all component crates (config, token, api).
pub struct Hessra {
    client: HessraClient,
    config: HessraConfig,
}

impl Hessra {
    /// Create a new Hessra SDK instance from a configuration
    pub fn new(config: HessraConfig) -> Result<Self, SdkError> {
        let client = HessraClientBuilder::new()
            .from_config(&config)
            .build()
            .map_err(|e| SdkError::Generic(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Create a builder for a Hessra SDK instance
    pub fn builder() -> HessraBuilder {
        HessraBuilder::new()
    }

    /// Request a token for a resource
    pub async fn request_token(&self, resource: impl Into<String>) -> Result<String, SdkError> {
        self.client
            .request_token(resource.into())
            .await
            .map_err(|e| SdkError::Generic(e.to_string()))
    }

    /// Verify a token using the remote Hessra service
    pub async fn verify_token(
        &self,
        token: impl Into<String>,
        subject: impl Into<String>,
        resource: impl Into<String>,
    ) -> Result<String, SdkError> {
        self.client
            .verify_token(token.into(), subject.into(), resource.into())
            .await
            .map_err(|e| SdkError::Generic(e.to_string()))
    }

    /// Verify a token locally using cached public keys
    pub fn verify_token_local(
        &self,
        token: impl AsRef<[u8]>,
        subject: impl AsRef<str>,
        resource: impl AsRef<str>,
    ) -> Result<(), SdkError> {
        let public_key = self
            .config
            .public_key()
            .ok_or_else(|| SdkError::Generic("Public key not configured".to_string()))?;

        verify_biscuit_local(token, public_key, subject, resource).map_err(SdkError::Token)
    }

    /// Verify a service chain token using the remote Hessra service
    pub async fn verify_service_chain_token(
        &self,
        token: impl Into<String>,
        subject: impl Into<String>,
        resource: impl Into<String>,
        component: Option<String>,
    ) -> Result<String, SdkError> {
        self.client
            .verify_service_chain_token(token.into(), subject.into(), resource.into(), component)
            .await
            .map_err(|e| SdkError::Generic(e.to_string()))
    }

    /// Verify a service chain token locally using cached public keys
    pub fn verify_service_chain_token_local(
        &self,
        token: impl AsRef<[u8]>,
        subject: impl AsRef<str>,
        resource: impl AsRef<str>,
        service_chain: &ServiceChain,
        component: Option<String>,
    ) -> Result<(), SdkError> {
        let public_key = self
            .config
            .public_key()
            .ok_or_else(|| SdkError::Generic("Public key not configured".to_string()))?;

        verify_service_chain_biscuit_local(
            token,
            public_key,
            subject,
            resource,
            &service_chain.to_internal(),
            component,
        )
        .map_err(SdkError::Token)
    }

    /// Attenuate a token with service node information
    pub fn attenuate_service_chain_token(
        &self,
        token: impl AsRef<[u8]>,
        service: impl Into<String>,
    ) -> Result<Vec<u8>, SdkError> {
        let keypair_str = self
            .config
            .personal_keypair()
            .ok_or_else(|| SdkError::Generic("Personal keypair not configured".to_string()))?;

        let public_key_str = self
            .config
            .public_key()
            .ok_or_else(|| SdkError::Generic("Public key not configured".to_string()))?;

        // Parse the keypair and public key
        let keypair = KeyPair::from_private_key_pem(&keypair_str)
            .map_err(|e| SdkError::Generic(format!("Failed to parse keypair: {}", e)))?;

        let public_key = PublicKey::from_pem(&public_key_str)
            .map_err(|e| SdkError::Generic(format!("Failed to parse public key: {}", e)))?;

        // Convert token to a Vec<u8> if it isn't already
        let token_vec = token.as_ref().to_vec();

        add_service_node_attenuation(token_vec, public_key, &service.into(), &keypair)
            .map_err(SdkError::Token)
    }

    /// Get the public key from the Hessra service
    pub async fn get_public_key(&self) -> Result<String, SdkError> {
        self.client
            .get_public_key()
            .await
            .map_err(|e| SdkError::Generic(e.to_string()))
    }

    /// Get the client used by this SDK instance
    pub fn client(&self) -> &HessraClient {
        &self.client
    }

    /// Get the configuration used by this SDK instance
    pub fn config(&self) -> &HessraConfig {
        &self.config
    }
}

/// Builder for Hessra SDK instances
#[derive(Default)]
pub struct HessraBuilder {
    config_builder: hessra_config::HessraConfigBuilder,
}

impl HessraBuilder {
    /// Create a new Hessra SDK builder
    pub fn new() -> Self {
        Self {
            config_builder: HessraConfig::builder(),
        }
    }

    /// Set the base URL for the Hessra service
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.base_url(base_url);
        self
    }

    /// Set the mTLS private key
    pub fn mtls_key(mut self, mtls_key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.mtls_key(mtls_key);
        self
    }

    /// Set the mTLS client certificate
    pub fn mtls_cert(mut self, mtls_cert: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.mtls_cert(mtls_cert);
        self
    }

    /// Set the server CA certificate
    pub fn server_ca(mut self, server_ca: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.server_ca(server_ca);
        self
    }

    /// Set the port for the Hessra service
    pub fn port(mut self, port: u16) -> Self {
        self.config_builder = self.config_builder.port(port);
        self
    }

    /// Set the protocol to use
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.config_builder = self.config_builder.protocol(protocol);
        self
    }

    /// Set the public key for token verification
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.public_key(public_key);
        self
    }

    /// Set the personal keypair for service chain attestation
    pub fn personal_keypair(mut self, keypair: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.personal_keypair(keypair);
        self
    }

    /// Build a Hessra SDK instance
    pub fn build(self) -> Result<Hessra, SdkError> {
        let config = self.config_builder.build()?;
        Hessra::new(config)
    }
}

/// Fetch a public key from the Hessra service
///
/// This is a convenience function that doesn't require a fully configured client.
pub async fn fetch_public_key(
    base_url: impl Into<String>,
    port: Option<u16>,
    server_ca: impl Into<String>,
) -> Result<String, SdkError> {
    HessraClient::fetch_public_key(base_url, port, server_ca)
        .await
        .map_err(|e| SdkError::Generic(e.to_string()))
}

/// Fetch a public key from the Hessra service using HTTP/3
///
/// This is a convenience function that doesn't require a fully configured client.
#[cfg(feature = "http3")]
pub async fn fetch_public_key_http3(
    base_url: impl Into<String>,
    port: Option<u16>,
    server_ca: impl Into<String>,
) -> Result<String, SdkError> {
    HessraClient::fetch_public_key_http3(base_url, port, server_ca)
        .await
        .map_err(|e| SdkError::Generic(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
