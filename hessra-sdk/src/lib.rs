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
        self.nodes.to_vec()
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
        let public_key_str = match &self.config.public_key {
            Some(key) => key,
            None => return Err(SdkError::Generic("Public key not configured".to_string())),
        };

        let public_key = hessra_token::biscuit_key_from_string(public_key_str.clone())?;

        // Convert token to Vec<u8>
        let token_vec = token.as_ref().to_vec();

        verify_biscuit_local(
            token_vec,
            public_key,
            subject.as_ref().to_string(),
            resource.as_ref().to_string(),
        )
        .map_err(SdkError::Token)
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
        let public_key_str = match &self.config.public_key {
            Some(key) => key,
            None => return Err(SdkError::Generic("Public key not configured".to_string())),
        };

        let public_key = hessra_token::biscuit_key_from_string(public_key_str.clone())?;

        // Convert token to Vec<u8>
        let token_vec = token.as_ref().to_vec();

        verify_service_chain_biscuit_local(
            token_vec,
            public_key,
            subject.as_ref().to_string(),
            resource.as_ref().to_string(),
            service_chain.to_internal(),
            component,
        )
        .map_err(SdkError::Token)
    }

    /// Attenuate a service chain token with a new service node attestation
    pub fn attenuate_service_chain_token(
        &self,
        token: impl AsRef<[u8]>,
        service: impl Into<String>,
    ) -> Result<Vec<u8>, SdkError> {
        let _keypair_str = match &self.config.personal_keypair {
            Some(keypair) => keypair,
            None => {
                return Err(SdkError::Generic(
                    "Personal keypair not configured".to_string(),
                ))
            }
        };

        let public_key_str = match &self.config.public_key {
            Some(key) => key,
            None => return Err(SdkError::Generic("Public key not configured".to_string())),
        };

        // Parse keypair from string to KeyPair
        let keypair = KeyPair::new(); // This is a placeholder - we need to implement proper PEM parsing

        // Parse public key from string
        let public_key = hessra_token::biscuit_key_from_string(public_key_str.clone())?;

        // Convert token to Vec<u8>
        let token_vec = token.as_ref().to_vec();

        // Convert service to String
        let service_str = service.into();

        add_service_node_attenuation(token_vec, public_key, &service_str, &keypair)
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
        // Create a simple service chain with two nodes
        let json = r#"[
            {
                "component": "service1",
                "public_key": "ed25519/abcdef1234567890"
            },
            {
                "component": "service2",
                "public_key": "ed25519/0987654321fedcba"
            }
        ]"#;

        let service_chain = ServiceChain::from_json(json).unwrap();
        assert_eq!(service_chain.nodes().len(), 2);
        assert_eq!(service_chain.nodes()[0].component, "service1");
        assert_eq!(
            service_chain.nodes()[0].public_key,
            "ed25519/abcdef1234567890"
        );
        assert_eq!(service_chain.nodes()[1].component, "service2");
        assert_eq!(
            service_chain.nodes()[1].public_key,
            "ed25519/0987654321fedcba"
        );

        // Test adding a node
        let mut chain = ServiceChain::new();
        let node = ServiceNode {
            component: "service3".to_string(),
            public_key: "ed25519/1122334455667788".to_string(),
        };
        chain.add_node(node);
        assert_eq!(chain.nodes().len(), 1);
        assert_eq!(chain.nodes()[0].component, "service3");
    }

    #[test]
    fn test_service_chain_builder() {
        let builder = ServiceChainBuilder::new();
        let node1 = ServiceNode {
            component: "auth".to_string(),
            public_key: "ed25519/auth123".to_string(),
        };
        let node2 = ServiceNode {
            component: "payment".to_string(),
            public_key: "ed25519/payment456".to_string(),
        };

        let chain = builder.add_node(node1).add_node(node2).build();

        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(chain.nodes()[0].component, "auth");
        assert_eq!(chain.nodes()[1].component, "payment");
    }
}
