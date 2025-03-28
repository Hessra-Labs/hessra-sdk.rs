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
};

pub use hessra_config::{ConfigError, HessraConfig, Protocol};

pub use hessra_api::{
    HessraClient, HessraClientBuilder, PublicKeyResponse, TokenRequest, TokenResponse,
    VerifyServiceChainTokenRequest, VerifyTokenRequest, VerifyTokenResponse,
};

// TODO: Implement service chain types from src/lib.rs
// This includes ServiceNode and ServiceChain implementations

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

// TODO: Implement ServiceChain methods from src/lib.rs

// TODO: Define and implement any additional high-level functionality
// that combines features from multiple component crates
