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

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::error::Error;

use hessra_config::{HessraConfig, Protocol};

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

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub response_msg: String,
    pub public_key: String,
}

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

/// HTTP/3 client implementation (only available with the "http3" feature)
#[cfg(feature = "http3")]
pub struct Http3Client {
    /// Base configuration
    config: BaseConfig,
    /// QUIC endpoint for HTTP/3 connections
    endpoint: quinn::Endpoint,
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

// TODO: Implement HTTP client functionality from src/lib.rs
// This includes the HessraClient, HessraClientBuilder, Http1Client, Http3Client implementations
