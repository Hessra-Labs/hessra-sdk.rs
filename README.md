# Hessra SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/hessra-sdk.svg)](https://crates.io/crates/hessra-sdk)
[![Documentation](https://docs.rs/hessra-sdk/badge.svg)](https://docs.rs/hessra-sdk)
[![License](https://img.shields.io/crates/l/hessra-sdk.svg)](https://github.com/hessra-labs/hessra-sdk.rs/blob/main/LICENSE)
[![CI Status](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/jcorrv/b2734fbe9a9c147a9dfdeafcdcd6c7b7/raw/hessra-sdk-rs-ci-status.json)](https://github.com/hessra-labs/hessra-sdk.rs/actions/workflows/ci.yml)

A complete Rust SDK for requesting and handling both identity tokens and authorization tokens from the Hessra authentication and authorization services.

## How to use

### With Identity Tokens (Recommended)

- Request an identity token once using mTLS authentication
- Use the identity token for subsequent authorization token requests (no mTLS required)
- Delegate identity tokens to sub-identities for fine-grained access control
- Verify identity and authorization tokens completely offline

### With mTLS Only

- Request authorization tokens directly using mTLS certificates
- Include the authorization token in your request
- Verify and optionally add service chain attestations to the token along the way, completely offline
- Verify the final token, completely offline

## Project Structure

This repository is organized as a Rust workspace with the following components:

- **hessra-sdk**: Main SDK crate that provides a unified API (this is what you'll import)
- **hessra-token**: Authorization token re-exports from sub-crates
- **hessra-token-core**: Core utilities and types shared by token crates
- **hessra-token-authz**: Authorization token creation, verification, and attestation
- **hessra-token-identity**: Identity token creation, verification, delegation, and domain restrictions
- **hessra-config**: Configuration management for the SDK
- **hessra-api**: HTTP client for communicating with Hessra services
- **hessra-ffi**: Foreign Function Interface for other languages
- **hessra-pgrx**: Postgres extension to verify tokens (e.g. Row Level Security)

## Features

- **Dual Authentication**: Support for both mTLS and identity token authentication
- **Identity Tokens**: Hierarchical, delegatable identity tokens for authentication without mTLS
- **Domain-Restricted Identities**: Bind identity tokens to specific domains for multi-tenant and scoped access control
- **Secure by Design**: Tokens are short-lived and narrowly scoped to specific resources and operations
- **Protocol Support**: HTTP/1.1 with optional HTTP/3 (via feature flag)
- **Flexible Configuration**: Multiple ways to configure the client including environment variables, files, and code
- **Token Management**: Request and verify both identity and authorization tokens with strong cryptographic guarantees
- **Service Chain Attestation**: Support for multi-service attestation chains: prove your request went through the proper places
- **Offline Verification**: Verify tokens locally without network calls using cached public keys

## Quick Start

### Using Identity Tokens (Recommended)

```rust
use hessra_sdk::{Hessra, Protocol};

// Create a client with mTLS for initial identity token request
let mut client = Hessra::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("certs/client.crt"))
    .mtls_key(include_str!("certs/client.key"))
    .server_ca(include_str!("certs/ca.crt"))
    .build()?;
client.setup()?;

// Request an identity token (requires mTLS)
let identity_response = client.request_identity_token(None).await?;
let identity_token = identity_response.token;

// Use identity token to request authorization tokens (no mTLS needed)
let auth_token = client.request_token_with_identity(
    "my-protected-resource",
    "read",
    &identity_token
).await?;

// Delegate identity to a sub-identity
let delegated_token = client.attenuate_identity_token(
    &identity_token,
    "urn:hessra:alice:laptop",
    None
)?;
```

### Using mTLS Only

```rust
use hessra_sdk::{Hessra, Protocol};

// Create a client using the builder pattern
let mut client = Hessra::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("certs/client.crt"))
    .mtls_key(include_str!("certs/client.key"))
    .server_ca(include_str!("certs/ca.crt"))
    .build()?;
client.setup()?;

// Request a token for a protected resource
let token = client.request_token(
    "my-protected-resource".to_string(),
    "read".to_string()
).await?;

// Verify the token later
let verification = client.verify_token(
    token,
    "subject".to_string(),
    "my-protected-resource".to_string(),
    "read".to_string()
).await?;
```

## Installation

Add the SDK to your Cargo.toml:

```toml
[dependencies]
hessra-sdk = "0.10"
```

### Feature Flags

Enable optional features based on your needs:

```toml
[dependencies]
hessra-sdk = { version = "0.10", features = ["http3", "toml", "wasm"] }
```

Available features:

- **http3**: Enables HTTP/3 protocol support for improved performance (unstable)
- **toml**: Enables configuration loading from TOML files
- **wasm**: Enables WebAssembly support for token verification and service configuration (currently WIP)

> **Note**: HTTP3 requires building with `RUSTFLAGS='--cfg reqwest_unstable'`. Once reqwest http3 support is stable, this won't be necessary.

## Configuration

The SDK offers multiple ways to configure the client:

1. **Builder Pattern**: Explicitly set each option in code
2. **Configuration Files**: Load from JSON or TOML files (requires `toml` feature)
3. **Environment Variables**: Use environment variables for configuration
4. **Auto-discovery**: Automatically find configuration in standard locations

## Identity Tokens

Identity tokens provide a hierarchical, delegatable authentication mechanism that eliminates the need for mTLS certificates in most scenarios:

```rust
// Request initial identity token (requires mTLS)
let identity_response = client.request_identity_token(Some("urn:hessra:alice")).await?;

// Delegate to a sub-identity (e.g., for a specific device)
let laptop_token = client.attenuate_identity_token(
    &identity_response.token,
    "urn:hessra:alice:laptop",
    Some(chrono::Utc::now() + chrono::Duration::hours(24))
)?;

// Further delegate to an application
let app_token = client.attenuate_identity_token(
    &laptop_token,
    "urn:hessra:alice:laptop:browser",
    Some(chrono::Utc::now() + chrono::Duration::hours(1))
)?;

// Verify identity token locally
client.verify_identity_token_local(
    &app_token,
    "urn:hessra:alice:laptop:browser"
)?;
```

Key benefits of identity tokens:

- **No mTLS Required**: After initial issuance, use identity tokens instead of certificates
- **Hierarchical Delegation**: Create sub-identities with restricted permissions
- **Time-bound**: Each delegation can have its own expiration
- **Offline Verification**: Verify tokens locally without network calls

### Domain-Restricted Identities

For multi-tenant applications or scoped access control, realm identities can mint domain-restricted identity tokens:

```rust
// Realm identity mints a domain-restricted token for a user
let response = realm_client.mint_domain_restricted_identity_token(
    "urn:hessra:tenant1:user123".to_string(),
    Some(3600)  // 1 hour TTL
).await?;

// Use the domain-restricted identity to request authorization
// The domain parameter enables enhanced verification
let auth_token = client.request_token_with_identity(
    "protected-resource",
    "read",
    &response.token.unwrap(),
    Some("urn:hessra:tenant1".to_string())  // Domain context
).await?;
```

Domain-restricted tokens:
- Cannot mint new identities (prevents delegation chains)
- Are bound to a specific domain context
- Get permissions from role-based configuration on the server
- Enable enhanced subject-in-domain verification

## Service Chain Attestation

For multi-service scenarios or anyplace you have concrete security boundaries, you can use service chain attestation:

```rust
use hessra_sdk::{ServiceChain, ServiceNode};

// Define the service chain (order matters!)
let service_chain = ServiceChain::builder()
    .add_node(ServiceNode {
        component: "api-gateway",
        public_key: "ed25519/abcdef1234567890",
    })
    .add_node(ServiceNode {
        component: "processing-service",
        public_key: "ed25519/0987654321fedcba",
    })
    .build();

// gateway-service adds attestation
let gateway_token = gateway_client.attest_service_chain_token(
    token,
    authz_service_pub_key,
    "service_name",
    gateway_keypair
);

// processing-service adds attestation
let processing_token = processing_client.attest_service_chain_token(
    gateway_token,
    authz_service_pub_key,
    "service_name",
    processing_keypair
);

// Verify a token with the service chain
// This token is only valid if it has visited and been attested by
// the gateway-service and processing-service.
client.verify_service_chain_token(
    processing_token,
    "user123",
    "resourcexyz",
    "read",
    &service_chain,
    None,
).await?;
```

**Note:** Service chain verification uses an extended time limit of 10ms (vs 1ms for regular tokens) because each service node adds additional Datalog checks.

## Examples

Check the [examples directory](hessra-sdk/examples/) for complete working examples:

- HTTP/1.1 client usage
- HTTP/3 client usage (requires the `http3` feature)
- Configuration loading
- Identity token usage and delegation
- Service chain attestation

## Continuous Integration

This project uses GitHub Actions for continuous integration testing:

- Runs unit tests across multiple platforms (Linux, macOS) and Rust versions (stable, beta, nightly)
- Performs code linting with rustfmt and clippy
- Executes integration tests using examples
- Generates and publishes code coverage reports
- Runs security audits with cargo-audit
- Automatically builds and deploys documentation
- Publishes to crates.io on new version tags

## Documentation

For detailed API documentation:

- [API Docs on docs.rs](https://docs.rs/hessra-sdk)
- Run locally: `cargo doc --open`

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.
