# Hessra SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/hessra-sdk.svg)](https://crates.io/crates/hessra-sdk)
[![Documentation](https://docs.rs/hessra-sdk/badge.svg)](https://docs.rs/hessra-sdk)
[![License](https://img.shields.io/crates/l/hessra-sdk.svg)](https://github.com/hessra-labs/hessra-sdk.rs/blob/main/LICENSE)
[![CI Status](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/jcorrv/b2734fbe9a9c147a9dfdeafcdcd6c7b7/raw/hessra-sdk-rs-ci-status.json)](https://github.com/hessra-labs/hessra-sdk.rs/actions/workflows/ci.yml)

A complete rust SDK for requesting and handling authorization tokens from the Hessra authorization service.

## How to use

- Request your authorization token before you make your request
- Include the authorization token in your request
- verify and optionally add service chain attestations to the token along the way, completely offline
- verify the final token, completely offline

## Project Structure

This repository is organized as a Rust workspace with the following components:

- **hessra-sdk**: Main SDK crate that provides a unified API (this is what you'll import)
- **hessra-token**: Core token creation, verification, and attestation functionality
- **hessra-config**: Configuration management for the SDK
- **hessra-api**: HTTP client for communicating with Hessra services
- **hessra-ffi**: Foreign Function Interface for other languages
- **hessra-pgrx**: Postgres extension to verify tokens (e.g. Row Level Security)

## Features

- **Secure by Design**: tokens are short-lived and narrowly scoped to a single request
- **Protocol Support**: HTTP/1.1 with optional HTTP/3 (via feature flag)
- **Flexible Configuration**: Multiple ways to configure the client including environment variables, files, and code
- **Token Management**: Request and verify authorization tokens with strong cryptographic guarantees
- **Service Chain Attestation**: Support for multi-service attestation chains: prove your request went through the proper places

## Quick Start

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
hessra-sdk = "0.8"
```

### Feature Flags

Enable optional features based on your needs:

```toml
[dependencies]
hessra-sdk = { version = "0.8", features = ["http3", "toml", "wasm"] }
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

## Examples

Check the [examples directory](hessra-sdk/examples/) for complete working examples:

- HTTP/1.1 client usage
- HTTP/3 client usage (requires the `http3` feature)
- Configuration loading
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
