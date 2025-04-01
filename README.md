# Hessra SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/hessra-sdk.svg)](https://crates.io/crates/hessra-sdk)
[![Documentation](https://docs.rs/hessra-sdk/badge.svg)](https://docs.rs/hessra-sdk)
[![License](https://img.shields.io/crates/l/hessra-sdk.svg)](https://github.com/hessra/hessra-sdk.rs/blob/main/LICENSE)

A secure, flexible Rust SDK for the Hessra authorization service, providing mTLS-backed token request and verification capabilities.

## Project Structure

This repository is organized as a Rust workspace with the following components:

- **hessra-sdk**: Main SDK crate that provides a unified API (this is what you'll import)
- **hessra-token**: Core token verification and attestation functionality
- **hessra-config**: Configuration management for the SDK
- **hessra-api**: HTTP client for communicating with Hessra services

## Features

- **Secure by Design**: Built-in mutual TLS (mTLS) authentication with the Hessra service
- **Protocol Support**: HTTP/1.1 with optional HTTP/3 (via feature flag)
- **Flexible Configuration**: Multiple ways to configure the client including environment variables, files, and code
- **Token Management**: Request and verify authorization tokens with strong cryptographic guarantees
- **Service Chain Attestation**: Support for multi-service attestation chains
- **WebAssembly Support**: Optional WASM compatibility for token verification (via feature flag)

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
let token = client.request_token("my-protected-resource".to_string()).await?;

// Verify the token later
let verification = client.verify_token(token, "my-protected-resource".to_string()).await?;
```

## Installation

Add the SDK to your Cargo.toml:

```toml
[dependencies]
hessra-sdk = "0.5.0"
```

### Feature Flags

Enable optional features based on your needs:

```toml
[dependencies]
hessra-sdk = { version = "0.5.0", features = ["http3", "toml", "wasm"] }
```

Available features:

- **http3**: Enables HTTP/3 protocol support for improved performance
- **toml**: Enables configuration loading from TOML files
- **wasm**: Enables WebAssembly support for token verification

## Configuration

The SDK offers multiple ways to configure the client:

1. **Builder Pattern**: Explicitly set each option in code
2. **Configuration Files**: Load from JSON or TOML files (requires `toml` feature)
3. **Environment Variables**: Use environment variables for configuration
4. **Auto-discovery**: Automatically find configuration in standard locations

## Service Chain Attestation

For multi-service scenarios, you can use service chain attestation:

```rust
use hessra_sdk::{ServiceChain, ServiceNode};

// Create a service chain
let service_chain = ServiceChain::builder()
    .add_node(ServiceNode {
        component: "service1",
        public_key: "ed25519/abcdef1234567890",
    })
    .add_node(ServiceNode {
        component: "service2",
        public_key: "ed25519/0987654321fedcba",
    })
    .build();

// Verify a token with service chain attestation
client.verify_service_chain_token_local(
    token,
    "subject",
    "resource",
    &service_chain,
    None,
)?;
```

## Examples

Check the [examples directory](hessra-sdk/examples/) for complete working examples:

- HTTP/1.1 client usage
- HTTP/3 client usage (requires the `http3` feature)
- Configuration loading
- Service chain attestation

## Documentation

For detailed API documentation:

- [API Docs on docs.rs](https://docs.rs/hessra-sdk)
- Run locally: `cargo doc --open`

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.
