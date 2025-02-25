# Hessra SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/hessra-sdk.svg)](https://crates.io/crates/hessra-sdk)
[![Documentation](https://docs.rs/hessra-sdk/badge.svg)](https://docs.rs/hessra-sdk)
[![License](https://img.shields.io/crates/l/hessra-sdk.svg)](https://github.com/Hessra-Labs/hessra-sdk.rs/blob/main/LICENSE)

A secure, flexible Rust SDK for the Hessra authorization service, providing mTLS-backed token request and verification capabilities.

## Features

- **Secure by Design**: Built-in mutual TLS (mTLS) authentication with the Hessra service
- **Protocol Support**: HTTP/1.1 with optional HTTP/3 (via feature flag)
- **Flexible Configuration**: Multiple ways to configure the client including environment variables, files, and code
- **Procedural Macros**: Simple attribute macros to protect functions and endpoints

## Quick Start

```rust
use hessra_sdk::{HessraClient, Protocol};

// Create a client using the builder pattern
let client = HessraClient::builder()
    .base_url("auth.example.com")
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("certs/client.crt"))
    .mtls_key(include_str!("certs/client.key"))
    .server_ca(include_str!("certs/ca.crt"))
    .build()?;

// Request a token for a protected resource
let token = client.request_token("my-protected-resource".to_string()).await?;

// Verify the token later
let verification = client.verify_token(token, "my-protected-resource".to_string()).await?;
```

## Function Protection with Macros

Protect your functions with simple attribute macros:

```rust
use hessra_macros::request_authorization;

#[request_authorization("my-resource")]
async fn protected_function() {
    // Function is executed after authorization token is obtained
}
```

## Configuration

The SDK offers multiple ways to configure the client:

1. **Builder Pattern**: Explicitly set each option in code
2. **Configuration Files**: Load from JSON or TOML files
3. **Environment Variables**: Use environment variables for configuration
4. **Auto-discovery**: Automatically find configuration in standard locations

See [CONFIG.md](CONFIG.md) for detailed configuration options and examples.

## Installation

Add the SDK to your Cargo.toml:

```toml
[dependencies]
hessra-sdk = "0.1.0"
hessra-macros = "0.1.0"  # For procedural macros
```

For HTTP/3 support:

```toml
[dependencies]
hessra-sdk = { version = "0.1.0", features = ["http3"] }
```

## Examples

Check the [examples directory](examples/) for complete working examples:

- HTTP/1.1 client usage
- HTTP/3 client usage (requires the `http3` feature)
- Configuration loading
- Macro usage

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.
