# Hessra SDK

The unified Rust SDK for interacting with Hessra authentication services.

## Overview

This crate provides a unified interface for interacting with Hessra authentication services, combining functionality from three component crates:

- `hessra-token`: Token verification and attestation
- `hessra-config`: Configuration management
- `hessra-api`: HTTP client for the Hessra service

The SDK enables applications to request, verify, and attest authorization tokens for protected resources using mutual TLS (mTLS) for secure client authentication.

## Features

- **Flexible configuration**: Load configuration from various sources (environment variables, files, etc.)
- **Protocol support**: HTTP/1.1 support with optional HTTP/3 via feature flag
- **Mutual TLS**: Strong security with client and server certificate validation
- **Token management**: Request and verify authorization tokens
- **Local verification**: Retrieve and store public keys for local token verification
- **Service chains**: Support for service chain attestation and verification

## Installation

Add the Hessra SDK to your `Cargo.toml`:

```toml
[dependencies]
hessra-sdk = "0.1.0"
```

## Feature Flags

- `http3`: Enables HTTP/3 protocol support
- `toml`: Enables configuration loading from TOML files
- `wasm`: Enables WebAssembly support for token verification

## Usage Examples

### Basic Token Request and Verification

```rust
use hessra_sdk::{Hessra, Protocol};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a Hessra SDK instance
    let hessra = Hessra::builder()
        .base_url("api.hessra.com")
        .port(443)
        .mtls_key(include_str!("certs/client.key"))
        .mtls_cert(include_str!("certs/client.crt"))
        .server_ca(include_str!("certs/ca.crt"))
        .protocol(Protocol::Http1)
        .build()?;

    // Request a token
    let token = hessra.request_token("my-resource").await?;

    // Verify the token
    let result = hessra.verify_token(&token, "user123", "my-resource").await?;
    println!("Token verification result: {}", result);

    Ok(())
}
```

### Service Chain Verification

```rust
use hessra_sdk::{Hessra, ServiceChain, ServiceNode};

// Define a service chain
let service_chain = ServiceChain::builder()
    .add_node(ServiceNode::new("auth-service", "ed25519/123456"))
    .add_node(ServiceNode::new("payment-service", "ed25519/abcdef"))
    .build();

// Verify a service chain token
let result = hessra.verify_service_chain_token(
    &token,
    "user123",
    "my-resource",
    Some("payment-service".to_string()),
).await?;
```

### Loading Configuration from Files

```rust
use hessra_sdk::HessraConfig;

// Load from a JSON file
let config = HessraConfig::from_file("config.json")?;

// Or use TOML with the "toml" feature enabled
#[cfg(feature = "toml")]
let config = HessraConfig::from_toml_file("config.toml")?;

// Create a Hessra SDK instance
let hessra = Hessra::new(config)?;
```

## Component Libraries

This SDK integrates the following component libraries:

1. **hessra-token**: Token verification library

   - Token verification and attestation
   - No networking dependencies
   - WASM-compatible

2. **hessra-config**: Configuration management

   - Load from files, environment variables, etc.
   - Configuration validation

3. **hessra-api**: API client
   - HTTP/1.1 and HTTP/3 support
   - mTLS connection management

## Documentation

For detailed API documentation, run:

```
cargo doc --open
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
