# Hessra SDK

A Rust client library for interacting with Hessra authentication services.

## Project Structure

The Hessra SDK has been refactored into modular components:

- **hessra-config**: Configuration management
- **hessra-token**: Token verification and attestation
- **hessra-api**: HTTP client for the Hessra service
- **hessra-sdk**: Main SDK that pulls everything together

## Examples and Tests Organization

### Tests

Tests should be organized as follows:

1. **Component-specific tests**:

   - Each component has its own tests in `<component-name>/tests/`
   - Example: `hessra-config/tests/config_test.rs`

2. **Integration tests**:
   - Tests that verify multiple components working together should be in `hessra-sdk/tests/`
   - Example: `hessra-sdk/tests/integration_test.rs`

### Examples

Examples should be organized as follows:

1. **Component-specific examples**:

   - Each component has its own examples in `<component-name>/examples/`
   - Example: `hessra-config/examples/config_methods.rs`

2. **SDK examples**:
   - Examples showcasing the full SDK functionality should be in `hessra-sdk/examples/`
   - These demonstrate how to use multiple components together

## Usage

### Configuration

```rust
use hessra_config::{HessraConfig, Protocol};

// Create a configuration with the builder pattern
let config = HessraConfig::builder()
    .base_url("https://test.hessra.example.com")
    .port(8443)
    .protocol(Protocol::Http1)
    .mtls_cert("-----BEGIN CERTIFICATE-----\nCERT CONTENT\n-----END CERTIFICATE-----")
    .mtls_key("-----BEGIN PRIVATE KEY-----\nKEY CONTENT\n-----END PRIVATE KEY-----")
    .server_ca("-----BEGIN CERTIFICATE-----\nCA CONTENT\n-----END CERTIFICATE-----")
    .build()
    .expect("Failed to build config");
```

### Using the SDK

```rust
use hessra_sdk::{Hessra, ServiceChain, ServiceNode};

// Create an SDK instance
let hessra = Hessra::new(config)
    .expect("Failed to create SDK instance");

// Request a token
let token = hessra.request_token("resource_name")
    .await
    .expect("Failed to request token");

// Verify a token
hessra.verify_token(token, "subject", "resource")
    .await
    .expect("Failed to verify token");
```

## Service Chain Attestation

```rust
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
hessra.verify_service_chain_token_local(
    token,
    "subject",
    "resource",
    &service_chain,
    None,
).expect("Failed to verify service chain token");
```

## Feature Flags

- `http3`: Enables HTTP/3 protocol support
- `toml`: Enables configuration loading from TOML files
- `wasm`: Enables WebAssembly support for token verification

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
