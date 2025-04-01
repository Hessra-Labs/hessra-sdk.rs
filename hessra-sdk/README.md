# Hessra SDK

The primary interface for interacting with Hessra authentication services.

## API Reference

This crate integrates functionality from these component crates:

- `hessra-token`: Token verification and attestation
- `hessra-config`: Configuration management
- `hessra-api`: HTTP client for the Hessra service

## Detailed Usage

### Creating a Client

```rust
use hessra_sdk::{HessraClient, Protocol};

// Basic client setup
let client = HessraClient::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .build()?;

// More complete setup with mTLS certificates
let secure_client = HessraClient::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("certs/client.crt"))
    .mtls_key(include_str!("certs/client.key"))
    .server_ca(include_str!("certs/ca.crt"))
    .build()?;

// Loading from environment variables
let env_client = HessraClient::from_env()?;

// Loading from a configuration file
let file_client = HessraClient::from_file("path/to/config.json")?;
```

### Working with Tokens

```rust
// Request a token
let token = client.request_token("resource_name").await?;
println!("Token: {}", token);

// Simple token verification
let verification = client.verify_token(token.clone(), "resource_name").await?;
println!("Valid: {}", verification.is_valid);

// Local token verification (using cached public keys)
let local_verification = client.verify_token_local(token.clone(), "resource_name")?;
println!("Valid locally: {}", local_verification.is_valid);

// Update public keys cache for local verification
client.update_public_keys().await?;
```

### Advanced: Service Chain Attestation

For services that need to verify tokens passed through multiple services:

```rust
use hessra_sdk::{ServiceChain, ServiceNode};

// Define the service chain (order matters!)
let service_chain = ServiceChain::builder()
    .add_node(ServiceNode {
        component: "gateway-service",
        public_key: "ed25519/abcdef1234567890",
    })
    .add_node(ServiceNode {
        component: "processing-service",
        public_key: "ed25519/0987654321fedcba",
    })
    .build();

// Verify a token with the service chain
client.verify_service_chain_token(
    token,
    "user:123",
    "data:read",
    &service_chain,
    None,
).await?;

// Local verification of service chain token
client.verify_service_chain_token_local(
    token,
    "user:123",
    "data:read",
    &service_chain,
    None,
)?;
```

### Error Handling

The SDK provides a comprehensive error handling system:

```rust
use hessra_sdk::error::HessraError;

fn handle_token(token: &str) -> Result<(), HessraError> {
    match client.verify_token_local(token, "resource")? {
        verification if verification.is_valid => {
            println!("Token is valid!");
            Ok(())
        }
        _ => Err(HessraError::InvalidToken("Invalid token".to_string())),
    }
}
```

## Feature Flags

- `http3`: Enables HTTP/3 protocol support via the `hessra-api` crate
- `toml`: Enables TOML configuration file support via the `hessra-config` crate
- `wasm`: Enables WebAssembly support for token verification via the `hessra-token` crate

## Advanced Configuration

### Customizing HTTP Clients

```rust
use hessra_sdk::{HessraClient, Protocol};
use std::time::Duration;

let client = HessraClient::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .timeout(Duration::from_secs(30))
    .retry_attempts(3)
    .retry_backoff(Duration::from_millis(100))
    .build()?;
```

### Using HTTP/3

When the `http3` feature is enabled:

```rust
use hessra_sdk::{HessraClient, Protocol};

let client = HessraClient::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http3)
    .build()?;
```

## License

Licensed under the Apache License, Version 2.0.
