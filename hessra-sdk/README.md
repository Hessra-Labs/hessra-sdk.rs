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
use hessra_sdk::{Hessra, Protocol};

// Basic client setup
let client = Hessra::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .build()?;

// More complete setup with mTLS certificates
let mut secure_client = Hessra::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("certs/client.crt"))
    .mtls_key(include_str!("certs/client.key"))
    .server_ca(include_str!("certs/ca.crt"))
    .build()?;
// Finishes setting up the client by making API calls to the Hessra
// service for its token signing public key
secure_client.setup()?;

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

// Simple token verification. Tries locally then fallsback to service API
let verification = client.verify_token(token.clone(), "resource_name").await?;
println!("Valid: {}", verification.is_valid);

// Local token verification (using cached public keys)
let local_verification = client.verify_token_local(token.clone(), "resource_name")?;
println!("Valid locally: {}", local_verification.is_valid);
```

### Advanced: Service Chain Authorization

For services that need to verify tokens passed through multiple services:

```rust
use hessra_sdk::{ServiceChain, ServiceNode};

// gateway-service adds attenuation
gateway_token = gateway_client.attenuate_service_chain_token(token, "data:read");

// processing-service adds attenuation
processing_token = processing_client.attenuate_service_chain_token(gateway_token, "data:read");

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
// This token is only valid if it has visited and been attenuated by
// the gateway-service and processing-service.
client.verify_service_chain_token(
    processing_token,
    "user:123",
    "data:read",
    &service_chain,
    None,
).await?;

// Local verification of service chain token
client.verify_service_chain_token_local(
    processing_token,
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

Note: http3 support is currently unstable since it relies on reqwest's implementation which
is also unstable. Once reqwest's http3 is stable, it will be here too.

WASM support is currently a WIP.

- `toml`: Enables TOML configuration file support via the `hessra-config` crate
- `http3`: Enables HTTP/3 protocol support via the `hessra-api` crate
- `wasm`: Enables WebAssembly support for token verification via the `hessra-token` crate

### Using HTTP/3

When the `http3` feature is enabled:

```rust
use hessra_sdk::{HessraClient, Protocol};

let client = HessraClient::builder()
    .base_url("yourco.hessra.net")
    .protocol(Protocol::Http3)
    .build()?;
```

requires building with `RUSTFLAGS='--cfg reqwest_unstable'`
Once reqwest http3 support is stable, this won't be necessary.

## License

Licensed under the Apache License, Version 2.0.
