# Hessra SDK

The primary interface for interacting with Hessra authentication services.

## API Reference

This crate integrates functionality from these component crates:

- `hessra-token`: Token verification, attestation, and multi-party authorization
- `hessra-config`: Configuration management
- `hessra-api`: HTTP client for the Hessra service including multi-party token signing

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
// keys and certs should be base64 encoded PEM
let env_client = HessraClient::from_env()?;

// Loading from a configuration file
let file_client = HessraClient::from_file("path/to/config.json")?;
```

### Working with Tokens

The authorization service requires a client to authenticate itself in order to get a token for it to use for a given operation on a resource. Currently, that means using an mTLS connection where the client/subject identifier is encoded in an x509 client certificate as a Subject Alternative Name (SAN).

```rust
// Request a token
let subject = "user:123";
let resource = "resource1";
let operation = "read";
let token = client.request_token(resource.clone(), operation.clone()).await?;
println!("Token: {}", token);

// Simple token verification. Tries locally then fallsback to service API
let verification = client.verify_token(token.clone(), subject.clone(), resource.clone(), operation.clone()).await?;
println!("Valid: {}", verification.is_valid);

// Local token verification (using cached public keys)
let local_verification = client.verify_token_local(token, subject, resource, operation)?;
println!("Valid locally: {}", local_verification.is_valid);
```

### Advanced: Service Chain Authorization

For services that need to verify tokens passed through multiple services:

```rust
use hessra_sdk::{ServiceChain, ServiceNode};

// gateway-service adds attestation
gateway_token = gateway_client.attest_service_chain_token(token, "resource1", "read");

// processing-service adds attestation
processing_token = processing_client.attest_service_chain_token(gateway_token, "resource1", "read");

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
// This token is only valid if it has visited and been attested by
// the gateway-service and processing-service.
client.verify_service_chain_token(
    processing_token,
    "user:123",
    "resource1",
    "read",
    &service_chain,
    None,
).await?;

// Local verification of service chain token
client.verify_service_chain_token_local(
    processing_token,
    "user:123",
    "resource1",
    "read",
    &service_chain,
    None,
)?;
```

### Multi-Party Authorization

Handle tokens that require signoffs from multiple authorization services:

```rust
use hessra_sdk::Hessra;

// Request a token that may require multi-party authorization
let token_response = client.request_token("sensitive_resource", "admin").await?;

if let Some(pending_signoffs) = token_response.pending_signoffs {
    println!("Token requires {} additional signoffs", pending_signoffs.len());

    // Automatically collect all required signoffs
    let fully_signed_token = client
        .collect_signoffs(token_response, "sensitive_resource", "admin")
        .await?;

    println!("All signoffs collected: {}", fully_signed_token);

    // Verify the fully signed token
    client.verify_token(
        &fully_signed_token,
        "user:123",
        "sensitive_resource",
        "admin"
    ).await?;
} else if let Some(token) = token_response.token {
    println!("Token issued without additional signoffs required");
}

// Manually sign a token at a specific authorization service
let signed_response = client.sign_token(
    "token_to_sign",
    "resource_name",
    "operation"
).await?;
```

### Error Handling

The SDK provides a comprehensive error handling system:

```rust
use hessra_sdk::error::HessraError;

fn handle_token(token: &str) -> Result<(), HessraError> {
    match client.verify_token_local(token, "subject1", "resource1", "operation1")? {
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

WASM support is currently a WIP. Please open an issue if you need WASM or the ability for offline token verification in javascript/typescript.

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
