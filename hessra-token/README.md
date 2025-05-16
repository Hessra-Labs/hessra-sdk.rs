# Hessra Token

Core verification library for Hessra authentication tokens.

This crate provides functionality for creating, verifying and attenuating biscuit tokens
used in the Hessra authentication system. It is designed to be WASM-compatible
and has no networking dependencies.

## Features

- **Token creation**: Create new tokens with configurable time settings and operations
- **Token verification**: Verify tokens without contacting the authorization server
- **Token attestation**: Add service node attestations to tokens
- **WASM compatibility**: Can be compiled to WebAssembly for use in browsers (via the `wasm` feature)

## Usage

### Creating Tokens

```rust
use hessra_token::{create_biscuit, create_service_chain_biscuit, TokenTimeConfig, KeyPair};

fn main() -> Result<(), hessra_token::TokenError> {
    // Create a key pair for token signing
    let keypair = KeyPair::new();

    // Create a basic token with default time settings (5 minutes)
    let token = create_biscuit(
        "user123".to_string(),
        "resource456".to_string(),
        "read".to_string(),
        keypair,
        TokenTimeConfig::default(),
    )?;

    // Create a token with custom time settings
    let custom_time = TokenTimeConfig {
        start_time: Some(chrono::Utc::now().timestamp()),
        duration: 3600, // 1 hour
    };

    let custom_token = create_biscuit(
        "user123".to_string(),
        "resource456".to_string(),
        "read".to_string(),
        keypair,
        custom_time,
    )?;

    println!("Tokens created successfully!");
    Ok(())
}
```

### Creating Service Chain Tokens

```rust
use hessra_token::{create_service_chain_biscuit, ServiceNode, KeyPair};

fn main() -> Result<(), hessra_token::TokenError> {
    let keypair = KeyPair::new();

    // Define service nodes in the chain
    let service_nodes = vec![
        ServiceNode {
            component: "auth_service".to_string(),
            public_key: "ed25519/service1key".to_string(),
        },
        ServiceNode {
            component: "payment_service".to_string(),
            public_key: "ed25519/service2key".to_string(),
        },
    ];

    // Create a service chain token
    let token = create_service_chain_biscuit(
        "user123".to_string(),
        "resource456".to_string(),
        "read".to_string(),
        keypair,
        &service_nodes,
    )?;

    println!("Service chain token created successfully!");
    Ok(())
}
```

### Basic Token Verification

```rust
use hessra_token::{verify_token, biscuit_key_from_string};

fn main() -> Result<(), hessra_token::TokenError> {
    // Your URL-safe base64-encoded token
    let token_base64 = "YOUR_TOKEN_STRING";

    // Parse public key from string format (ed25519/{hex} or secp256r1/{hex})
    let public_key = biscuit_key_from_string("ed25519/01234567890abcdef".to_string())?;

    // Verify the token
    verify_token(token_base64, public_key, "user123", "resource456", "read")?;

    println!("Token verification successful!");
    Ok(())
}
```

### Service Chain Verification

For tokens that need to be verified against a chain of service nodes:

```rust
use hessra_token::{verify_service_chain_token, biscuit_key_from_string, ServiceNode};

fn main() -> Result<(), hessra_token::TokenError> {
    let token_base64 = "YOUR_TOKEN_STRING";
    let public_key = biscuit_key_from_string("ed25519/01234567890abcdef".to_string())?;

    // Define the service chain
    let service_nodes = vec![
        ServiceNode {
            component: "service1".to_string(),
            public_key: "ed25519/service1pubkey".to_string(),
        },
        ServiceNode {
            component: "service2".to_string(),
            public_key: "ed25519/service2pubkey".to_string(),
        },
    ];

    // Verify the token with service chain
    verify_service_chain_token(
        token_base64,
        public_key,
        "user123",
        "resource456",
        "write",
        service_nodes,
        None, // Verify full chain, or specify a component to verify up to
    )?;

    println!("Token verification successful!");
    Ok(())
}
```

### Token Attenuation

To add service node attestations to tokens:

```rust
use hessra_token::{add_service_node_attenuation, decode_token, encode_token, KeyPair, PublicKey};

fn main() -> Result<(), hessra_token::TokenError> {
    let token_base64 = "YOUR_TOKEN_STRING";
    let token_bytes = decode_token(token_base64)?;

    // Public key for token verification
    let public_key = PublicKey::from_bytes(b"example_key", biscuit_auth::Algorithm::Ed25519)?;

    // Service node key pair
    let service_keypair = KeyPair::new();

    // Add service node attenuation
    let attenuated_token = add_service_node_attenuation(
        token_bytes,
        public_key,
        "my-service",
        &service_keypair,
    )?;

    // Encode back to URL-safe base64 for storage or transmission
    let attenuated_token_base64 = encode_token(&attenuated_token);

    println!("Token attenuated: {}", attenuated_token_base64);
    Ok(())
}
```

## WebAssembly Support

To compile with WebAssembly support, enable the `wasm` feature:

```toml
[dependencies]
hessra-token = { version = "0.3", features = ["wasm"] }
```

## Lower-level API

If you need more control, lower-level functions are also available:

- `verify_biscuit_local` - Directly verify binary token data
- `verify_service_chain_biscuit_local` - Verify binary token data with service chain
- `parse_token` - Parse a URL-safe base64 token string into a Biscuit for inspection
- `decode_token` - Convert URL-safe base64 encoded token to binary data
- `encode_token` - Convert binary token data to URL-safe base64 string

## Development

This crate is part of the Hessra SDK refactoring project. It provides the token functionality
that was previously part of the monolithic SDK.

## Token Operations

The library supports specifying operations when creating and verifying tokens. Common operations include:

- `read`: Read access to a resource
- `write`: Write access to a resource
- `delete`: Delete access to a resource
- `admin`: Administrative access to a resource

You can define your own operations as needed for your application.

## Service Chain Tokens

For service chain tokens, you can specify operations in the same way:

```rust
use hessra_token::{create_service_chain_token, verify_service_chain_token_local, ServiceNode};

let nodes = vec![
    ServiceNode {
        component: "auth_service".to_string(),
        public_key: "ed25519/...".to_string(),
    }
];

let token = create_service_chain_token(
    "user123".to_string(),
    "resource456".to_string(),
    "read".to_string(),
    keypair,
    &nodes,
)?;

verify_service_chain_token_local(
    &token,
    public_key,
    "user123",
    "resource456",
    "read",
    nodes,
    None,
)?;
```

## Low-Level Functions

If you need more control, lower-level functions are also available:

- `verify_biscuit_local` - Directly verify binary token data
- `verify_service_chain_biscuit_local` - Verify binary token data with service chain
- `parse_token` - Parse a URL-safe base64 token string into a Biscuit for inspection
- `decode_token` - Convert URL-safe base64 encoded token to binary data
- `encode_token` - Convert binary token data to URL-safe base64 string

## Development

This crate is part of the Hessra SDK refactoring project. It provides the token functionality
that was previously part of the monolithic SDK.
