# Hessra API

HTTP client for Hessra authentication services.

This crate provides a client for making HTTP requests to the Hessra authorization service. It supports both HTTP/1.1 and HTTP/3 (as an optional feature) and implements the OpenAPI specification for the Hessra service.

## Features

- HTTP/1.1 client for Hessra services
- Optional HTTP/3 support via the `http3` feature flag
- Implementation of all Hessra API endpoints
- Mutual TLS (mTLS) for secure client authentication
- Proper error handling with custom error types
- Comprehensive test coverage

## Usage

### Creating a Client

```rust
use hessra_api::HessraClient;
use hessra_config::HessraConfig;

// Load configuration from environment variables
let config = HessraConfig::from_env("HESSRA")?;

// Create a client using the configuration
let client = HessraClient::builder()
    .from_config(&config)
    .build()?;

// Or create a client manually
let client = HessraClient::builder()
    .base_url("test.hessra.net")
    .port(443)
    .protocol(Protocol::Http1)
    .mtls_cert(include_str!("../certs/client.crt"))
    .mtls_key(include_str!("../certs/client.key"))
    .server_ca(include_str!("../certs/ca.crt"))
    .public_key("optional-public-key")
    .personal_keypair("optional-keypair")
    .build()?;
```

### Requesting a Token

```rust
// Request a token for a resource
let resource = "example-resource".to_string();
let token = client.request_token(resource.clone()).await?;
```

### Verifying a Token

```rust
// Verify the token
let subject = "example-user".to_string();
let resource = "example-resource".to_string();
let result = client.verify_token(token, subject, resource).await?;
```

### Getting the Public Key

```rust
// Retrieve the server's public key
let public_key = client.get_public_key().await?;

// Or fetch the public key without creating a client
let public_key = HessraClient::fetch_public_key(
    "test.hessra.net",
    Some(443),
    include_str!("../certs/ca.crt"),
).await?;
```

### Verifying a Service Chain Token

```rust
// Verify a service chain token
let result = client.verify_service_chain_token(
    token,
    subject,
    resource,
    Some("component-name".to_string()),
).await?;
```

## HTTP/3 Support

To use HTTP/3, enable the `http3` feature in your Cargo.toml:

```toml
[dependencies]
hessra-api = { version = "0.1.0", features = ["http3"] }
```

Then create a client with the HTTP/3 protocol:

```rust
let client = HessraClient::builder()
    .protocol(Protocol::Http3)
    // ... other configuration
    .build()?;
```

## Error Handling

The API client provides a custom error type `ApiError` that includes detailed information about any errors that occur. Errors are categorized into specific types such as HTTP client errors, SSL configuration errors, token request errors, etc.

```rust
match client.request_token(resource).await {
    Ok(token) => {
        // Use the token
    },
    Err(e) => {
        match e {
            ApiError::HttpClient(e) => {
                // Handle HTTP client error
            },
            ApiError::SslConfig(e) => {
                // Handle SSL configuration error
            },
            // Handle other error types
            _ => {
                // Generic error handling
            }
        }
    }
}
```

## Examples

See the `examples` directory for complete usage examples:

- `client_example.rs`: Basic usage of the HTTP/1.1 client
- `http3_example.rs`: Using the HTTP/3 client (requires the `http3` feature)

## Integration with hessra-config

This crate is designed to work seamlessly with the `hessra-config` crate, which provides configuration management for Hessra services. You can create a client directly from a `HessraConfig` instance, which makes it easy to share configuration between multiple components.
