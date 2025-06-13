# Hessra Configuration Guide

This guide explains the various ways to configure the Hessra SDK in your application.

## Configuration Options

The Hessra SDK provides a flexible configuration system that allows you to:

1. Create configurations manually with explicit parameters
2. Load configurations from JSON or TOML files
3. Load configurations from environment variables
4. Set a global default configuration for simpler usage
5. Auto-discover configurations from standard locations

## HessraConfig Structure

The core of the configuration system is the `HessraConfig` struct, which contains all the parameters needed to establish a secure connection to the Hessra authorization service:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HessraConfig {
    pub base_url: String,                 // URL of the Hessra service (e.g. test.hessra.net)
    pub port: Option<u16>,                // Port to connect to (optional, default 443)
    pub mtls_cert: String,                // mTLS certificate (PEM-encoded)
    pub mtls_key: String,                 // mTLS private key (PEM-encoded)
    pub server_ca: String,                // Server CA certificate (PEM-encoded)
    pub protocol: Protocol,               // HTTP/1 or HTTP/3, default is HTTP/1
    pub public_key: Option<String>,       // Authorization service's public key for offline token verification
    pub personal_keypair: Option<String>, // This client's keypair for signing attestations for service chain tokens (must be ed25519 or P-256 keypair)
}
```

## Configuration Methods

### 1. Manual Configuration

Create a configuration directly with explicit parameters:

```rust
use hessra_sdk::{HessraConfig, Protocol};

let config = HessraConfig::new(
    "https://auth.example.com",  // base URL
    Some(443),                   // port (optional)
    Protocol::Http1,             // protocol
    include_str!("certs/client.crt"), // mTLS certificate
    include_str!("certs/client.key"),  // mTLS key
    include_str!("certs/ca.crt"),      // Server CA certificate
);
```

### 2. File-Based Configuration

Load a configuration from a JSON file:

```rust
use hessra_sdk::HessraConfig;
use std::path::Path;

let config = HessraConfig::from_file(Path::new("./config.json"))
    .expect("Failed to load configuration");
```

Example JSON configuration file:

```json
{
  "base_url": "https://auth.example.com",
  "port": 443,
  "mtls_cert": "-----BEGIN CERTIFICATE-----\n...",
  "mtls_key": "-----BEGIN PRIVATE KEY-----\n...",
  "server_ca": "-----BEGIN CERTIFICATE-----\n...",
  "protocol": "Http1"
}
```

With the "toml" feature enabled, you can also load from TOML files:

```rust
use hessra_sdk::HessraConfig;
use std::path::Path;

let config = HessraConfig::from_toml(Path::new("./config.toml"))
    .expect("Failed to load configuration");
```

Example TOML configuration file:

```toml
base_url = "https://auth.example.com"
port = 443
mtls_cert = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
mtls_key = """
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"""
server_ca = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
protocol = "Http1"
```

### 3. Environment Variable Configuration

Load a configuration from environment variables:

```rust
use hessra_sdk::HessraConfig;

// Loads from environment variables with the "HESSRA_" prefix
let config = HessraConfig::from_env("HESSRA")
    .expect("Failed to load configuration from environment");
```

Environment variables:

- `{PREFIX}_BASE_URL`: URL of the Hessra service
- `{PREFIX}_PORT`: Port to connect to (optional, default 443)
- `{PREFIX}_MTLS_CERT`: mTLS certificate (PEM-format, base64 encoded)
- `{PREFIX}_MTLS_KEY`: mTLS private key (PEM-format, base64 encoded)
- `{PREFIX}_SERVER_CA`: Server CA certificate (PEM-format, base64 encoded)
- `{PREFIX}_PUBLIC_KEY`: The authorization service's public key (PEM-format, base64 encoded)
- `{PREFIX}_PERSONAL_KEYPAIR`: This client/node's keypair to attest service chain tokens with (PEM-format, base64 encoded. MUST BE either ed25519 or P-256. Can be the same as MTLS_KEY)
- `{PREFIX}_PROTOCOL`: "http1" or "http3" (optional, defaults to "http1")

### 4. Environment Variables with File Paths

Load a configuration from environment variables that can point to files:

```rust
use hessra_sdk::HessraConfig;

// Loads from environment variables with the "HESSRA_" prefix
let config = HessraConfig::from_env_or_file("HESSRA")
    .expect("Failed to load configuration from environment");
```

Environment variables:

- `{PREFIX}_BASE_URL`: URL of the Hessra service
- `{PREFIX}_PORT`: Port to connect to (optional)
- One of the following for each credential:
  - `{PREFIX}_MTLS_CERT`: mTLS certificate content, or
  - `{PREFIX}_MTLS_CERT_FILE`: Path to a file containing the mTLS certificate
  - `{PREFIX}_MTLS_KEY`: mTLS private key content, or
  - `{PREFIX}_MTLS_KEY_FILE`: Path to a file containing the mTLS private key
  - `{PREFIX}_SERVER_CA`: Server CA certificate content, or
  - `{PREFIX}_SERVER_CA_FILE`: Path to a file containing the server CA certificate
- `{PREFIX}_PROTOCOL`: "http1" or "http3" (optional, defaults to "http1")

### 5. Global Configuration

Set and use a global default configuration:

```rust
use hessra_sdk::{HessraConfig, Protocol, set_default_config, get_default_config};

// Set up the global configuration
let config = HessraConfig::new(
    "https://auth.example.com",
    Some(443),
    Protocol::Http1,
    "CERT CONTENT",
    "KEY CONTENT",
    "CA CONTENT",
);

// Set as the default configuration (can only be done once)
set_default_config(config).expect("Failed to set default configuration");

// Later in your code, get the default configuration
let default_config = get_default_config()
    .expect("No default configuration set");
```

### 6. Auto-Discovery

Automatically discover configuration from standard locations:

```rust
use hessra_sdk::{try_load_default_config, set_default_config};

// Try to load a default configuration from standard locations
if let Some(config) = try_load_default_config() {
    // Use the loaded configuration
    set_default_config(config).expect("Failed to set default configuration");
} else {
    eprintln!("No configuration found in standard locations");
}
```

This function checks the following locations in order:

1. Environment variables with the prefix "HESSRA"
2. A file at ./hessra.json
3. A file at ~/.hessra/config.json
4. A file at /etc/hessra/config.json
5. If the "toml" feature is enabled, it also tries TOML files with the same paths

## Using with Macros

The Hessra SDK provides macros for authorization that can work with the configuration system:

```rust
use hessra_macros::request_authorization;
use hessra_sdk::{HessraConfig, set_default_config};

// Set up a global configuration
let config = HessraConfig::from_file("./config.json").expect("Failed to load config");
set_default_config(config).expect("Failed to set default config");

// Use the global configuration with the macro
#[request_authorization("my-resource")]
async fn protected_function() {
    // This function will be called after token is obtained using global config
}

// Or provide a specific config parameter
#[request_authorization("my-resource", client_config)]
async fn custom_protected_function(client_config: &HessraConfig) {
    // This function will be called after token is obtained using the provided config
}
```

## Error Handling

The configuration system provides detailed error messages to help diagnose issues:

```rust
use hessra_sdk::HessraConfig;

match HessraConfig::from_env("HESSRA") {
    Ok(config) => {
        // Use the config
        println!("Configuration loaded successfully");
    },
    Err(e) => {
        // Handle the error with detailed information
        eprintln!("Configuration error: {}", e);
    }
}
```

## Feature Flags

- `http3`: Enables HTTP/3 protocol support
- `toml`: Enables TOML configuration file support

To enable these features, add them to your Cargo.toml:

```toml
[dependencies]
hessra-sdk = { version = "0.8.0", features = ["http3", "toml"] }
```
