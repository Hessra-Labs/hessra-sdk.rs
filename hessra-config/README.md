# Hessra Config

[![Crates.io](https://img.shields.io/crates/v/hessra-config.svg)](https://crates.io/crates/hessra-config)
[![Documentation](https://docs.rs/hessra-config/badge.svg)](https://docs.rs/hessra-config)
[![License](https://img.shields.io/crates/l/hessra-config.svg)](https://github.com/Hessra-Labs/hessra-sdk.rs/blob/main/LICENSE)

Configuration management for Hessra SDK.

This crate provides structures and utilities for loading and managing configuration for the Hessra authentication system. It supports loading configuration from various sources including environment variables, files, and programmatic configuration.

## Features

- Configuration loading from JSON files
- Configuration loading from environment variables
- Optional TOML file support (enabled by default)
- Builder pattern for programmatic configuration
- Validation of configuration parameters
- Global configuration management

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hessra-config = "0.2.0"
```

## Usage

### Creating a Configuration Manually

```rust
use hessra_config::{HessraConfig, Protocol};

let config = HessraConfig::new(
    "https://test.hessra.net",    // base URL
    Some(443),                     // port (optional)
    Protocol::Http1,               // protocol
    "client-cert-content",         // mTLS certificate
    "client-key-content",          // mTLS key
    "ca-cert-content",             // Server CA certificate
);
```

### Using the Builder Pattern

```rust
use hessra_config::{HessraConfig, Protocol};

let config = HessraConfig::builder()
    .base_url("https://test.hessra.net")
    .port(443)
    .protocol(Protocol::Http1)
    .mtls_cert("client-cert-content")
    .mtls_key("client-key-content")
    .server_ca("ca-cert-content")
    .public_key("server-public-key")
    .personal_keypair("personal-keypair-content")
    .build()
    .unwrap();
```

### Loading from a JSON File

```rust
use hessra_config::HessraConfig;
use std::path::Path;

let config = HessraConfig::from_file(Path::new("./config.json")).unwrap();
```

### Loading from a TOML File

```rust
use hessra_config::HessraConfig;
use std::path::Path;

let config = HessraConfig::from_toml(Path::new("./config.toml")).unwrap();
```

### Loading from Environment Variables

```rust
use hessra_config::HessraConfig;

// Using the prefix "HESSRA" for environment variables
// Looks for HESSRA_BASE_URL, HESSRA_PORT, etc.
//
// Note: keys and certificates should be in PEM format encoded as base64 strings
// when stored as environment variables
let config = HessraConfig::from_env("HESSRA").unwrap();
```

### Automatic Configuration

Automatically attempt to load configuration from environment variables or standard file locations:

```rust
use hessra_config::HessraConfig;

let config = HessraConfig::from_env_or_file("HESSRA").unwrap();
```

### Global Configuration

Set a global configuration that can be accessed throughout your application:

```rust
use hessra_config::{HessraConfig, set_default_config, get_default_config};

// Set the global default config
set_default_config(config).unwrap();

// Later, retrieve the global config
if let Some(config) = get_default_config() {
    println!("Using global config: {}", config.base_url);
}
```

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](https://github.com/Hessra-Labs/hessra-sdk.rs/blob/main/LICENSE) file for details.
