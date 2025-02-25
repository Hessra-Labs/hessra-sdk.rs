# Hessra Macros

[![Crates.io](https://img.shields.io/crates/v/hessra-macros.svg)](https://crates.io/crates/hessra-macros)
[![Documentation](https://docs.rs/hessra-macros/badge.svg)](https://docs.rs/hessra-macros)
[![License](https://img.shields.io/crates/l/hessra-macros.svg)](https://github.com/Hessra-Labs/hessra-sdk.rs/blob/main/LICENSE)

Procedural macros for the Hessra authorization service SDK for Rust.

## Overview

This crate provides procedural macros that simplify working with the Hessra authorization service. It is part of the [hessra-sdk](https://crates.io/crates/hessra-sdk) ecosystem.

## Macros

### `request_authorization`

The `request_authorization` macro wraps a function with authorization token request logic. It will request an authorization token for a given resource before executing the wrapped function.

```rust
use hessra_macros::request_authorization;

// With client config parameter
#[request_authorization("my-resource", client_config)]
async fn protected_function(client_config: HessraConfig) {
    // This function will be called after token is obtained
}

// Using global configuration
#[request_authorization("my-resource")]
async fn protected_function_global() {
    // This function will be called after token is obtained
}
```

### `authorize`

The `authorize` macro validates that a token parameter is present in the function signature and can be used for authorization checks.

```rust
use hessra_macros::authorize;

#[authorize("my-resource")]
async fn protected_function(token: &str) {
    // This function will be called if the token is valid
}
```

## Features

- `axum` - Enables integration with the Axum web framework

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](https://github.com/Hessra-Labs/hessra-sdk.rs/blob/main/LICENSE) file for details.
