# hessra-token-core

Core utilities and types for Hessra token SDKs.

This crate provides shared functionality used by both authorization tokens (`hessra-token-authz`) and identity tokens (`hessra-token-identity`).

## Features

- Common error types for token operations
- Biscuit token utilities and helpers
- Time configuration structures
- Base64 encoding/decoding utilities
- Cryptographic key management helpers

## Usage

This crate is typically not used directly. Instead, use one of:

- `hessra-token-authz` for authorization tokens
- `hessra-token-identity` for identity tokens
- `hessra-token` for the combined interface
- `hessra-sdk` for the complete SDK

## License

Apache-2.0
