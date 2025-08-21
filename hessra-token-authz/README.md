# hessra-token-authz

Authorization token implementation for Hessra SDK.

This crate provides functionality for creating, verifying, and attesting authorization tokens using the Biscuit token format.

## Features

- Authorization token creation and verification
- Service chain attestation support
- Multi-party token signoff
- Offline token verification using public keys
- Strong cryptographic guarantees using Biscuit tokens

## Usage

```rust
use hessra_token_authz::{verify_biscuit_local, verify_service_chain_biscuit_local};
use biscuit_auth::PublicKey;

// Verify a simple authorization token
let public_key = PublicKey::from_pem(&public_key_pem)?;
verify_biscuit_local(
    &token,
    public_key,
    "subject",
    "resource",
    "operation"
)?;

// Verify a token with service chain attestations
verify_service_chain_biscuit_local(
    &token,
    public_key,
    "subject",
    "resource",
    "operation",
    &service_chain,
    None
)?;
```

## Service Chain Attestation

Service chains allow tokens to be attested by multiple services in a defined order, providing cryptographic proof that a request passed through the proper authorization checkpoints.

## License

Apache-2.0
