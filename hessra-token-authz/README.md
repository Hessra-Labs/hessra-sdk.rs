# hessra-token-authz

Authorization token implementation for Hessra SDK.

This crate provides functionality for creating, verifying, and attesting authorization tokens using the Biscuit token format.

## Features

- Authorization token creation and verification
- Service chain attestation support
- Multi-party token signoff
- Domain-restricted authorization tokens
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

## Domain-Restricted Tokens

Authorization tokens can be restricted to a specific domain:

```rust
use hessra_token_authz::{HessraAuthorization, AuthorizationVerifier};
use hessra_token_core::{KeyPair, TokenTimeConfig};

let keypair = KeyPair::new();

// Create a domain-restricted authorization token
let token = HessraAuthorization::new(
    "alice".to_string(),
    "resource1".to_string(),
    "read".to_string(),
    TokenTimeConfig::default(),
)
.domain_restricted("myapp.example.com".to_string())
.issue(&keypair)?;

// Verify with domain context
AuthorizationVerifier::new(token, keypair.public(), "alice", "resource1", "read")
    .with_domain("myapp.example.com".to_string())
    .verify()?;
```

Domain-restricted tokens require the verifier to provide the matching domain context.

## License

Apache-2.0
