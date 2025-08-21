# hessra-token-identity

Identity token implementation for Hessra SDK.

This crate provides hierarchical, delegatable identity tokens using the Biscuit token format. Identity tokens serve as the authentication layer in the Hessra system, eliminating the need for mTLS certificates in most scenarios.

## Features

- Hierarchical URI-based identities
- Secure delegation to sub-identities
- Time-based expiration controls
- Offline verification using public keys
- Prevention of prefix attacks through strict boundary checking

## Identity Hierarchy

Identity tokens use URI-based identifiers with colon (`:`) delimiters for hierarchy:

```
urn:hessra:alice                    # Base identity
urn:hessra:alice:laptop              # Delegated to device
urn:hessra:alice:laptop:chrome       # Further delegated to application
```

## Usage

```rust
use hessra_token_identity::{create_identity_token, verify_identity_token, add_identity_attenuation_to_token};
use biscuit_auth::{KeyPair, PublicKey};

// Create an identity token
let keypair = KeyPair::from_pem(&keypair_pem)?;
let token = create_identity_token(
    "urn:hessra:alice",
    keypair,
    Default::default()
)?;

// Verify an identity token
let public_key = PublicKey::from_pem(&public_key_pem)?;
verify_identity_token(
    &token,
    public_key,
    "urn:hessra:alice"
)?;

// Delegate to a sub-identity
let attenuated_token = add_identity_attenuation_to_token(
    &token,
    "urn:hessra:alice:laptop",
    keypair,
    Default::default()
)?;
```

## Security Model

### Delegation Restricts Usage

When a token is attenuated (delegated), it becomes MORE restrictive:

1. Alice creates base token for `urn:hessra:alice`
2. Alice attenuates it to `urn:hessra:alice:laptop`
3. The attenuated token works ONLY for `urn:hessra:alice:laptop` and its sub-hierarchies
4. Alice herself cannot use the attenuated token

### All Checks Must Pass

Biscuit enforces that ALL checks in ALL blocks must pass:

- Base block: allows `alice` and `alice:*`
- Attenuation block: allows `alice:laptop` and `alice:laptop:*`
- Result: only `alice:laptop` and `alice:laptop:*` are authorized

## Design Documentation

For detailed design information, see [IDENTITY_TOKEN_DESIGN.md](IDENTITY_TOKEN_DESIGN.md).

## License

Apache-2.0
