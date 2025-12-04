# hessra-token-identity

Identity token implementation for Hessra SDK.

This crate provides hierarchical, delegatable identity tokens using the Biscuit token format. Identity tokens serve as the authentication layer in the Hessra system, eliminating the need for mTLS certificates in most scenarios.

## Features

- Hierarchical URI-based identities
- Secure delegation to sub-identities
- Time-based expiration controls
- Offline verification using public keys
- Prevention of prefix attacks through strict boundary checking
- Domain-restricted identity tokens
- Token inspection for extracting identity metadata
- Short-lived (JIT) tokens for secure network transmission

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

## Token Types

The crate supports three types of identity tokens:

### Delegatable Tokens (Default)

Standard identity tokens that can be delegated to sub-identities:

```rust
use hessra_token_identity::HessraIdentity;
use hessra_token_core::{KeyPair, TokenTimeConfig};

let token = HessraIdentity::new("urn:hessra:alice".to_string(), TokenTimeConfig::default())
    .delegatable(true)  // Default
    .issue(&keypair)?;
```

### Non-Delegatable Tokens

Fixed identity tokens that cannot be delegated further:

```rust
let token = HessraIdentity::new("urn:hessra:alice".to_string(), TokenTimeConfig::default())
    .delegatable(false)
    .issue(&keypair)?;
```

### Domain-Restricted Tokens

Identity tokens bound to a specific domain:

```rust
let token = HessraIdentity::new("urn:hessra:alice".to_string(), TokenTimeConfig::default())
    .domain_restricted("myapp.example.com".to_string())
    .issue(&keypair)?;
```

Domain-restricted tokens require the verifier to provide matching domain context.

## Token Inspection

Extract metadata from tokens without verification:

```rust
use hessra_token_identity::inspect_identity_token;

let result = inspect_identity_token(token, public_key)?;

println!("Identity: {}", result.identity);
println!("Expired: {}", result.is_expired);
println!("Delegated: {}", result.is_delegated);
println!("Domain: {:?}", result.domain);
println!("Expiry: {:?}", result.expiry);
```

The `InspectResult` contains:
- `identity` - The subject or most specific delegated identity
- `expiry` - Unix timestamp when the token expires
- `is_expired` - Whether the token is currently expired
- `is_delegated` - Whether the token has delegation blocks
- `domain` - Domain restriction if present

## Short-Lived (JIT) Tokens

Create ultra-short-lived tokens (5 seconds) for secure network transmission:

```rust
use hessra_token_identity::create_short_lived_identity_token;

// Create a short-lived version of an existing token
let jit_token = create_short_lived_identity_token(long_lived_token, public_key)?;

// Send over the network - expires in 5 seconds
send_to_server(jit_token);
```

This pattern keeps long-lived tokens secure on the client while transmitting short-lived versions.

## Verification with Domain Context

For domain-restricted tokens, use the builder pattern:

```rust
use hessra_token_identity::IdentityVerifier;

IdentityVerifier::new(token, public_key)
    .with_identity("urn:hessra:alice".to_string())
    .with_domain("myapp.example.com".to_string())
    .verify()?;
```

## Design Documentation

For detailed design information, see [IDENTITY_TOKEN_DESIGN.md](IDENTITY_TOKEN_DESIGN.md).

## License

Apache-2.0
