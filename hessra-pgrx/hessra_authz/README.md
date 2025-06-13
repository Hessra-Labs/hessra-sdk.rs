# Hessra AuthZ Extension for PostgreSQL

A PostgreSQL extension for authorization and token verification using Biscuit tokens, built with pgrx.

## Overview

The `hessra_authz` extension provides a lightweight, secure way to manage and verify authorization tokens directly within PostgreSQL. It supports:

- Public key management for token verification
- Service chain verification for multi-service architectures
- Integration with Biscuit tokens (attenuation-based authorization tokens)
- SQL-friendly API for authorization checks

This extension is ideal for applications that use PostgreSQL and need to perform token-based authorization checks directly in database queries.

## Prerequisites

- PostgreSQL 12 or newer
- Rust toolchain (1.65+)
- [pgrx](https://github.com/pgcentralfoundation/pgrx) (PostgreSQL Rust Extension framework)

### Mac Setup

On macOS, set the following environment variables:

```bash
export MACOSX_DEPLOYMENT_TARGET=15.4
export PKG_CONFIG_PATH=/opt/homebrew/opt/icu4c/lib/pkgconfig
```

Consider adding these to your `~/.zshrc` or `~/.bashrc` for persistent setup.

## Installation

1. Install pgrx if you haven't already:

```bash
cargo install cargo-pgrx
cargo pgrx init
```

2. Build and install the extension:

```bash
cargo pgrx install --package hessra_authz
```

3. Enable the extension in your PostgreSQL database:

```sql
CREATE EXTENSION hessra_authz;
```

## Usage

### Managing Public Keys

```sql
-- Add a public key (last parameter sets it as the default key)
SELECT add_public_key('my_key', '-----BEGIN PUBLIC KEY-----\n...', true);

-- Retrieve a key
SELECT get_public_key('my_key');

-- Get the default key
SELECT get_public_key(NULL);

-- Update a key
SELECT update_public_key('my_key', '-----BEGIN PUBLIC KEY-----\n...', false);

-- Delete a key
SELECT delete_public_key('my_key');
```

### Managing Service Chains

```sql
-- Add a service chain
SELECT add_service_chain('payment_flow', '[
  {
    "component": "auth_service",
    "public_key": "ed25519/0123456789abcdef0123456789abcdef"
  },
  {
    "component": "payment_service",
    "public_key": "ed25519/fedcba9876543210fedcba9876543210"
  }
]');

-- Retrieve a service chain
SELECT get_service_chain('payment_flow');

-- Update a service chain
SELECT update_service_chain('payment_flow', '[...]');

-- Delete a service chain
SELECT delete_service_chain('payment_flow');
```

### Verifying Tokens

```sql
-- Verify a token directly
SELECT verify_token(
  'biscuit_token_string',
  '-----BEGIN PUBLIC KEY-----\n...',
  'subject',
  'resource',
  'operation',
  NULL
);

-- Verify a token using a stored key
SELECT verify_token_with_stored_key(
  'biscuit_token_string',
  'my_key',  -- Optional, uses default key if NULL
  'subject',
  'resource_path',
  'operation',
  NULL
);
```

### Integration Example

```sql
-- Create a policy that uses token verification
CREATE POLICY user_data_policy ON user_data
  USING (
    verify_token_with_stored_key(
      current_setting('app.auth_token', true),
      NULL,  -- Use default key
      user_id::text,
      'user_data/' || id::text,
      'create',
      NULL
    ) IS NULL  -- Successful verification returns NULL
  );

-- Enable row-level security
ALTER TABLE user_data ENABLE ROW LEVEL SECURITY;
```

## Development

### Running Tests

```bash
cargo pgrx test --package hessra_authz
```

### Running in Development Mode

```bash
cargo pgrx run --package hessra_authz
```

## About Biscuit Tokens

[Biscuit](https://www.biscuitsec.org/) is an authorization token format built for microservices and distributed systems:

- **Attenuation and Attestation**: Tokens can be restricted and 3rd parties can add attestations
- **Offline verification**: No need to call a central service to verify a biscuit, you only need the public key(s)
- **Cryptographically secure**: Based on public-key cryptography
- **Capability-based**: Tokens contain the necessary authorization information

This extension integrates with the Biscuit token format to enable secure, decentralized authorization directly within PostgreSQL.

## License

This project is licensed under the MIT License.
