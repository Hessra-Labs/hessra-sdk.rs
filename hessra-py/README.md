# Hessra Python SDK

Python bindings for the Hessra authentication and authorization system.

## Overview

This Python package provides bindings to the Rust-based Hessra SDK, enabling Python applications to:

- Request and verify identity tokens
- Delegate identity tokens to sub-identities
- Mint domain-restricted identity tokens
- Verify Biscuit authorization tokens (locally and remotely)
- Request authorization tokens using identity token authentication
- Manage service chain token attestation
- Handle mTLS-authenticated communication with Hessra services
- Configure and manage authorization settings

## Installation

### From PyPI

```bash
# With uv
uv add hessra-py

# With pip
pip install hessra-py
```

### From Source

```bash
cd hessra-py

# Sync development dependencies (includes maturin)
uv sync --dev

# Build and install in development mode
uv run maturin develop

# Or build wheel and install
uv run maturin build --release
uv add target/wheels/hessra_py-*.whl
```

## Requirements

- Python 3.8+ (recommended: Python 3.12)
- [uv](https://docs.astral.sh/uv/) for Python package management
- Rust toolchain (for building from source)

## Quick Start

The Python SDK connects to your Hessra authorization service using the same test certificates as the Rust SDK examples.

```python
import hessra_py

# Load certificates (same as used in Rust SDK examples)
mtls_cert = open("../certs/client.crt").read()
mtls_key = open("../certs/client.key").read()
server_ca = open("../certs/ca-2030.pem").read()

# Create configuration
config = (hessra_py.HessraConfig.builder()
    .base_url("test.hessra.net")
    .port(443)
    .protocol("http1")
    .mtls_cert(mtls_cert)
    .mtls_key(mtls_key)
    .server_ca(server_ca)
    .build())

# Create client and setup with public key
client = hessra_py.HessraClient(config)
client_with_key = client.setup_new()

# Verify a token locally (requires real Biscuit token)
client_with_key.verify_token_local(
    token="<biscuit_token_base64>",
    subject="uri:urn:test:argo-cli0",
    resource="resource1",
    operation="read"
)

# Create configuration from environment variables
config = hessra_py.HessraConfig.from_env()

# Or build configuration manually
config = (hessra_py.HessraConfig.builder()
    .base_url("your-auth-service.com")
    .port(443)
    .protocol("http1")
    .mtls_cert(your_client_cert)
    .mtls_key(your_client_key)
    .server_ca(your_server_ca)
    .public_key(your_public_key)
    .build())

# Create client
client = hessra_py.HessraClient(config)

# Setup client (fetches public key if needed)
client = client.setup_new()

# Verify a token locally
client.verify_token_local(
    token="your_base64_token",
    subject="user_id",
    resource="api/endpoint",
    operation="read"
)

# Verify token remotely via API
result = client.verify_token_remote(
    token="your_base64_token",
    subject="user_id",
    resource="api/endpoint",
    operation="read"
)
print(f"Verification result: {result}")
```

## Identity Token Operations

The Python SDK supports full identity token management:

### Request Identity Token

Authenticate with mTLS to obtain an identity token:

```python
# Client must be configured with mTLS credentials
response = client.request_identity_token(identifier=None)  # Optional identifier
print(f"Identity: {response.identity}")
print(f"Expires in: {response.expires_in} seconds")
identity_token = response.token
```

### Delegate Identity

Create a delegated identity token for sub-identities:

```python
# Delegate to a more specific identity
delegated_token = client.attenuate_identity_token(
    token=identity_token,
    delegated_identity="urn:hessra:alice:agent",
    duration=3600  # 1 hour, optional (defaults to 1 hour)
)
```

### Verify Identity Token

Verify an identity token locally:

```python
client.verify_identity_token_local(
    token=identity_token,
    identity="urn:hessra:alice"
)
```

### Mint Domain-Restricted Identity

Realm identities can mint domain-restricted tokens:

```python
# Requires authentication as a realm identity (via mTLS or identity token)
response = client.mint_domain_restricted_identity_token(
    subject="urn:hessra:mycompany:user123",
    duration=3600  # Optional TTL
)
domain_token = response.token
```

### Request Authorization with Identity

Use an identity token to request authorization (no mTLS needed):

```python
# Create client WITHOUT mTLS
user_client = (
    hessra_py.HessraClient.builder()
    .base_url("auth.your-domain.com")
    .server_ca(ca_cert)
    .build()
)

# Request authorization token with identity
auth_token = user_client.request_token_with_identity(
    resource="protected-resource",
    operation="read",
    identity_token=identity_token,
    domain="urn:hessra:mycompany"  # Optional domain context
)
```

### Refresh Identity Token

Refresh an identity token before it expires:

```python
response = client.refresh_identity_token(
    current_token=identity_token,
    identifier=None  # Optional
)
new_token = response.token
```

### Create Local Identity Token

Create an identity token locally (requires personal keypair):

```python
token = client.create_identity_token_local(
    subject="urn:hessra:alice",
    duration=3600  # Optional TTL
)
```

## Service Chain Operations

For complex authorization flows involving multiple services:

```python
# Attest a token with your service
attested_token = client.attest_service_chain_token(
    token="original_token",
    service="my-service"
)

# Verify a service chain token
service_chain_json = '''[
    {
        "component": "auth-service",
        "public_key": "ed25519/public_key_1"
    },
    {
        "component": "payment-service",
        "public_key": "ed25519/public_key_2"
    }
]'''

client.verify_service_chain_token_local(
    token=attested_token,
    subject="user_id",
    resource="api/endpoint",
    operation="read",
    service_chain_json=service_chain_json,
    component=None  # Verify entire chain
)
```

## Configuration

### Environment Variables

The library supports loading configuration from environment variables:

```bash
export HESSRA_BASE_URL="your-service.com"
export HESSRA_PORT="443"
export HESSRA_PROTOCOL="http1"
export HESSRA_MTLS_CERT="$(cat client.crt)"
export HESSRA_MTLS_KEY="$(cat client.key)"
export HESSRA_SERVER_CA="$(cat ca.crt)"
export HESSRA_PUBLIC_KEY="$(cat public.key)"
export HESSRA_PERSONAL_KEYPAIR="$(cat personal.key)"
```

Then load with:

```python
config = hessra_py.HessraConfig.from_env()
```

### Builder Pattern

All configuration and client objects support a fluent builder pattern:

```python
config = (hessra_py.HessraConfig.builder()
    .base_url("service.com")
    .port(443)
    .protocol("http1")  # or "http3"
    .mtls_cert(cert_string)
    .mtls_key(key_string)
    .server_ca(ca_string)
    .public_key(public_key_string)
    .personal_keypair(keypair_string)
    .build())

client = (hessra_py.HessraClient.builder()
    .base_url("service.com")
    .port(443)
    # ... other configuration
    .build())
```

## Error Handling

All operations can raise `HessraPyError`:

```python
try:
    client.verify_token_local(token, subject, resource, operation)
    print("Token is valid")
except hessra_py.HessraPyError as e:
    print(f"Verification failed: {e}")
```

## API Reference

### HessraConfig

Configuration object for Hessra services.

**Methods:**

- `from_env()` - Load from environment variables
- `builder()` - Create configuration builder
- Properties: `base_url`, `port`, `protocol`, `public_key`

### HessraClient

Main client for interacting with Hessra services.

**Methods:**

- `__init__(config)` - Create client with configuration
- `setup_new()` - Setup client and return new instance with public key
- `get_public_key()` - Fetch public key from service

**Identity Token Methods:**

- `request_identity_token(identifier)` - Request identity token with mTLS
- `refresh_identity_token(current_token, identifier)` - Refresh identity token
- `verify_identity_token_local(token, identity)` - Verify identity token locally
- `attenuate_identity_token(token, delegated_identity, duration)` - Delegate identity
- `create_identity_token_local(subject, duration)` - Create identity token locally
- `mint_domain_restricted_identity_token(subject, duration)` - Mint domain-restricted token
- `request_token_with_identity(resource, operation, identity_token, domain)` - Request auth with identity

**Authorization Token Methods:**

- `request_token_simple(resource, operation)` - Request authorization token
- `verify_token_local(token, subject, resource, operation)` - Verify token locally
- `verify_token_remote(token, subject, resource, operation)` - Verify token via API

**Service Chain Methods:**

- `attest_service_chain_token(token, service)` - Add service attestation to token
- `verify_service_chain_token_local(...)` - Verify service chain token locally
- `verify_service_chain_token_remote(...)` - Verify service chain token via API

## Examples

See the `examples/` directory for complete usage examples:

- `basic_usage.py` - Basic token verification and configuration
- `test_verification.py` - Test suite demonstrating all features

## Development

Building and testing the Python bindings:

```bash
# Clone and navigate to the project
cd hessra-py

# Initialize uv project and sync dependencies
uv sync --dev

# Build in development mode
uv run maturin develop

# Run example tests
uv run python examples/basic_usage.py
uv run python examples/test_verification.py

# Run tests with pytest (when available)
uv run pytest

# Build release wheel
uv run maturin build --release

# Check the built wheel
ls -la target/wheels/
```

### Development Workflow

The Python bindings use `uv` for fast dependency management and `maturin` for building the Rust extension:

1. **Initial setup**: `uv sync --dev` installs all development dependencies
2. **Development builds**: `uv run maturin develop` builds and installs for testing
3. **Running examples**: `uv run python examples/...` executes Python scripts
4. **Release builds**: `uv run maturin build --release` creates optimized wheels

## Publishing and Releases

This package is published to PyPI independently from the main Hessra SDK. See [RELEASE.md](RELEASE.md) for the complete release process.

### For Maintainers

To release a new version:

1. Update version in `Cargo.toml`
2. Commit changes and create a tag: `git tag hessra-py-v0.1.1`
3. Push the tag: `git push origin hessra-py-v0.1.1`
4. GitHub Actions will automatically build and publish to PyPI

## License

Apache License 2.0 - See LICENSE file for details.
