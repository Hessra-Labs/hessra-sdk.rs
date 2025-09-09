# Hessra CLI

Command-line interface for Hessra authentication and identity management.

## Installation

### From cargo

```bash
cargo install hessra
```

### From Source

```bash
cargo install --path hessra
```

### Development Build

```bash
cargo build --release
# Binary will be at target/release/hessra
```

## Usage

### Identity Management

#### Authenticate with mTLS

Get an identity token using mTLS authentication:

```bash
hessra identity authenticate \
  --server test.hessra.net \
  --cert ~/.hessra/client.crt \
  --key ~/.hessra/client.key \
  --ca ~/.hessra/ca.pem \
  --save-as default
```

Or use environment variables:

```bash
export HESSRA_SERVER=test.hessra.net
export HESSRA_CERT=~/.hessra/client.crt
export HESSRA_KEY=~/.hessra/client.key
export HESSRA_CA=~/.hessra/ca.pem

hessra identity authenticate
```

#### Create Delegated Identity

Create a delegated identity token for an AI agent or service:

```bash
hessra identity delegate \
  --identity "uri:urn:test:user:ai-agent" \
  --ttl 3600 \
  --from-token default \
  --save-as ai-agent
```

#### Verify Token

Verify a saved token:

```bash
hessra identity verify --token-name default
```

Or verify a token file:

```bash
hessra identity verify --token-file /path/to/token --identity "uri:urn:test:user"
```

#### Refresh Token

Refresh an identity token:

```bash
hessra identity refresh --token-name default --save-as refreshed
```

#### List Saved Tokens

```bash
hessra identity list
```

#### Delete Token

```bash
hessra identity delete old-token
```

### Authorization Operations

#### Request Authorization Token

Request an authorization token for a specific resource and operation:

Using mTLS authentication:
```bash
hessra authorize request \
  --resource resource1 \
  --operation read \
  --cert ~/.hessra/client.crt \
  --key ~/.hessra/client.key \
  --server test.hessra.net
```

Using a saved identity token:
```bash
hessra authorize request \
  --resource resource1 \
  --operation read \
  --identity-token default \
  --server test.hessra.net
```

Automatically use default identity token if available:
```bash
hessra authorize request \
  --resource resource1 \
  --operation write \
  --server test.hessra.net
```

Output just the token for piping:
```bash
# Use in environment variable
export AUTH_TOKEN=$(hessra authorize request \
  --resource resource1 \
  --operation read \
  --token-only)

# Pipe to another command
hessra authorize request \
  --resource resource1 \
  --operation read \
  --token-only | curl -H "Authorization: Bearer $(cat)" ...
```

#### Verify Authorization Token

Verify an authorization token:

```bash
# Pipe token from another command
hessra authorize request --resource resource1 --operation read --token-only | \
  hessra authorize verify \
    --subject "uri:urn:test:user" \
    --resource resource1 \
    --operation read

# Or provide token directly
hessra authorize verify \
  --token "EtQBCmEK..." \
  --subject "uri:urn:test:user" \
  --resource resource1 \
  --operation read
```

### Configuration Management

#### Initialize Configuration

```bash
hessra config init
```

#### Set Configuration Values

```bash
hessra config set default_server test.hessra.net
hessra config set default_cert_path ~/.hessra/client.crt
hessra config set default_key_path ~/.hessra/client.key
hessra config set default_ca_path ~/.hessra/ca.pem
```

#### View Configuration

```bash
# Show all configuration
hessra config get

# Show specific value
hessra config get default_server
```

#### Show Configuration File Path

```bash
hessra config path
```

## Configuration

The CLI stores configuration and tokens in `~/.hessra/`:

- **Configuration file**: `~/.hessra/config.toml`
- **Tokens directory**: `~/.hessra/tokens/`

This location is consistent across all platforms (Linux, macOS, Unix).

### Configuration File Format

```toml
default_server = "test.hessra.net"
default_port = 443
default_cert_path = "/home/user/.hessra/client.crt"
default_key_path = "/home/user/.hessra/client.key"
default_ca_path = "/home/user/.hessra/ca.pem"
token_storage_dir = "/home/user/.hessra/tokens"
```

## Environment Variables

The CLI supports the following environment variables:

- `HESSRA_SERVER`: Default server hostname
- `HESSRA_PORT`: Default server port
- `HESSRA_CERT`: Path to client certificate
- `HESSRA_KEY`: Path to client private key
- `HESSRA_CA`: Path to CA certificate

## Output Formats

### Standard Output

By default, the CLI provides human-readable colored output:

```
✓ Authentication successful!
  Identity: uri:urn:test:user
  Expires in: 7200 seconds
  Token saved as: default
```

### JSON Output

Use `--json` flag for machine-readable output:

```bash
hessra identity authenticate --json
```

```json
{
  "success": true,
  "identity": "uri:urn:test:user",
  "expires_in": 7200,
  "token_saved_as": "default",
  "token_path": "/home/user/.hessra/tokens/default.token"
}
```

## Examples

### Workflow: Delegate to AI Agent

1. Authenticate with your credentials:

```bash
hessra identity authenticate \
  --cert ~/.hessra/my-cert.crt \
  --key ~/.hessra/my-key.key \
  --ca ~/.hessra/ca.pem
```

2. Create a delegated token for your AI agent:

```bash
hessra identity delegate \
  --identity "uri:urn:test:myuser:ai-assistant" \
  --ttl 3600 \
  --save-as ai-assistant
```

3. Provide the token to your AI agent:

```bash
export AI_AGENT_TOKEN=$(cat ~/.hessra/tokens/ai-assistant.token)
```

### CI/CD Usage

```bash
# Use environment variables and JSON output for CI/CD
export HESSRA_SERVER=prod.hessra.net
export HESSRA_CERT="$CI_MTLS_CERT"
export HESSRA_KEY="$CI_MTLS_KEY"
export HESSRA_CA="$CI_CA_CERT"

# Get token and extract it using jq
TOKEN=$(hessra identity authenticate --json | jq -r '.token')
```

## Security Notes

- Tokens are stored in plain text files by default
- Use appropriate file permissions for token storage directory
- Consider using the `secure-storage` feature (when available) for keychain integration
- Never commit tokens or certificates to version control

## License

Apache-2.0
