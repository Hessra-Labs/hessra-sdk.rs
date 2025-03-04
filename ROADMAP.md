# Hessra SDK Configuration Strategy

## Current Implementation Status

The Hessra SDK currently implements two procedural macros:

- `request_authorization`: Requests an authorization token for a resource
- `authorize`: Verifies an authorization token for a resource

These macros work by wrapping functions and support two configuration methods:

1. **Direct client parameter**: Passing an existing client reference

   ```rust
   #[request_authorization("my-resource", client_config)]
   async fn protected_function(client_config: &HessraClient) { ... }
   ```

2. **Individual parameters**: Specifying configuration values directly
   ```rust
   #[request_authorization("my-resource")]
   async fn protected_function(base_url: &str, mtls_cert: &str, mtls_key: &str, server_ca: &str) { ... }
   ```

## Configuration Strategy Recommendations

### Core Configuration Structure

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HessraConfig {
    base_url: String,
    port: Option<u16>,
    mtls_cert: String,
    mtls_key: String,
    server_ca: String,
    protocol: Protocol,
    // Potential future fields:
    // local_verification_enabled: bool,
    // public_key_path: Option<String>,
}
```

### Multiple Initialization Methods

```rust
impl HessraConfig {
    // Create from explicit parameters
    pub fn new(
        base_url: impl Into<String>,
        port: Option<u16>,
        protocol: Protocol,
        mtls_cert: impl Into<String>,
        mtls_key: impl Into<String>,
        server_ca: impl Into<String>,
    ) -> Self {
        HessraConfig {
            base_url: base_url.into(),
            port,
            protocol,
            mtls_cert: mtls_cert.into(),
            mtls_key: mtls_key.into(),
            server_ca: server_ca.into(),
        }
    }

    // Create from configuration file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_content = fs::read_to_string(path)?;
        let config: HessraConfig = serde_json::from_str(&file_content)?;
        config.validate()?;
        Ok(config)
    }

    // Create from TOML file
    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let file_content = fs::read_to_string(path)?;
        let config: HessraConfig = toml::from_str(&file_content)?;
        config.validate()?;
        Ok(config)
    }

    // Create from environment variables
    pub fn from_env(prefix: &str) -> Result<Self, ConfigError> {
        let base_url = env::var(format!("{}_BASE_URL", prefix))
            .map_err(|_| ConfigError::MissingBaseUrl)?;

        let port = env::var(format!("{}_PORT", prefix))
            .ok()
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| ConfigError::InvalidPort)?;

        // Similar for other fields...

        let config = HessraConfig {
            base_url,
            port,
            // Other fields...
        };

        config.validate()?;
        Ok(config)
    }

    // Validation
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_url.is_empty() {
            return Err(ConfigError::MissingBaseUrl);
        }

        // Validate certificates exist and are parseable
        // ...

        Ok(())
    }

    // Create client
    pub fn create_client(&self) -> Result<HessraClient, Error> {
        HessraClient::builder()
            .base_url(&self.base_url)
            .port(self.port.unwrap_or(443))
            .protocol(self.protocol.clone())
            .mtls_cert(&self.mtls_cert)
            .mtls_key(&self.mtls_key)
            .server_ca(&self.server_ca)
            .build()
    }
}
```

### Global Configuration (Optional, for convenience)

```rust
// Singleton pattern for default configuration
static DEFAULT_CONFIG: OnceLock<HessraConfig> = OnceLock::new();

pub fn set_default_config(config: HessraConfig) -> Result<(), ConfigError> {
    config.validate()?;
    DEFAULT_CONFIG.set(config).map_err(|_| ConfigError::AlreadyInitialized)
}

pub fn get_default_config() -> Option<&'static HessraConfig> {
    DEFAULT_CONFIG.get()
}
```

## Cross-Platform Integration Approaches

### 1. JavaScript/WASM (Next.js/Deno)

```typescript
// TypeScript interface
interface HessraConfig {
  baseUrl: string;
  port?: number;
  mtlsCert: string;
  mtlsKey: string;
  serverCa: string;
  protocol?: "http1" | "http3";
}

// Client initialization
class HessraClient {
  constructor(config: HessraConfig) {
    // Initialize WASM with config
  }

  async requestToken(resource: string): Promise<string> {
    // Call WASM module
  }

  async verifyToken(token: string, resource: string): Promise<boolean> {
    // Call WASM module
  }
}

// React context
const HessraContext = createContext<HessraClient | null>(null);

export const HessraProvider = ({
  children,
  config,
}: {
  children: React.ReactNode;
  config: HessraConfig;
}) => {
  const client = useMemo(() => new HessraClient(config), [config]);
  return (
    <HessraContext.Provider value={client}>{children}</HessraContext.Provider>
  );
};

export const useHessra = () => {
  const client = useContext(HessraContext);
  if (!client)
    throw new Error("useHessra must be used within a HessraProvider");
  return client;
};
```

### 2. OCaml Integration

```ocaml
(* OCaml interface *)
module Hessra = struct
  type protocol = Http1 | Http3

  type config = {
    base_url : string;
    port : int option;
    protocol : protocol;
    mtls_cert : string;
    mtls_key : string;
    server_ca : string;
  }

  (* Client interface *)
  type client

  let default_config = {
    base_url = "";
    port = Some 443;
    protocol = Http1;
    mtls_cert = "";
    mtls_key = "";
    server_ca = "";
  }

  let config_of_file path =
    let ic = open_in path in
    let config = Yojson.Safe.from_channel ic |> config_of_yojson in
    close_in ic;
    config

  let create_client config =
    (* Call to Rust through FFI *)

  let request_token client resource =
    (* Call to Rust through FFI *)

  let verify_token client token resource =
    (* Call to Rust through FFI *)
end
```

### 3. Nginx/Postgres Integration

```
# Example Nginx configuration
hessra {
    base_url https://auth.example.com;
    port 443;
    protocol http1;
    mtls_cert /etc/nginx/certs/client.crt;
    mtls_key /etc/nginx/certs/client.key;
    server_ca /etc/nginx/certs/ca.crt;
}

# Usage in location block
location /api {
    hessra_authorize $http_authorization resource1;
    proxy_pass http://backend;
}
```

## Implementation Roadmap

### Phase 1: Core Configuration Structure ✅

- [x] Initial macros for authorization flow
- [x] Create `HessraConfig` struct with validation
- [x] Implement multiple initialization methods
- [x] Update macros to work with the new config structure
- [x] Add comprehensive tests for configuration handling

### Phase 2: Enhanced Rust API ✅

- [x] Add configuration file support (JSON, TOML)
- [x] Implement environment variable configuration
- [x] Create global/default configuration option
- [x] Add comprehensive documentation and examples

### Phase 3: Adding and verifying attenuations 🚧

- [ ] Add way to configure personal keypair
- [ ] Add authenticated call (mTLS) to authorization service to give name and public key
- [ ] Add unauthenticated call to retrieve non-Hessra public keys
- [ ] Add biscuit attenuation using personal keypair
- [ ] Add attenuated biscuit verification using Hessra public key plus the non-Hessra public keys

### Phase 4: WASM Integration 🚧

- [ ] Define clear WASM API boundaries
- [ ] Create TypeScript type definitions
- [ ] Build React/Next.js integration components
- [ ] Add Deno compatibility

### Phase 5: System Integrations 🚧

- [ ] Develop Postgres extension
- [ ] Design OCaml bindings
- [ ] Implement Nginx module
- [ ] Create configuration validation tools

### Phase 6: Advanced Features 🚧

- [x] Local verification with public keys
- [ ] Adding and verifying third-party blocks
- [ ] Configuration hot-reloading
- [ ] Performance optimizations

### Ideas for beyond

- [ ] Develop browser-friendly mtls certificate handling

### Testing improvements 🚧

- [ ] Enhance unit testing and mock integration testing
- [ ] Expand and polish examples to show best way to use SDK
- [ ] Create a GitHub workflow for CI testing
- [ ] Use the examples to test against the deployed test.hessra.net instance

## Future Considerations

### Security

- Certificate rotation
- Secure storage of private keys
- Audit logging for authorization requests
- Rate limiting and throttling

### Performance

- Connection pooling
- Token caching
- Parallel verification

### Extensibility

- Plugin system for custom verification logic
- Support for alternative authentication methods
- Custom resource definitions

## Current Progress & Next Steps

### Current Progress

- Basic macro implementation complete
- SDK client functionality working
- `HessraConfig` struct with validation
- File-based configuration support
- Examples with different usage patterns
- Ability to fetch public keys for validating tokens in various ways
- Local verification of tokens with network call fallback

### Next Steps

1. WASM for Node.js (Next.js) usage
2. CI testing in GitHub once test.hessra.net is updated [blocked]
3. WASM for Deno
4. Postgres plugin for Row Level Security authorization

## Collaboration Notes

When continuing this work in the future, please consider:

1. **Compatibility**: Ensure any changes maintain backward compatibility with existing code
2. **Testing**: Add test cases for each new configuration method
3. **Documentation**: Update examples, docs rs, and this document to reflect changes
4. **Versioning**: Consider using feature flags for experimental features

When discussing future development:

- Reference specific sections of this document
- Indicate which phase of the roadmap you're working on
- Share any new integration requirements that may have emerged

---

This document will evolve as the implementation progresses. It serves as both a reference for current design decisions and a roadmap for future development.
