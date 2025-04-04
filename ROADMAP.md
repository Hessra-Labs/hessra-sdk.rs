# Hessra SDK Roadmap

## Current Implementation Status

The Hessra SDK has been refactored to separate concerns into distinct components:

- **Token verification**: Local validation of authorization tokens
- **Configuration handling**: Managing SDK configuration
- **API client**: Handling remote API calls to the Hessra service
- **SDK**: Unified interface bringing together all components

The SDK currently supports:

- Requesting authorization tokens for resources
- Verifying authorization tokens locally or via API
- Managing attenuation of tokens
- Configuration via multiple methods
- Public key retrieval and management

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

### Phase 3: Adding and verifying attenuations ✅

- [x] Add way to configure personal keypair
- [x] Add authenticated call (mTLS) to authorization service to give name and public key
- [x] Add unauthenticated call to retrieve non-Hessra public keys
- [x] Add biscuit attenuation using personal keypair
- [x] Add attenuated biscuit verification using Hessra public key plus the non-Hessra public keys

### Phase 4: WASM Integration 🚧

- [ ] Implement WASM bindings for token verification
- [ ] Implement WASM bindings for configuration handling
- [x] Create native NodeJS API client
- [ ] Integrate WASM components with NodeJS client to create full SDK
- [ ] Create TypeScript type definitions
- [ ] Build React/Next.js integration components
- [ ] Add Deno compatibility

### Phase 5: System Integrations 🚧

- [ ] Develop Postgres plugin with C FFI bindings
- [ ] Design OCaml bindings
- [ ] Implement Nginx module
- [ ] Create configuration validation tools

### Phase 6: Advanced Features 🚧

- [x] Local verification with public keys
- [x] Adding and verifying third-party blocks
- [ ] Configuration hot-reloading
- [ ] Performance optimizations
- [ ] C FFI bindings for the full SDK (for Go, Python, etc.)

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

- Refactored architecture to separate API calls from local verification
- Unified components in a centralized SDK crate
- Implementation of token verification and attestation
- Native NodeJS API client developed
- Public key management for token validation

### Next Steps

1. Complete WASM implementation for token and config crates
2. Develop Postgres plugin with C FFI bindings for token and config components
3. Integrate WASM components with NodeJS client
4. Create C FFI bindings for the full SDK to support languages like Go and Python
5. Develop Nginx module and other system integrations
6. CI testing in GitHub once test.hessra.net is updated [blocked]

## Collaboration Notes

When continuing this work in the future, please consider:

1. **Compatibility**: Ensure any changes maintain backward compatibility with existing code
2. **Testing**: Add test cases for each new feature or component
3. **Documentation**: Update examples, docs rs, and this document to reflect changes
4. **Versioning**: Consider using feature flags for experimental features
5. **Performance**: C FFI bindings and WASM should prioritize performance, especially for token verification

When discussing future development:

- Reference specific sections of this document
- Indicate which phase of the roadmap you're working on
- Share any new integration requirements that may have emerged

---

This document will evolve as the implementation progresses. It serves as both a reference for current design decisions and a roadmap for future development.
