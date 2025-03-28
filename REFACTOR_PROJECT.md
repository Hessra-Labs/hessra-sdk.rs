# Hessra SDK Refactoring Project Plan

## Overview

This document outlines the plan for refactoring the Hessra SDK to improve modularity, cross-platform support, and maintainability. It serves as a knowledge base and progress tracker for the project.

## Background

The current Hessra SDK combines three main responsibilities:

1. **API Client**: Makes HTTP requests to the Hessra authorization service defined in the OpenAPI spec
2. **Token Operations**: Locally verifies and attenuates biscuit tokens
3. **Configuration**: Manages settings for both API connectivity and token operations

This combined approach limits our ability to support multiple platforms efficiently, particularly for WebAssembly (WASM) and Node.js targets.

## Goals

- Separate the SDK into modular components with clear boundaries
- Enable cross-platform support, particularly for WASM/Node.js
- Maintain backward compatibility for existing users
- Simplify maintenance by isolating concerns
- Facilitate language-specific implementations

## Proposed Architecture

### Core Crates

1. **hessra-token** (core verification library)

   - Token verification logic
   - Token attestation functionality
   - No networking dependencies
   - WASM-compatible

2. **hessra-config** (configuration management)

   - Configuration structures and loading
   - Environment, file, and programmatic config
   - Minimal dependencies

3. **hessra-api** (API client)

   - HTTP client for Hessra service
   - Implements OpenAPI spec functionality
   - Platform-specific networking

4. **hessra-sdk** (unified SDK)
   - Re-exports and combines functionality from above crates
   - Provides simple high-level interface
   - Full Rust implementation

### Dependency Graph

```
hessra-token    hessra-config    hessra-api
     ↑               ↑               ↑
     └───────────────┴───────────────┘
                     |
                hessra-sdk
```

## Implementation Plan

### Phase 1: Core Refactoring

#### 1. Initial Setup (Week 1)

- [x] Create new workspace with all four crates
- [x] Define dependencies between crates
- [x] Set up CI/CD pipelines for testing
- [x] Move existing tests to appropriate locations

#### 2. Code Migration (Weeks 2-3)

- [ ] Move token verification to `hessra-token`
  - [ ] Extract verification logic
  - [ ] Extract attestation logic
  - [ ] Add unit tests
- [x] Extract configuration into `hessra-config`
  - [x] Move config structs
  - [x] Move loading functionality
  - [x] Create builder patterns
- [ ] Isolate API client into `hessra-api`
  - [ ] Extract HTTP client code
  - [ ] Implement OpenAPI endpoints
  - [ ] Error handling
- [ ] Create unified SDK in `hessra-sdk`
  - [ ] Re-export functionality
  - [ ] Create high-level interfaces
  - [ ] Ensure backward compatibility

#### 3. API Refinement (Week 4)

- [ ] Define clean interfaces between components
- [ ] Document public APIs
- [ ] Ensure backward compatibility
- [ ] Create migration guides

### Phase 2: Cross-Platform Support (After Core Refactoring)

- [ ] WASM bindings for `hessra-token`
  - [ ] Add WASM compilation support with feature flag
  - [ ] Create WASM-specific bindings
  - [ ] Test in WASM environment
- [ ] Example Node.js implementation using WASM
- [ ] C API wrapper around `hessra-sdk`
- [ ] Testing on multiple platforms

### Phase 3: Documentation and Testing

- [ ] Unit tests for each crate
- [ ] Integration tests across crates
- [ ] Comprehensive documentation
- [ ] Usage examples

## Platform-Specific Implementations

### WASM/Node.js SDK

- Use `hessra-token` compiled to WASM
- Implement API client natively in JavaScript/TypeScript
- Use native JS configuration handling with schema from `hessra-config`

### C/FFI Bindings

- Use `hessra-sdk` as the foundation
- Create C-compatible wrapper functions
- Provide memory management utilities

### Other Languages

- Create similar patterns for other target languages
- Reuse `hessra-token` WASM where possible

## Project Status

| Component              | Status      | Notes                                                               |
| ---------------------- | ----------- | ------------------------------------------------------------------- |
| hessra-token           | Completed   | Fully implemented with verification, attenuation, and base64 utils  |
| hessra-config          | Completed   | Full implementation migrated from original src/config.rs with tests |
| hessra-api             | In Progress | Basic structure created, HTTP client interface defined              |
| hessra-sdk             | In Progress | Basic structure created, re-exports set up                          |
| WASM support for token | Not started | Will be implemented after core functionality refactoring            |
| C API                  | Not started | Will be implemented after basic refactoring                         |

## Notes and Decisions

### Token Implementation (2023-04-30 Update)

- Completed implementation of `hessra-token` with the following components:
  - Core token verification (`verify.rs`)
  - Token attenuation (`attenuate.rs`)
  - Custom error handling (`error.rs`)
  - Base64 utility functions (`utils.rs`)
  - High-level token API (`token.rs`)
- Added comprehensive unit tests and examples
- Ensured all functions are independent of API client code
- Created detailed documentation in README.md
- Next step is to focus on `hessra-api` implementation

### Project Phases (2023-04-30 Update)

We've decided to separate the project into distinct phases:

1. **Phase 1**: Complete the core refactoring of all functionality without WASM
2. **Phase 2**: Add WASM support to the token verification library
3. **Phase 3**: Complete documentation and additional platform support

This approach allows us to get the new architecture functioning correctly first before adding cross-platform capabilities.

### Workspace Structure (2023-04-15)

- Created a workspace with four crates:
  - `hessra-token`: Core token verification and attestation, WASM-compatible
  - `hessra-config`: Configuration management with no other crate dependencies
  - `hessra-api`: API client functionality, depends on hessra-config
  - `hessra-sdk`: Unified SDK that re-exports functionality from all other crates

### Dependency Design

- **hessra-token**: No dependencies on other crates

  - External dependencies: biscuit-auth, base64, chrono, serde, hex
  - Optional WASM dependencies: wasm-bindgen, js-sys, web-sys

- **hessra-config**: No dependencies on other crates

  - External dependencies: serde, serde_json, dirs, thiserror
  - Optional TOML support via feature flag

- **hessra-api**: Depends on hessra-config

  - External dependencies: reqwest, tokio, base64, chrono
  - Optional HTTP/3 dependencies behind feature flag

- **hessra-sdk**: Depends on all three other crates
  - Minimal direct dependencies: just serde and thiserror
  - Passes all feature flags down to dependent crates

### Feature Flags

- **http3**: Enables HTTP/3 protocol support in hessra-api and hessra-sdk
- **toml**: Enables TOML configuration support in hessra-config and hessra-sdk
- **wasm**: Enables WebAssembly support in hessra-token and hessra-sdk

### Code Migration Strategy

1. Move token verification and attestation code to `hessra-token`

   - verify.rs and attenuate.rs already copied
   - Need to adapt for standalone usage without API client dependencies
   - WASM compatibility will be addressed in Phase 2

2. Move configuration code to `hessra-config`

   - Completed implementation of HessraConfig, HessraConfigBuilder, and related functionality
   - Successfully migrated all methods from the original config.rs
   - Added comprehensive unit tests
   - Implemented "toml" feature for optional TOML configuration file support
   - Removed create_client and other API-specific methods (moved to hessra-api)
   - Removed token-specific functionality (moved to hessra-token)

3. Move API client code to `hessra-api`

   - Defined basic structures and interfaces
   - Need to implement HTTP client functionality (HTTP/1 and HTTP/3)

4. Implement re-export functionality in `hessra-sdk`
   - Already set up basic re-exports
   - Need to implement ServiceChain and high-level APIs

### hessra-config Implementation Notes (2023-04-28)

- Migrated all configuration functionality from the original src/config.rs
- Removed references to HessraClient (now part of hessra-api)
- Modified the configuration validation to focus strictly on config properties
- Added comprehensive tests for builder pattern, validation, loading from files, etc.
- Implemented conditional compilation for TOML support using the "toml" feature flag
- Added helper functions for loading config based on file extension
- Maintained backward compatibility with the original configuration API

### Version Migration

- Starting with workspace version 0.1.0 for the refactored crates
- Will eventually update to match the original package version (currently 0.4.1)
- Use Cargo features to ensure backward compatibility

## References

- Current Hessra SDK codebase
- OpenAPI specification for the Hessra authorization service
- [Biscuit authentication documentation](https://www.biscuitsec.org/)
