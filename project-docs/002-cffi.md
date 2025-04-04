# C FFI Bindings and PostgreSQL Plugin Integration

## Overview

This document outlines the implementation plan for creating C FFI bindings for the Hessra SDK to enable PostgreSQL integration via a plugin for row-level security based on Hessra authentication tokens.

## Design Decisions

After reviewing the codebase, here are the recommended approaches:

### Approach 1: Focused FFI for Token and Config (Recommended)

Create C FFI bindings only for the essential components:

- `hessra-token`: For token verification functionality
- `hessra-config`: For configuration management

**Pros:**

- Minimal dependencies and smaller code footprint
- Faster performance for database operations
- No networking dependencies which are unsuitable for database contexts
- More maintainable with clear separation of concerns

**Cons:**

- Some code duplication may be required
- Separate API from the main SDK

### Approach 2: Full SDK with Local-Only Mode

Create C FFI bindings for the entire SDK with a configuration option to disable remote calls.

**Pros:**

- Full feature parity with the Rust SDK
- Single API surface for all Hessra functionality
- Easier maintenance with less code duplication

**Cons:**

- Larger binary size and more dependencies
- Potential performance overhead from unnecessary components
- Risk of accidentally enabling remote calls within database context

### Selected Approach

**Approach 1 (Focused FFI)** is recommended for the PostgreSQL plugin. This approach aligns with the separation of concerns principle already visible in the SDK architecture and will result in a more performant and maintainable solution.

## Implementation Plan

### Phase 1: Core FFI Development

1. **Create FFI Module Structure**

   - Create a new crate `hessra-ffi` at the workspace level
   - Set up compilation targets for dynamic and static libraries
   - Define FFI-compatible data structures

2. **Implement Token Verification Bindings**

   - Create C-compatible functions for token verification
   - Implement memory management for token handling
   - Add error handling and conversion between Rust and C error types

3. **Implement Configuration Bindings**

   - Create C-compatible functions for configuration loading
   - Implement functions for reading public keys from different sources
   - Add validation for configuration parameters

4. **Testing Harness**
   - Create simple C application for testing bindings
   - Implement automated tests for the FFI layer
   - Verify memory safety with tools like Valgrind

### Phase 2: PostgreSQL Plugin Development

1. **Initialize Plugin Repository**

   - Create a separate C repository for the PostgreSQL plugin
   - Set up build system with CMake or similar
   - Configure dependency management for linking with Hessra FFI

2. **Implement Core Plugin Functionality**

   - Create PostgreSQL extension structure
   - Implement row-level security functions using Hessra token verification
   - Add configuration handling specific to PostgreSQL

3. **Security Review**

   - Perform threat modeling for the PostgreSQL integration
   - Review memory management for security implications
   - Implement safeguards against common attack vectors

4. **Documentation and Examples**
   - Create comprehensive documentation for plugin installation
   - Document SQL functions and usage patterns
   - Provide example configurations for common scenarios

### Phase 3: Integration and Testing

1. **Set Up Testing Environment**

   - Create Docker-based test environment with PostgreSQL
   - Script automated test cases for different security scenarios
   - Implement benchmark suite for performance testing

2. **Integration Testing**

   - Test with various PostgreSQL versions
   - Verify compatibility with different database schemas
   - Test concurrent access patterns

3. **Performance Optimization**

   - Profile plugin performance under various loads
   - Identify and optimize hotspots
   - Implement caching if needed for token verification

4. **Release Preparation**
   - Create release packaging for different platforms
   - Prepare documentation for publication
   - Set up CI/CD pipeline for automated builds

## C FFI Interface Specification

### Core Types

```c
// Handle types (opaque pointers)
typedef struct HessraToken* HessraToken;
typedef struct HessraConfig* HessraConfig;
typedef struct HessraPublicKey* HessraPublicKey;

// Error type
typedef enum {
    HESSRA_SUCCESS = 0,
    HESSRA_ERROR_INVALID_TOKEN = 1,
    HESSRA_ERROR_INVALID_KEY = 2,
    HESSRA_ERROR_VERIFICATION_FAILED = 3,
    HESSRA_ERROR_CONFIG_INVALID = 4,
    HESSRA_ERROR_MEMORY = 5,
    // Add other error codes as needed
} HessraResult;

// Result with error message
typedef struct {
    HessraResult code;
    char* message;
} HessraError;
```

### Core Functions

```c
// Token operations
HessraResult hessra_token_parse(const char* token_string, HessraToken* out_token);
HessraResult hessra_token_verify(HessraToken token, HessraPublicKey public_key,
                               const char* subject, const char* resource);
void hessra_token_free(HessraToken token);

// Key operations
HessraResult hessra_public_key_from_string(const char* key_string, HessraPublicKey* out_key);
HessraResult hessra_public_key_from_file(const char* file_path, HessraPublicKey* out_key);
void hessra_public_key_free(HessraPublicKey key);

// Configuration operations
HessraResult hessra_config_new(HessraConfig* out_config);
HessraResult hessra_config_from_file(const char* file_path, HessraConfig* out_config);
HessraResult hessra_config_set_public_key(HessraConfig config, const char* key_id, HessraPublicKey key);
HessraResult hessra_config_get_public_key(HessraConfig config, const char* key_id, HessraPublicKey* out_key);
void hessra_config_free(HessraConfig config);

// Error handling
const char* hessra_error_message(HessraResult result);
void hessra_error_free(char* error_message);
```

## PostgreSQL Plugin Interface

The PostgreSQL plugin will expose the following SQL functions:

```sql
-- Initialization function (called during extension loading)
CREATE FUNCTION hessra_init(config_path TEXT) RETURNS BOOLEAN;

-- Token verification function
CREATE FUNCTION hessra_verify_token(
    token TEXT,
    subject TEXT,
    resource TEXT
) RETURNS BOOLEAN;

-- Row security policy helper
CREATE FUNCTION hessra_row_security(
    token TEXT,
    table_name TEXT,
    operation TEXT
) RETURNS BOOLEAN;

-- Configuration management
CREATE FUNCTION hessra_reload_config() RETURNS BOOLEAN;
```

## Timeline and Milestones

1. **Milestone 1: FFI Core Development**

   - Set up project structure
   - Implement token verification FFI
   - Implement configuration FFI
   - Create basic tests

2. **Milestone 2: PostgreSQL Plugin Framework**

   - Set up PostgreSQL extension skeleton
   - Implement core SQL functions
   - Create Docker-based testing environment

3. **Milestone 3: Integration and Testing**

   - Complete integration tests
   - Performance optimization
   - Documentation and examples

4. **Milestone 4: Production Readiness**
   - Security review and fixes
   - Packaging and distribution
   - Final documentation and examples

## Conclusion

This implementation plan provides a focused approach to developing C FFI bindings for the Hessra token verification system and integrating it with PostgreSQL for row-level security. By focusing specifically on the token verification and configuration components, we can create a lightweight, high-performance solution suitable for database contexts.

The plan prioritizes security, maintainability, and performance while providing a clear path to implementation and testing.
u
