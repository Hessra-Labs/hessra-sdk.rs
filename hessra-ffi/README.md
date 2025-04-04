# Hessra FFI

C FFI bindings for the Hessra SDK token verification and configuration functionality.

## Overview

This crate provides C-compatible bindings for the core functionality of the Hessra SDK, focused specifically on token verification and configuration management. It is designed to be used in contexts where the full Rust SDK would be impractical, such as in database plugins.

## Features

- Token parsing and verification with optional subject and resource checking
- Service chain token validation
- Public key management (loading from files or strings)
- Configuration management (create, load, and modify)
- Memory-safe FFI interface with proper resource cleanup
- Comprehensive error handling

## Building

### As a Dynamic Library

```sh
cargo build --release
```

The resulting library will be in `target/release/libhessra.so` (Linux), `target/release/libhessra.dylib` (macOS), or `target/release/hessra.dll` (Windows).

### As a Static Library

```sh
cargo build --release
```

The resulting library will be in `target/release/libhessra.a` (Unix) or `target/release/hessra.lib` (Windows).

## Using in C Projects

Include the `hessra.h` header file in your project and link against the dynamic or static library.

### Basic Usage

```c
#include "hessra.h"

int main() {
    // Initialize the library
    HessraResult result = hessra_init();
    if (result != HESSRA_SUCCESS) {
        // Handle error
        return 1;
    }

    // Get version information
    const char* version = hessra_version();
    printf("Hessra version: %s\n", version);
    hessra_string_free((char*)version);

    return 0;
}
```

### Token Verification

```c
// Load a public key from a file
HessraPublicKey* public_key = NULL;
result = hessra_public_key_from_file("path/to/public_key.pem", &public_key);
if (result != HESSRA_SUCCESS) {
    // Handle error
}

// Verify a token
result = hessra_token_verify(token_string, public_key, "subject", "resource");
if (result != HESSRA_SUCCESS) {
    char* error_message = hessra_error_message(result);
    printf("Verification failed: %s\n", error_message);
    hessra_string_free(error_message);
}

// Don't forget to free resources
hessra_public_key_free(public_key);
```

### Configuration Management

```c
// Create a new configuration
HessraConfig* config = NULL;
result = hessra_config_new(&config);
if (result != HESSRA_SUCCESS) {
    // Handle error
}

// Set a public key in the configuration
result = hessra_config_set_public_key(config, public_key);
if (result != HESSRA_SUCCESS) {
    // Handle error
}

// Get a public key from the configuration
HessraPublicKey* retrieved_key = NULL;
result = hessra_config_get_public_key(config, &retrieved_key);
if (result != HESSRA_SUCCESS) {
    // Handle error
}

// Clean up
hessra_public_key_free(retrieved_key);
hessra_config_free(config);
```

## Examples

A more comprehensive example can be found in the `examples/test.c` file, which demonstrates:

- Library initialization
- Version retrieval
- Configuration creation
- Public key loading
- Token verification
- Proper resource cleanup

To build and run the example:

```sh
# Build the library
cargo build --release

# Build the example (Unix-like systems)
gcc -o test examples/test.c -L./target/release -lhessra -I./include

# Run the example (Linux)
LD_LIBRARY_PATH=./target/release ./test

# Run the example (macOS)
DYLD_LIBRARY_PATH=./target/release ./test
```

## Testing

The FFI library is tested through:

1. **Example Program**: The `examples/test.c` file serves as a basic functional test
2. **Automated Testing**: Rust tests that call the FFI functions to verify their behavior
3. **Memory Safety Testing**: Valgrind is used to check for memory leaks and other memory-related issues

To run the memory safety tests:

```sh
# Build the example in debug mode
cargo build
gcc -o test_debug examples/test.c -L./target/debug -lhessra -I./include

# Run with Valgrind
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
    --trace-children=yes LD_LIBRARY_PATH=./target/debug ./test_debug
```

## PostgreSQL Plugin

This FFI library is designed to be used in the Hessra PostgreSQL plugin for row-level security based on Hessra tokens. See the PostgreSQL plugin repository for more information.

## License

Apache License 2.0
