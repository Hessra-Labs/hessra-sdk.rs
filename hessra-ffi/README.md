# Hessra FFI

C FFI bindings for the Hessra SDK token verification and configuration functionality.

## Overview

This crate provides C-compatible bindings for the core functionality of the Hessra SDK, focused specifically on token verification and configuration management. It is designed to be used in contexts where the full Rust SDK would be impractical, such as in database plugins.

## Features

- Token parsing and verification
- Public key loading from files or strings
- Configuration management
- Memory-safe FFI interface

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

```c
#include "hessra.h"

int main() {
    // Initialize the library
    hessra_init();

    // Use the library functions...

    return 0;
}
```

## Example

See the `examples` directory for a simple example of using the library from C.

## PostgreSQL Plugin

This FFI library is designed to be used in the Hessra PostgreSQL plugin for row-level security based on Hessra tokens. See the PostgreSQL plugin repository for more information.

## License

Apache License 2.0
