# Hessra SDK Tests

This directory contains tests for the Hessra SDK.

## Test Structure

- **Unit Tests**: Tests for individual components and functions

  - In-library unit tests in `src/lib.rs`
  - Standalone unit tests in `tests/client_builder_test.rs`

- **Integration Tests**: Tests that verify the SDK works correctly with a mock server

  - `tests/integration_test.rs`: Tests for HTTP/1 and HTTP/3 clients

- **Mocks**: Mock implementations for testing

  - `tests/mocks/mock_server.rs`: A mock HTTP server for testing

- **Utilities**: Helper functions for testing
  - `tests/test_utils.rs`: Utilities for generating test certificates

## Running Tests

To run all tests:

```bash
cargo test
```

To run tests with HTTP/3 support:

```bash
cargo test --features http3
```

To run a specific test:

```bash
cargo test test_name
```

## Test Certificates

The tests use self-signed certificates for testing TLS connections. These certificates are generated automatically when running the tests for the first time.

## Adding New Tests

When adding new tests:

1. For unit tests of new functionality, add them to the appropriate test module
2. For integration tests of new endpoints, add them to `tests/integration_test.rs`
3. If you need to mock new server behavior, update `tests/mocks/mock_server.rs`

## Improvements

Needed areas of improvement for the overall SDK

1. Make it clear for each token/biscuit operation and key/cert operation what the expected format is and what the output format is. For example, some places expect and return a base64 encoded biscuit token where others might want a Vec<u8> representation. For keys, some things want a string representation: "ed25519/key", PEM encoded, or the raw key. Provide helpers to convert seemlessly or better yet create strict types.
2. create SDK API such that there is a verify_token, verify_token_local, and verify_token_remote. verify_token should try to do it locally first and then resort to an API call if an authorization service is configured for use.
