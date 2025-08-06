#!/usr/bin/env python3
"""
Comprehensive example for hessra-py Python bindings.

This example mirrors the functionality of hessra-sdk/examples/http1_example.rs,
demonstrating the complete workflow of client setup, token request, and verification.
"""

import os

import hessra_py

BASE_URL = "test.hessra.net"
PORT = 443


def read_cert_file(filename):
    """Read certificate file from the certs directory."""
    cert_path = os.path.join(os.path.dirname(__file__), "../../certs", filename)
    with open(cert_path) as f:
        return f.read()


def main():
    print("Hessra Python SDK - Comprehensive Example")
    print("=" * 50)

    try:
        print("Loading certificates...")
        mtls_cert = read_cert_file("client.crt")
        mtls_key = read_cert_file("client.key")
        server_ca = read_cert_file("ca-2030.pem")
        print("✓ Certificates loaded")

        print("\nInitializing client with HTTP/1.1...")
        client = (
            hessra_py.HessraClient.builder()
            .base_url(BASE_URL)
            .port(PORT)
            .protocol("http1")
            .mtls_cert(mtls_cert)
            .mtls_key(mtls_key)
            .server_ca(server_ca)
            .build()
        )
        print("✓ Client created")

        print("\nSetting up client (fetching public key from server)...")
        client = client.setup_new()
        print("✓ Client setup completed")

        public_key = client.get_public_key()
        print(f"✓ Public key loaded: {public_key[:50]}...")

        print("\nRequesting token for resource...")
        resource = "resource1"
        operation = "read"
        token = client.request_token_simple(resource, operation)
        print(f"✓ Received token: {token[:50]}...")

        print("\nVerifying token locally...")
        subject = "uri:urn:test:argo-cli0"
        client.verify_token_local(
            token=token, subject=subject, resource=resource, operation=operation
        )
        print("✓ Token verified successfully")

        print("\n" + "=" * 50)
        print("COMPLETE WORKFLOW SUCCESS!")
        print("✓ Connected to authorization service")
        print("✓ Fetched public key from server")
        print("✓ Requested token via API")
        print("✓ Verified token locally")
        print("✓ Full request → verify cycle working!")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure you're running from the hessra-py directory")
        print("2. Check that certificate files exist in ../../certs/")
        print("3. Verify network connectivity to test.hessra.net:443")
        print(
            "4. Make sure the hessra-py module was built with: uv run maturin develop"
        )
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
