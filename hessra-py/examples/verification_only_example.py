#!/usr/bin/env python3
"""
Token verification example for hessra-py Python bindings.

This example demonstrates how to verify tokens using the Python SDK,
assuming tokens are obtained from the authorization service via other means.
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
    print("Hessra Python SDK - Token Verification Example")
    print("=" * 50)

    try:
        print("Loading certificates...")
        mtls_cert = read_cert_file("client.crt")
        mtls_key = read_cert_file("client.key")
        server_ca = read_cert_file("ca-2030.pem")
        print("✓ Certificates loaded")

        print("\nCreating configuration...")
        config = (
            hessra_py.HessraConfig.builder()
            .base_url(BASE_URL)
            .port(PORT)
            .protocol("http1")
            .mtls_cert(mtls_cert)
            .mtls_key(mtls_key)
            .server_ca(server_ca)
            .build()
        )
        print(f"✓ Configuration created for {config.base_url}:{config.port}")

        print("\nInitializing client...")
        client = hessra_py.HessraClient(config)
        print("✓ Client created")

        print("\nSetting up client (fetching public key from server)...")
        client = client.setup_new()
        print("✓ Client setup completed")

        public_key = client.get_public_key()
        print(f"✓ Public key loaded: {public_key[:50]}...")

        print("\n" + "=" * 50)
        print("CLIENT READY FOR TOKEN VERIFICATION")
        print("✓ Successfully connected to test.hessra.net")
        print("✓ mTLS authentication working")
        print("✓ Public key fetched from authorization service")
        print("✓ Client ready for token verification operations")

        print("\nVerification API usage:")
        print("  # For local verification (offline, using cached public key)")
        print("  client.verify_token_local(")
        print("      token='<biscuit_token_base64>',")
        print("      subject='uri:urn:test:argo-cli0',")
        print("      resource='resource1',")
        print("      operation='read'")
        print("  )")
        print()
        print("  # For remote verification (online, via API)")
        print("  result = client.verify_token_remote(")
        print("      token='<biscuit_token_base64>',")
        print("      subject='uri:urn:test:argo-cli0',")
        print("      resource='resource1',")
        print("      operation='read'")
        print("  )")

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
