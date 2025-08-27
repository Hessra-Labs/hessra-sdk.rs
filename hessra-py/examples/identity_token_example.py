#!/usr/bin/env python3
"""
Identity token example for hessra-py Python bindings.

This example demonstrates the identity token functionality:
- Requesting identity tokens from the service
- Verifying identity tokens locally
- Creating delegated identities through attenuation
- Using identity tokens for authentication
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
    print("Hessra Python SDK - Identity Token Example")
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

        print("\n" + "=" * 50)
        print("IDENTITY TOKEN OPERATIONS")
        print("=" * 50)

        # Request an identity token
        print("\n1. Requesting identity token from service...")
        identity_response = client.request_identity_token(
            identifier="urn:hessra:test:user"
        )
        print("✓ Identity token received")
        print(f"   Message: {identity_response.response_msg}")
        print(f"   Identity: {identity_response.identity}")
        print(f"   Expires in: {identity_response.expires_in} seconds")

        if identity_response.token:
            identity_token = identity_response.token
            print(f"   Token: {identity_token[:50]}...")

            # Verify the identity token locally
            print("\n2. Verifying identity token locally...")
            try:
                client.verify_identity_token_local(
                    token=identity_token, identity="urn:hessra:test:user"
                )
                print("✓ Identity token verified successfully")
            except Exception as e:
                print(f"✗ Verification failed: {e}")

            # Create a delegated identity token
            print("\n3. Creating delegated identity token...")
            try:
                delegated_token = client.attenuate_identity_token(
                    token=identity_token,
                    delegated_identity="urn:hessra:test:user:laptop",
                    duration=None,  # Use default duration (1 hour)
                )
                print("✓ Delegated identity token created")
                print(f"   Token: {delegated_token[:50]}...")

                # Verify the delegated token
                print("\n4. Verifying delegated identity token...")
                client.verify_identity_token_local(
                    token=delegated_token, identity="urn:hessra:test:user:laptop"
                )
                print("✓ Delegated token verified for 'urn:hessra:test:user:laptop'")

                # Try to verify with the original identity (should fail)
                print("\n5. Testing delegation restriction...")
                try:
                    client.verify_identity_token_local(
                        token=delegated_token, identity="urn:hessra:test:user"
                    )
                    print(
                        "✗ Unexpected: Delegated token should not verify for original identity"
                    )
                except Exception:
                    print(
                        "✓ Correct: Delegated token does not verify for original identity"
                    )

            except Exception as e:
                print(f"✗ Delegation failed: {e}")

            # Use identity token for authentication
            print("\n6. Using identity token for authentication...")
            try:
                auth_token = client.request_token_with_identity(
                    resource="resource1",
                    operation="read",
                    identity_token=identity_token,
                )
                print("✓ Authorization token obtained using identity token")
                print(f"   Token: {auth_token[:50]}...")

                # Verify the authorization token
                print("\n7. Verifying authorization token...")
                client.verify_token_local(
                    token=auth_token,
                    subject="urn:hessra:test:user",
                    resource="resource1",
                    operation="read",
                )
                print("✓ Authorization token verified successfully")

            except Exception as e:
                print(f"✗ Authorization with identity token failed: {e}")

            # Refresh the identity token
            print("\n8. Refreshing identity token...")
            try:
                refreshed_response = client.refresh_identity_token(
                    current_token=identity_token, identifier="urn:hessra:test:user"
                )
                print("✓ Identity token refreshed")
                print(f"   Message: {refreshed_response.response_msg}")
                print(f"   Expires in: {refreshed_response.expires_in} seconds")
            except Exception as e:
                print(f"✗ Token refresh failed: {e}")

        print("\n" + "=" * 50)
        print("IDENTITY TOKEN EXAMPLE COMPLETE!")
        print("✓ Successfully demonstrated identity token operations")
        print("✓ Request, verify, delegate, and use identity tokens")
        print("✓ Identity-based authentication working")

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
