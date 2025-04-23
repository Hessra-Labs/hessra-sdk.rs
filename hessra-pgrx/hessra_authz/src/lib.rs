use pgrx::prelude::*;

::pgrx::pg_module_magic!();

#[pg_extern]
fn info_hessra_authz() -> &'static str {
    "hessra_authz extension loaded"
}

#[pg_extern]
fn verify_token(
    token: &str,
    public_key: &str,
    subject: &str,
    resource: &str,
) -> Result<(), hessra_token::TokenError> {
    let public_key = biscuit_auth::PublicKey::from_pem(public_key).unwrap();
    hessra_token::verify_token(token, public_key, subject, resource)
}

#[pg_extern]
fn verify_service_chain_token(
    token: &str,
    public_key: &str,
    subject: &str,
    resource: &str,
    service_nodes: &str, // JSON array of service nodes
    component: Option<&str>,
) -> Result<(), hessra_token::TokenError> {
    let public_key = biscuit_auth::PublicKey::from_pem(public_key).unwrap();
    let service_nodes: Vec<hessra_token::ServiceNode> =
        serde_json::from_str(service_nodes).unwrap();
    let component = component.map(|s| s.to_string());
    hessra_token::verify_service_chain_token(
        token,
        public_key,
        subject,
        resource,
        service_nodes,
        component,
    )
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;
    use serde_json::Value;

    #[pg_test]
    fn test_info_hessra_authz() {
        assert_eq!("hessra_authz extension loaded", crate::info_hessra_authz());
    }

    #[pg_test]
    fn test_token_verification_from_json() {
        // Load the test tokens from JSON
        let json_data = include_str!("../../../hessra-token/tests/test_tokens.json");
        let tokens: Value =
            serde_json::from_str(&json_data).expect("Failed to parse test_tokens.json");

        // Load the public key
        let public_key_str = include_str!("../../../certs/hessra_public.pem");
        let public_key = biscuit_auth::PublicKey::from_pem(public_key_str).unwrap();

        // Test each token
        for token_value in tokens["tokens"].as_array().unwrap() {
            let name = token_value["name"].as_str().unwrap();
            let token_string = token_value["token"].as_str().unwrap();
            let metadata = &token_value["metadata"];

            // Get values from metadata
            let subject = metadata["subject"].as_str().unwrap();
            let resource = metadata["resource"].as_str().unwrap();
            let expected_result = metadata["expected_result"].as_bool().unwrap();
            let description = metadata["description"].as_str().unwrap_or("No description");

            println!("Testing token '{}': {}", name, description);

            // Verify the token
            let result = hessra_token::parse_token(token_string, public_key).and_then(|biscuit| {
                // Print the token blocks for debugging
                println!("Token blocks: {}", biscuit.print());

                if metadata["type"].as_str().unwrap() == "singleton" {
                    crate::verify_token(token_string, public_key_str, subject, resource)
                } else {
                    // Create test service nodes as JSON array
                    let service_nodes = r#"[
                        {
                            "component": "auth_service",
                            "public_key": "ed25519/0123456789abcdef0123456789abcdef"
                        },
                        {
                            "component": "payment_service", 
                            "public_key": "ed25519/fedcba9876543210fedcba9876543210"
                        }
                    ]"#;

                    crate::verify_service_chain_token(
                        token_string,
                        public_key_str,
                        subject,
                        resource,
                        service_nodes,
                        None,
                    )
                }
            });

            // Check if the result matches expectations
            let verification_succeeded = result.is_ok();
            assert_eq!(
                verification_succeeded, expected_result,
                "Token '{}' verification resulted in {}, expected: {} - {}",
                name, verification_succeeded, expected_result, description
            );

            println!(
                "✓ Token '{}' - Verification: {}",
                name,
                if verification_succeeded == expected_result {
                    "PASSED"
                } else {
                    "FAILED"
                }
            );
        }
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
