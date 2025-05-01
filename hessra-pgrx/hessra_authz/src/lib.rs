use pgrx::prelude::*;

::pgrx::pg_module_magic!();

/// Returns the extension version information
///
/// This function can be used to verify the extension is properly loaded.
#[pg_extern]
fn info_hessra_authz() -> &'static str {
    "hessra_authz extension loaded"
}

/// Schema setup module
///
/// Contains the initialization code that runs when the extension is created
#[pg_schema]
mod schema {
    use pgrx::prelude::*;

    // Create required tables during extension load
    #[pg_guard]
    pub extern "C-unwind" fn _PG_init() {
        let create_tables_sql = r#"
        -- Create table for storing the public key
        CREATE TABLE IF NOT EXISTS hessra_public_keys (
            id SERIAL PRIMARY KEY,
            key_name TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            is_default BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- Create table for storing service chains
        CREATE TABLE IF NOT EXISTS hessra_service_chains (
            id SERIAL PRIMARY KEY,
            service_name TEXT UNIQUE NOT NULL,
            service_nodes JSONB NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        "#;

        Spi::run(create_tables_sql).unwrap();
    }
}

/// Helper function to escape single quotes in SQL strings to prevent SQL injection
fn sql_escape(s: &str) -> String {
    s.replace('\'', "''")
}

//-----------------------------------------------------------------------------
// Public Key Management Functions
//-----------------------------------------------------------------------------

/// Adds a new public key to the database
///
/// # Arguments
/// * `key_name` - A unique name for the public key
/// * `public_key` - The PEM-encoded public key
/// * `is_default` - Whether this key should be the default key for verification
///
/// # Returns
/// * The ID of the newly created key or an error message
#[pg_extern]
fn add_public_key(key_name: &str, public_key: &str, is_default: bool) -> Result<i32, String> {
    // First validate the public key format
    match biscuit_auth::PublicKey::from_pem(public_key) {
        Ok(_) => (),
        Err(e) => return Err(format!("Invalid public key format: {}", e)),
    }

    // If setting as default, unset any existing defaults
    if is_default {
        let update_sql = "UPDATE hessra_public_keys SET is_default = FALSE WHERE is_default = TRUE";
        Spi::run(update_sql).map_err(|e| format!("Failed to update existing keys: {}", e))?;
    }

    // Insert the new key and return the ID
    let insert_sql = format!(
        "INSERT INTO hessra_public_keys (key_name, public_key, is_default) 
         VALUES ('{}', '{}', {}) 
         RETURNING id",
        sql_escape(key_name),
        sql_escape(public_key),
        if is_default { "TRUE" } else { "FALSE" }
    );

    let result =
        Spi::get_one::<i32>(&insert_sql).map_err(|e| format!("Failed to insert key: {}", e))?;

    match result {
        Some(id) => Ok(id),
        None => Err("No ID returned from insert".to_string()),
    }
}

/// Updates an existing public key in the database
///
/// # Arguments
/// * `key_name` - The name of the key to update
/// * `public_key` - The new PEM-encoded public key
/// * `is_default` - Whether this key should be the default key for verification
///
/// # Returns
/// * `true` if the key was updated, `false` if the key was not found
#[pg_extern]
fn update_public_key(key_name: &str, public_key: &str, is_default: bool) -> Result<bool, String> {
    // First validate the public key format
    match biscuit_auth::PublicKey::from_pem(public_key) {
        Ok(_) => (),
        Err(e) => return Err(format!("Invalid public key format: {}", e)),
    }

    // If setting as default, unset any existing defaults
    if is_default {
        let update_sql = "UPDATE hessra_public_keys SET is_default = FALSE WHERE is_default = TRUE";
        Spi::run(update_sql).map_err(|e| format!("Failed to update existing keys: {}", e))?;
    }

    // Update the key
    let update_sql = format!(
        "UPDATE hessra_public_keys 
         SET public_key = '{}', is_default = {} 
         WHERE key_name = '{}'",
        sql_escape(public_key),
        if is_default { "TRUE" } else { "FALSE" },
        sql_escape(key_name)
    );

    // Check if any rows were updated by selecting the record after update
    let check_sql = format!(
        "SELECT COUNT(*) FROM hessra_public_keys WHERE key_name = '{}'",
        sql_escape(key_name)
    );

    Spi::run(&update_sql).map_err(|e| format!("Failed to update key: {}", e))?;

    let count = Spi::get_one::<i64>(&check_sql)
        .map_err(|e| format!("Failed to check update result: {}", e))?
        .unwrap_or(0);

    Ok(count > 0)
}

/// Deletes a public key from the database
///
/// # Arguments
/// * `key_name` - The name of the key to delete
///
/// # Returns
/// * `true` if the key was deleted, `false` if the key was not found
#[pg_extern]
fn delete_public_key(key_name: &str) -> Result<bool, String> {
    // First check if the key exists
    let check_sql = format!(
        "SELECT COUNT(*) FROM hessra_public_keys WHERE key_name = '{}'",
        sql_escape(key_name)
    );

    let count_before = Spi::get_one::<i64>(&check_sql)
        .map_err(|e| format!("Failed to check key existence: {}", e))?
        .unwrap_or(0);

    if count_before == 0 {
        return Ok(false);
    }

    // Delete the key
    let delete_sql = format!(
        "DELETE FROM hessra_public_keys WHERE key_name = '{}'",
        sql_escape(key_name)
    );

    Spi::run(&delete_sql).map_err(|e| format!("Failed to delete key: {}", e))?;

    Ok(true)
}

/// Retrieves a public key from the database
///
/// # Arguments
/// * `key_name` - Optional name of the key to retrieve. If None, the default key is returned.
///
/// # Returns
/// * The PEM-encoded public key or an error if no key is found
#[pg_extern]
fn get_public_key(key_name: Option<&str>) -> Result<String, String> {
    let select_sql = match key_name {
        Some(name) => format!(
            "SELECT public_key FROM hessra_public_keys WHERE key_name = '{}'",
            sql_escape(name)
        ),
        None => {
            "SELECT public_key FROM hessra_public_keys WHERE is_default = TRUE LIMIT 1".to_string()
        }
    };

    let result =
        Spi::get_one::<String>(&select_sql).map_err(|e| format!("Database error: {}", e))?;

    match result {
        Some(key) => Ok(key),
        None => Err(match key_name {
            Some(name) => format!("No public key found with name: {}", name),
            None => "No default public key found".to_string(),
        }),
    }
}

//-----------------------------------------------------------------------------
// Service Chain Management Functions
//-----------------------------------------------------------------------------

/// Adds a new service chain to the database
///
/// # Arguments
/// * `service_name` - A unique name for the service chain
/// * `service_nodes` - JSON array of service nodes with component names and public keys
///
/// # Returns
/// * The ID of the newly created service chain or an error message
#[pg_extern]
fn add_service_chain(service_name: &str, service_nodes: &str) -> Result<i32, String> {
    // Validate the service_nodes JSON
    match serde_json::from_str::<Vec<hessra_token::ServiceNode>>(service_nodes) {
        Ok(_) => (),
        Err(e) => return Err(format!("Invalid service nodes JSON: {}", e)),
    }

    let insert_sql = format!(
        "INSERT INTO hessra_service_chains (service_name, service_nodes) 
         VALUES ('{}', '{}'::jsonb) 
         RETURNING id",
        sql_escape(service_name),
        sql_escape(service_nodes)
    );

    let result = Spi::get_one::<i32>(&insert_sql)
        .map_err(|e| format!("Failed to insert service chain: {}", e))?;

    match result {
        Some(id) => Ok(id),
        None => Err("No ID returned from insert".to_string()),
    }
}

/// Updates an existing service chain in the database
///
/// # Arguments
/// * `service_name` - The name of the service chain to update
/// * `service_nodes` - JSON array of service nodes with component names and public keys
///
/// # Returns
/// * `true` if the service chain was updated, `false` if it was not found
#[pg_extern]
fn update_service_chain(service_name: &str, service_nodes: &str) -> Result<bool, String> {
    // Validate the service_nodes JSON
    match serde_json::from_str::<Vec<hessra_token::ServiceNode>>(service_nodes) {
        Ok(_) => (),
        Err(e) => return Err(format!("Invalid service nodes JSON: {}", e)),
    }

    // Check if the service chain exists
    let check_sql = format!(
        "SELECT COUNT(*) FROM hessra_service_chains WHERE service_name = '{}'",
        sql_escape(service_name)
    );

    let count_before = Spi::get_one::<i64>(&check_sql)
        .map_err(|e| format!("Failed to check service chain existence: {}", e))?
        .unwrap_or(0);

    if count_before == 0 {
        return Ok(false);
    }

    // Update the service chain
    let update_sql = format!(
        "UPDATE hessra_service_chains 
         SET service_nodes = '{}'::jsonb, updated_at = NOW() 
         WHERE service_name = '{}'",
        sql_escape(service_nodes),
        sql_escape(service_name)
    );

    Spi::run(&update_sql).map_err(|e| format!("Failed to update service chain: {}", e))?;

    Ok(true)
}

/// Deletes a service chain from the database
///
/// # Arguments
/// * `service_name` - The name of the service chain to delete
///
/// # Returns
/// * `true` if the service chain was deleted, `false` if it was not found
#[pg_extern]
fn delete_service_chain(service_name: &str) -> Result<bool, String> {
    // First check if the service chain exists
    let check_sql = format!(
        "SELECT COUNT(*) FROM hessra_service_chains WHERE service_name = '{}'",
        sql_escape(service_name)
    );

    let count_before = Spi::get_one::<i64>(&check_sql)
        .map_err(|e| format!("Failed to check service chain existence: {}", e))?
        .unwrap_or(0);

    if count_before == 0 {
        return Ok(false);
    }

    // Delete the service chain
    let delete_sql = format!(
        "DELETE FROM hessra_service_chains WHERE service_name = '{}'",
        sql_escape(service_name)
    );

    Spi::run(&delete_sql).map_err(|e| format!("Failed to delete service chain: {}", e))?;

    Ok(true)
}

/// Retrieves a service chain from the database
///
/// # Arguments
/// * `service_name` - The name of the service chain to retrieve
///
/// # Returns
/// * The JSON representation of the service chain or an error if not found
#[pg_extern]
fn get_service_chain(service_name: &str) -> Result<String, String> {
    let select_sql = format!(
        "SELECT service_nodes::text FROM hessra_service_chains WHERE service_name = '{}'",
        sql_escape(service_name)
    );

    let result =
        Spi::get_one::<String>(&select_sql).map_err(|e| format!("Database error: {}", e))?;

    match result {
        Some(nodes) => Ok(nodes),
        None => Err(format!(
            "No service chain found with name: {}",
            service_name
        )),
    }
}

//-----------------------------------------------------------------------------
// Token Verification Functions
//-----------------------------------------------------------------------------

/// Verifies a token against a public key for access to a resource
///
/// # Arguments
/// * `token` - The biscuit token to verify
/// * `public_key` - The PEM-encoded public key to use for verification
/// * `subject` - The subject (user) attempting to access the resource
/// * `resource` - The resource being accessed
///
/// # Returns
/// * Ok(()) if verification succeeds, or an error describing why it failed
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

/// Verifies a token in a service chain context
///
/// # Arguments
/// * `token` - The biscuit token to verify
/// * `public_key` - The PEM-encoded public key to use for verification
/// * `subject` - The subject (user) attempting to access the resource
/// * `resource` - The resource being accessed
/// * `service_nodes` - JSON array of service nodes in the chain
/// * `component` - Optional component name; if specified, verifies the chain up to and including this component
///
/// # Returns
/// * Ok(()) if verification succeeds, or an error describing why it failed
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

//-----------------------------------------------------------------------------
// Convenience Functions Using Stored Configurations
//-----------------------------------------------------------------------------

/// Verifies a token using a stored public key
///
/// # Arguments
/// * `token` - The biscuit token to verify
/// * `key_name` - Optional name of the key to use (uses default if None)
/// * `subject` - The subject (user) attempting to access the resource
/// * `resource` - The resource being accessed
///
/// # Returns
/// * Ok(()) if verification succeeds, or an error describing why it failed
#[pg_extern]
fn verify_token_with_stored_key(
    token: &str,
    key_name: Option<&str>,
    subject: &str,
    resource: &str,
) -> Result<(), String> {
    // Get the public key from the database
    let public_key = get_public_key(key_name)?;

    // Call the original verify_token function
    verify_token(token, &public_key, subject, resource)
        .map_err(|e| format!("Token verification failed: {}", e))
}

/// Verifies a token in a service chain context using stored configurations
///
/// # Arguments
/// * `token` - The biscuit token to verify
/// * `key_name` - Optional name of the key to use (uses default if None)
/// * `subject` - The subject (user) attempting to access the resource
/// * `resource` - The resource being accessed
/// * `service_name` - Name of the service chain to use for verification
/// * `component` - Optional component name; if specified, verifies the chain up to and including this component
///
/// # Returns
/// * Ok(()) if verification succeeds, or an error describing why it failed
#[pg_extern]
fn verify_service_chain_token_with_stored_config(
    token: &str,
    key_name: Option<&str>,
    subject: &str,
    resource: &str,
    service_name: &str,
    component: Option<&str>,
) -> Result<(), String> {
    // Get the public key from the database
    let public_key = get_public_key(key_name)?;

    // Get the service chain from the database
    let service_nodes = get_service_chain(service_name)?;

    // Call the original verify_service_chain_token function
    verify_service_chain_token(
        token,
        &public_key,
        subject,
        resource,
        &service_nodes,
        component,
    )
    .map_err(|e| format!("Service chain token verification failed: {}", e))
}

//-----------------------------------------------------------------------------
// Test Modules
//-----------------------------------------------------------------------------

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

    #[pg_test]
    fn test_public_key_management() {
        // Test key to use
        let test_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8v7JR/nUJ2J0wD2/hVNH9U9mz4xv7BiKWUHGob5I3Zo=\n-----END PUBLIC KEY-----";

        // Add a key
        let id =
            crate::add_public_key("test_key", test_key, true).expect("Failed to add public key");
        assert!(id > 0, "Key ID should be positive");

        // Get the key by name
        let key = crate::get_public_key(Some("test_key")).expect("Failed to get key by name");
        assert_eq!(key, test_key, "Retrieved key should match original");

        // Get the default key
        let default_key = crate::get_public_key(None).expect("Failed to get default key");
        assert_eq!(default_key, test_key, "Default key should match test key");

        // Update the key
        let updated =
            crate::update_public_key("test_key", test_key, false).expect("Failed to update key");
        assert!(updated, "Update should return true");

        // Delete the key
        let deleted = crate::delete_public_key("test_key").expect("Failed to delete key");
        assert!(deleted, "Delete should return true");

        // Verify key no longer exists
        let result = crate::get_public_key(Some("test_key"));
        assert!(result.is_err(), "Key should no longer exist");
    }

    #[pg_test]
    fn test_service_chain_management() {
        // Test service chain
        let test_chain = r#"[
            {
                "component": "test_service",
                "public_key": "ed25519/0123456789abcdef0123456789abcdef"
            }
        ]"#;

        // Add a service chain
        let id = crate::add_service_chain("test_service", test_chain)
            .expect("Failed to add service chain");
        assert!(id > 0, "Chain ID should be positive");

        // Get the service chain
        let chain = crate::get_service_chain("test_service").expect("Failed to get service chain");

        // The retrieved JSON might be formatted differently, so we parse and compare
        let original: serde_json::Value = serde_json::from_str(test_chain).unwrap();
        let retrieved: serde_json::Value = serde_json::from_str(&chain).unwrap();
        assert_eq!(original, retrieved, "Retrieved chain should match original");

        // Update the chain
        let updated = crate::update_service_chain("test_service", test_chain)
            .expect("Failed to update service chain");
        assert!(updated, "Update should return true");

        // Delete the chain
        let deleted =
            crate::delete_service_chain("test_service").expect("Failed to delete service chain");
        assert!(deleted, "Delete should return true");

        // Verify chain no longer exists
        let result = crate::get_service_chain("test_service");
        assert!(result.is_err(), "Service chain should no longer exist");
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
