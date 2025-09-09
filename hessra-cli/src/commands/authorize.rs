use crate::cli::AuthorizeCommands;
use crate::config::{CliConfig, PublicKeyStorage, TokenStorage};
use crate::error::{CliError, Result};
use colored::Colorize;
use hessra_sdk::{Hessra, Protocol, TokenResponse};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

pub async fn handle_authorize_command(command: AuthorizeCommands, json_output: bool) -> Result<()> {
    match command {
        AuthorizeCommands::Request {
            resource,
            operation,
            identity_token,
            token_file,
            token_only,
            cert,
            key,
            ca,
            server,
            port,
            public_key,
        } => {
            request_authorization(
                resource,
                operation,
                identity_token,
                token_file,
                cert,
                key,
                ca,
                server,
                port,
                public_key,
                json_output,
                token_only,
            )
            .await
        }
        AuthorizeCommands::Verify {
            token,
            subject,
            resource,
            operation,
            server,
            port,
            public_key,
        } => {
            verify_authorization(
                token,
                subject,
                resource,
                operation,
                server,
                port,
                public_key,
                json_output,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn request_authorization(
    resource: String,
    operation: String,
    identity_token_name: Option<String>,
    token_file: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
    server: Option<String>,
    port: u16,
    public_key: Option<String>,
    json_output: bool,
    token_only: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Determine authentication method and load identity token if needed
    let identity_token = if let Some(name) = identity_token_name {
        // Explicitly specified identity token
        Some(TokenStorage::load_token(&name, &config)?)
    } else if let Some(path) = token_file {
        // Identity token from file
        Some(fs::read_to_string(path)?)
    } else if TokenStorage::token_exists("default", &config) {
        // Try to use default identity token if it exists
        Some(TokenStorage::load_token("default", &config)?)
    } else {
        // No identity token available, will use mTLS
        None
    };

    let progress = if !json_output && !token_only {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Requesting authorization token...");
        Some(pb)
    } else {
        None
    };

    // Get server from config if not specified
    let server = server
        .or_else(|| config.default_server.clone())
        .ok_or_else(|| CliError::Config("No server specified and no default configured".into()))?;

    // Normalize server URL
    let server = if !server.starts_with("http://") && !server.starts_with("https://") {
        server
    } else {
        server
            .replace("https://", "")
            .replace("http://", "")
            .replace('/', "")
    };

    // Load or fetch public key for verification
    let public_key = if let Some(pk) = public_key {
        pk
    } else if let Some(pk) = PublicKeyStorage::load_public_key(&server, &config)? {
        pk
    } else {
        // We need to fetch the public key
        if let Some(ref pb) = progress {
            pb.set_message("Fetching server public key...");
        }

        // Build SDK to fetch public key
        let mut sdk = build_sdk_for_auth(
            &server,
            port,
            &identity_token,
            cert.as_deref(),
            key.as_deref(),
            ca.as_deref(),
            &config,
        )?;

        sdk.setup()
            .await
            .map_err(|e| CliError::Sdk(format!("Failed to fetch public key: {e}")))?;

        let pk = sdk
            .get_public_key()
            .await
            .map_err(|e| CliError::Sdk(format!("Failed to get public key: {e}")))?;

        // Cache the public key for future use
        PublicKeyStorage::save_public_key(&server, &pk, &config)?;
        pk
    };

    // Build SDK with appropriate authentication
    let sdk = if identity_token.is_some() {
        // Build SDK without mTLS, will use identity token
        Hessra::builder()
            .base_url(&server)
            .port(port)
            .protocol(Protocol::Http1)
            .public_key(&public_key)
            .server_ca(ca_cert_or_default(ca.as_deref())?)
            .build()
            .map_err(|e| CliError::Sdk(e.to_string()))?
    } else {
        // Build SDK with mTLS
        build_sdk_for_auth(
            &server,
            port,
            &None,
            cert.as_deref(),
            key.as_deref(),
            ca.as_deref(),
            &config,
        )?
    };

    if let Some(ref pb) = progress {
        pb.set_message(format!(
            "Requesting authorization for {resource}:{operation}..."
        ));
    }

    // Request the authorization token
    let response: TokenResponse = if let Some(id_token) = identity_token {
        sdk.request_token_with_identity(&resource, &operation, &id_token)
            .await
            .map_err(|e| CliError::Sdk(format!("Authorization request failed: {e}")))?
    } else {
        sdk.request_token(&resource, &operation)
            .await
            .map_err(|e| CliError::Sdk(format!("Authorization request failed: {e}")))?
    };

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Handle the response
    match response.token {
        Some(token) => {
            if token_only {
                // Just output the raw token
                print!("{token}");
            } else if json_output {
                let output = json!({
                    "success": true,
                    "token": token,
                    "resource": resource,
                    "operation": operation,
                    "response_msg": response.response_msg,
                    "pending_signoffs": response.pending_signoffs,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Authorization token granted!", "✓".green().bold());
                println!("  Resource: {resource}");
                println!("  Operation: {operation}");
                if let Some(signoffs) = &response.pending_signoffs {
                    if !signoffs.is_empty() {
                        println!(
                            "  {} This token requires {} additional signoffs",
                            "⚠".yellow(),
                            signoffs.len()
                        );
                        for signoff in signoffs {
                            println!(
                                "    - {} ({})",
                                signoff.component, signoff.authorization_service
                            );
                        }
                    }
                }
                println!("\nToken:");
                println!("{token}");
            }
        }
        None => {
            if json_output {
                let output = json!({
                    "success": false,
                    "resource": resource,
                    "operation": operation,
                    "response_msg": response.response_msg,
                    "pending_signoffs": response.pending_signoffs,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                eprintln!("{} Authorization denied", "✗".red().bold());
                eprintln!("  Resource: {resource}");
                eprintln!("  Operation: {operation}");
                eprintln!("  Reason: {}", response.response_msg);
                if let Some(signoffs) = response.pending_signoffs {
                    if !signoffs.is_empty() {
                        eprintln!(
                            "  {} Token requires {} signoffs that were not completed",
                            "⚠".yellow(),
                            signoffs.len()
                        );
                    }
                }
            }
            return Err(CliError::Authorization(response.response_msg));
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_authorization(
    token: Option<String>,
    subject: String,
    resource: String,
    operation: String,
    server: Option<String>,
    port: u16,
    public_key: Option<String>,
    json_output: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Get token from argument or stdin
    let token = if let Some(t) = token {
        t
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer.trim().to_string()
    };

    if token.is_empty() {
        return Err(CliError::Validation(
            "No token provided. Use --token or pipe token to stdin".into(),
        ));
    }

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Verifying authorization token...");
        Some(pb)
    } else {
        None
    };

    // Get server from config if not specified
    let server = server
        .or_else(|| config.default_server.clone())
        .ok_or_else(|| CliError::Config("No server specified and no default configured".into()))?;

    // Normalize server URL
    let server = if !server.starts_with("http://") && !server.starts_with("https://") {
        server
    } else {
        server
            .replace("https://", "")
            .replace("http://", "")
            .replace('/', "")
    };

    // Load or fetch public key for verification
    let public_key = if let Some(pk) = public_key {
        pk
    } else if let Some(pk) = PublicKeyStorage::load_public_key(&server, &config)? {
        pk
    } else {
        return Err(CliError::Config(
            "No public key available. Run 'hessra identity authenticate' first or provide --public-key".into(),
        ));
    };

    // Build SDK for verification (only needs public key)
    let sdk = Hessra::builder()
        .base_url(&server)
        .port(port)
        .protocol(Protocol::Http1)
        .public_key(&public_key)
        .server_ca(ca_cert_or_default(None)?)
        .build()
        .map_err(|e| CliError::Sdk(e.to_string()))?;

    // Verify the token
    let result = sdk
        .verify_token(&token, &subject, &resource, &operation)
        .await;

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    match result {
        Ok(_) => {
            if json_output {
                let output = json!({
                    "success": true,
                    "subject": subject,
                    "resource": resource,
                    "operation": operation,
                    "message": "Token is valid"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Token is valid!", "✓".green().bold());
                println!("  Subject: {subject}");
                println!("  Resource: {resource}");
                println!("  Operation: {operation}");
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                let output = json!({
                    "success": false,
                    "subject": subject,
                    "resource": resource,
                    "operation": operation,
                    "error": e.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                eprintln!("{} Token verification failed", "✗".red().bold());
                eprintln!("  Subject: {subject}");
                eprintln!("  Resource: {resource}");
                eprintln!("  Operation: {operation}");
                eprintln!("  Error: {e}");
            }
            Err(CliError::Verification(e.to_string()))
        }
    }
}

fn build_sdk_for_auth(
    server: &str,
    port: u16,
    identity_token: &Option<String>,
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    ca: Option<&std::path::Path>,
    config: &CliConfig,
) -> Result<Hessra> {
    let mut builder = Hessra::builder()
        .base_url(server)
        .port(port)
        .protocol(Protocol::Http1);

    // If we're using identity token, we don't need mTLS
    if identity_token.is_none() {
        // Load certificates for mTLS
        let cert_content = if let Some(cert_path) = cert {
            fs::read_to_string(cert_path)?
        } else if let Some(ref cert_path) = config.default_cert_path {
            fs::read_to_string(cert_path)?
        } else {
            return Err(CliError::Config(
                "No certificate specified and no default configured. Use --cert or configure defaults".into(),
            ));
        };

        let key_content = if let Some(key_path) = key {
            fs::read_to_string(key_path)?
        } else if let Some(ref key_path) = config.default_key_path {
            fs::read_to_string(key_path)?
        } else {
            return Err(CliError::Config(
                "No key specified and no default configured. Use --key or configure defaults"
                    .into(),
            ));
        };

        builder = builder.mtls_cert(&cert_content).mtls_key(&key_content);
    }

    // CA certificate
    let ca_content = ca_cert_or_default(ca)?;
    builder = builder.server_ca(&ca_content);

    builder.build().map_err(|e| CliError::Sdk(e.to_string()))
}

fn ca_cert_or_default(ca: Option<&std::path::Path>) -> Result<String> {
    if let Some(ca_path) = ca {
        Ok(fs::read_to_string(ca_path)?)
    } else {
        // Use the default CA certificate that's bundled with the CLI
        Ok(include_str!("../../../certs/ca-2030.pem").to_string())
    }
}
