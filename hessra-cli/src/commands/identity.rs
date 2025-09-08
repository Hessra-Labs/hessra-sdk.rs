use crate::cli::IdentityCommands;
use crate::config::{CliConfig, PublicKeyStorage, TokenStorage};
use crate::error::{CliError, Result};
use colored::Colorize;
use dialoguer::Input;
use hessra_sdk::{Hessra, IdentityTokenResponse, Protocol};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub async fn handle_identity_command(
    command: IdentityCommands,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    match command {
        IdentityCommands::Authenticate {
            server,
            port,
            cert,
            key,
            ca,
            save_as,
            ttl,
        } => {
            authenticate(
                server,
                port,
                cert,
                key,
                ca,
                save_as,
                ttl,
                json_output,
                verbose,
            )
            .await
        }

        IdentityCommands::Delegate {
            identity,
            ttl,
            from_token,
            save_as,
            token_only,
            server,
            port,
            ca,
            public_key,
        } => {
            delegate(
                identity,
                ttl,
                from_token,
                save_as,
                token_only,
                server,
                port,
                ca,
                public_key,
                json_output,
                verbose,
            )
            .await
        }

        IdentityCommands::Verify {
            token_name,
            token_file,
            identity,
            server,
        } => {
            verify(
                token_name,
                token_file,
                identity,
                server,
                json_output,
                verbose,
            )
            .await
        }

        IdentityCommands::Refresh {
            token_name,
            save_as,
            server,
            port,
        } => refresh(token_name, save_as, server, port, json_output, verbose).await,

        IdentityCommands::List => list_tokens(json_output).await,

        IdentityCommands::Delete { token_name } => delete_token(token_name, json_output).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    server: Option<String>,
    port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    save_as: String,
    ttl: Option<u64>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Resolve parameters with config defaults or prompts
    let server = server
        .or(config.default_server.clone())
        .or_else(|| {
            if !json_output {
                Input::new()
                    .with_prompt("Server hostname")
                    .default("test.hessra.net".to_string())
                    .interact()
                    .ok()
            } else {
                None
            }
        })
        .ok_or_else(|| CliError::InvalidInput("Server hostname is required".to_string()))?;

    let cert_path = cert_path
        .or(config.default_cert_path.clone())
        .ok_or_else(|| {
            CliError::InvalidInput("Certificate path is required (--cert)".to_string())
        })?;

    let key_path = key_path
        .or(config.default_key_path.clone())
        .ok_or_else(|| CliError::InvalidInput("Key path is required (--key)".to_string()))?;

    let ca_path = ca_path
        .or(config.default_ca_path.clone())
        .ok_or_else(|| CliError::InvalidInput("CA path is required (--ca)".to_string()))?;

    // Load certificates
    let cert = fs::read_to_string(&cert_path)
        .map_err(|e| CliError::FileNotFound(format!("Certificate file: {e}")))?;
    let key = fs::read_to_string(&key_path)
        .map_err(|e| CliError::FileNotFound(format!("Key file: {e}")))?;
    let ca = fs::read_to_string(&ca_path)
        .map_err(|e| CliError::FileNotFound(format!("CA file: {e}")))?;

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Authenticating with Hessra service...");
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Build SDK client
    let mut client = Hessra::builder()
        .base_url(&server)
        .port(port)
        .protocol(Protocol::Http1)
        .mtls_cert(&cert)
        .mtls_key(&key)
        .server_ca(&ca)
        .build()?;

    // Setup (fetch public key)
    client.setup().await?;

    // Save the public key for future use
    if let Ok(public_key) = hessra_sdk::fetch_public_key(&server, Some(port), &ca).await {
        PublicKeyStorage::save_public_key(&server, &public_key, &config)?;
        if verbose && !json_output {
            println!("  {} Public key cached for {server}", "✓".green());
        }
    }

    // Request identity token
    let ttl_str = ttl.map(|t| t.to_string());
    let response = client.request_identity_token(ttl_str).await?;

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    match response {
        IdentityTokenResponse {
            token: Some(token),
            identity: Some(identity),
            expires_in: Some(expires),
            ..
        } => {
            // Save token
            let token_path = TokenStorage::save_token(&save_as, &token, &config)?;

            if json_output {
                let output = json!({
                    "success": true,
                    "identity": identity,
                    "expires_in": expires,
                    "token_saved_as": save_as,
                    "token_path": token_path,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "✓ Authentication successful!".green());
                println!("  Identity: {}", identity.bright_cyan());
                println!("  Expires in: {expires} seconds");
                println!("  Token saved as: {}", save_as.bright_yellow());
                if verbose {
                    println!("  Token path: {}", token_path.display());
                }
            }
            Ok(())
        }
        _ => {
            let msg = format!("Authentication failed: {}", response.response_msg);
            if json_output {
                let output = json!({
                    "success": false,
                    "error": msg,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} {}", "✗".red(), msg);
            }
            Err(CliError::AuthenticationFailed(msg))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn delegate(
    identity: String,
    ttl: u64,
    from_token: String,
    save_as: Option<String>,
    token_only: bool,
    server: Option<String>,
    port: u16,
    ca_path: Option<PathBuf>,
    public_key_provided: Option<String>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Load the source token
    let token = TokenStorage::load_token(&from_token, &config)?;

    let progress = if !json_output && !token_only {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Creating delegated identity token...");
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Determine server to use for key caching
    let server = server
        .or(config.default_server.clone())
        .unwrap_or_else(|| "test.hessra.net".to_string());

    // Try to get the public key in order of priority:
    // 1. Provided via --public-key flag
    // 2. Cached public key for the server
    // 3. Fetch from server using CA certificate
    let public_key = if let Some(pk) = public_key_provided {
        if verbose && !json_output && !token_only {
            println!("  Using provided public key");
        }
        pk
    } else if let Some(pk) = PublicKeyStorage::load_public_key(&server, &config)? {
        if verbose && !json_output && !token_only {
            println!("  Using cached public key for {server}");
        }
        pk
    } else {
        // Need to fetch from server
        let ca_path_resolved = ca_path.or(config.default_ca_path.clone());

        let ca = if let Some(ca_path) = ca_path_resolved.as_ref() {
            Some(
                fs::read_to_string(ca_path)
                    .map_err(|e| CliError::FileNotFound(format!("CA certificate file: {e}")))?,
            )
        } else {
            None
        };

        if let Some(ca_cert) = ca.as_ref() {
            if verbose && !json_output && !token_only {
                println!("  Fetching public key from {server}");
            }
            let fetched_key = hessra_sdk::fetch_public_key(&server, Some(port), ca_cert).await?;

            // Cache the fetched key for future use
            PublicKeyStorage::save_public_key(&server, &fetched_key, &config)?;
            if verbose && !json_output && !token_only {
                println!("  {} Public key cached for {server}", "✓".green());
            }

            fetched_key
        } else {
            return Err(CliError::Config(
                "Public key required for delegating tokens. Provide --public-key, or --ca to fetch from server, or ensure a cached key exists".to_string(),
            ));
        }
    };

    // Build client with the public key
    let mut builder = Hessra::builder()
        .base_url(&server)
        .port(port)
        .public_key(public_key);

    // Add CA if available, otherwise use a dummy one (required by SDK even for local operations)
    // The SDK requires a valid PEM format even for local attenuation where it's not used
    // Using ISRG Root X1 certificate as a well-known valid CA
    const DUMMY_CA: &str = include_str!("../../../certs/ca-2030.pem");

    if let Some(ca_path) = config.default_ca_path.clone() {
        if let Ok(ca) = fs::read_to_string(ca_path) {
            builder = builder.server_ca(&ca);
        } else {
            builder = builder.server_ca(DUMMY_CA);
        }
    } else {
        builder = builder.server_ca(DUMMY_CA);
    }

    let client = builder.build()?;

    // Attenuate the token locally
    let delegated_token = client.attenuate_identity_token(&token, &identity, ttl as i64)?;

    // Save the delegated token if requested
    let token_saved = if let Some(ref name) = save_as {
        let path = TokenStorage::save_token(name, &delegated_token, &config)?;
        Some(path)
    } else {
        None
    };

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Handle output based on mode
    if token_only {
        // In token-only mode, just output the raw token (perfect for piping)
        println!("{delegated_token}");
    } else if json_output {
        let mut output = json!({
            "success": true,
            "token": delegated_token,
            "delegated_identity": identity,
            "ttl": ttl,
            "from_token": from_token,
            "saved": token_saved.is_some(),
        });

        if let Some(ref name) = save_as {
            output["saved_as"] = json!(name);
        }
        if let Some(ref path) = token_saved {
            output["token_path"] = json!(path);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Normal output mode
        println!("{}", "✓ Delegated identity token created!".green());
        println!("  Delegated to: {}", identity.bright_cyan());
        println!("  TTL: {ttl} seconds");
        println!("  From token: {from_token}");

        if let Some(ref name) = save_as {
            println!("  Saved as: {}", name.bright_yellow());
            if verbose {
                if let Some(ref path) = token_saved {
                    println!("  Token path: {}", path.display());
                }
            }
        } else {
            println!("  Status: {}", "Not saved (output only)".yellow());
        }

        // Always show the token in normal mode (not truncated)
        println!("\n{}", "Token:".bright_cyan());
        println!("{delegated_token}");
    }

    Ok(())
}

async fn verify(
    token_name: Option<String>,
    token_file: Option<PathBuf>,
    identity: Option<String>,
    server: Option<String>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Load token from either name or file
    let token = if let Some(name) = token_name {
        TokenStorage::load_token(&name, &config)?
    } else if let Some(path) = token_file {
        fs::read_to_string(path)?
    } else {
        TokenStorage::load_token("default", &config)?
    };

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Verifying identity token...");
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // For verification, we need the public key
    // Try to use cached public key if available
    let default_server = "test.hessra.net".to_string();
    let server_name = server
        .as_ref()
        .or(config.default_server.as_ref())
        .unwrap_or(&default_server);

    let mut builder = Hessra::builder().base_url(server_name);

    // Try to load cached public key
    if let Some(public_key) = PublicKeyStorage::load_public_key(server_name, &config)? {
        builder = builder.public_key(public_key);
        if verbose && !json_output {
            println!("  Using cached public key for {server_name}");
        }
    }

    // Add CA if available, otherwise use dummy (SDK requires it)
    const DUMMY_CA: &str = include_str!("../../../certs/ca-2030.pem");
    if let Some(ca_path) = config.default_ca_path.as_ref() {
        if let Ok(ca) = fs::read_to_string(ca_path) {
            builder = builder.server_ca(&ca);
        } else {
            builder = builder.server_ca(DUMMY_CA);
        }
    } else {
        builder = builder.server_ca(DUMMY_CA);
    }

    let client = builder.build()?;

    // Try to extract identity from token if not provided
    let identity = if let Some(id) = identity {
        id
    } else {
        // Parse token to extract identity (this is a simplified version)
        // In reality, you'd decode the Biscuit token properly
        if !json_output && !verbose {
            eprintln!("Warning: Identity not provided, verification may be incomplete");
        }
        "unknown".to_string()
    };

    // Perform local verification
    let result = client.verify_identity_token_local(&token, &identity);

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    match result {
        Ok(_) => {
            if json_output {
                let output = json!({
                    "success": true,
                    "valid": true,
                    "identity": identity,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "✓ Token is valid!".green());
                println!("  Identity: {}", identity.bright_cyan());
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                let output = json!({
                    "success": false,
                    "valid": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Token verification failed: {e}", "✗".red());
            }
            Err(CliError::Token(format!("Verification failed: {e}")))
        }
    }
}

async fn refresh(
    token_name: String,
    save_as: Option<String>,
    server: Option<String>,
    port: Option<u16>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Load the token to refresh
    let token = TokenStorage::load_token(&token_name, &config)?;

    let server = server
        .or(config.default_server.clone())
        .ok_or_else(|| CliError::InvalidInput("Server is required for refresh".to_string()))?;

    let port = port.unwrap_or(443);

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Refreshing identity token...");
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Build client (no mTLS needed for refresh)
    let mut builder = Hessra::builder()
        .base_url(&server)
        .port(port)
        .protocol(Protocol::Http1);

    // Add CA if available
    if let Some(ca_path) = config.default_ca_path.as_ref() {
        let ca = fs::read_to_string(ca_path)?;
        builder = builder.server_ca(&ca);
    }

    let mut client = builder.build()?;
    client.setup().await?;

    // Refresh the token
    let response = client.refresh_identity_token(&token, None).await?;

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    match response {
        IdentityTokenResponse {
            token: Some(new_token),
            identity: Some(identity),
            expires_in: Some(expires),
            ..
        } => {
            // Save the refreshed token
            let save_name = save_as.unwrap_or(token_name);
            let token_path = TokenStorage::save_token(&save_name, &new_token, &config)?;

            if json_output {
                let output = json!({
                    "success": true,
                    "identity": identity,
                    "expires_in": expires,
                    "saved_as": save_name,
                    "token_path": token_path,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "✓ Token refreshed successfully!".green());
                println!("  Identity: {}", identity.bright_cyan());
                println!("  Expires in: {expires} seconds");
                println!("  Saved as: {}", save_name.bright_yellow());
                if verbose {
                    println!("  Token path: {}", token_path.display());
                }
            }
            Ok(())
        }
        _ => {
            let msg = format!("Refresh failed: {}", response.response_msg);
            if json_output {
                let output = json!({
                    "success": false,
                    "error": msg,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} {}", "✗".red(), msg);
            }
            Err(CliError::Token(msg))
        }
    }
}

async fn list_tokens(json_output: bool) -> Result<()> {
    let config = CliConfig::load()?;
    let tokens = TokenStorage::list_tokens(&config)?;

    if json_output {
        let output = json!({
            "tokens": tokens,
            "count": tokens.len(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if tokens.is_empty() {
        println!("No saved tokens found.");
    } else {
        println!("{}", "Saved tokens:".bright_cyan());
        for token in tokens {
            println!("  • {token}");
        }
    }

    Ok(())
}

async fn delete_token(token_name: String, json_output: bool) -> Result<()> {
    let config = CliConfig::load()?;
    TokenStorage::delete_token(&token_name, &config)?;

    if json_output {
        let output = json!({
            "success": true,
            "deleted": token_name,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} Token '{token_name}' deleted.", "✓".green());
    }

    Ok(())
}
