use crate::cli::IdentityCommands;
use crate::config::{CliConfig, PublicKeyStorage, ServerConfig, TokenStorage};
use crate::error::{CliError, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use dialoguer::Confirm;
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
            public_key_file,
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
                public_key_file,
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

        IdentityCommands::List { details } => list_tokens(json_output, details).await,

        IdentityCommands::Inspect {
            token_name,
            token_file,
            verbose: inspect_verbose,
            server,
            public_key,
            public_key_file,
        } => {
            inspect_token(
                token_name,
                token_file,
                server,
                public_key,
                public_key_file,
                inspect_verbose,
                json_output,
            )
            .await
        }

        IdentityCommands::Prune {
            dry_run,
            force,
            server,
            public_key,
            public_key_file,
        } => {
            prune_tokens(
                dry_run,
                force,
                server,
                public_key,
                public_key_file,
                json_output,
            )
            .await
        }

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

    // Resolve server from parameter or config
    let server = config.resolve_server(server)?;

    // Try to load server config for cert/key paths and port
    let server_config = ServerConfig::load(&server).ok();
    let resolved_port = server_config.as_ref().map(|c| c.port).unwrap_or(port);

    // Resolve cert and key paths
    let cert_path = cert_path
        .or_else(|| server_config.as_ref().and_then(|c| c.cert_path.clone()))
        .or(config.default_cert_path.clone())
        .ok_or_else(|| {
            CliError::InvalidInput(
                "Certificate path is required (--cert). Run: hessra config init".to_string(),
            )
        })?;

    let key_path = key_path
        .or_else(|| server_config.as_ref().and_then(|c| c.key_path.clone()))
        .or(config.default_key_path.clone())
        .ok_or_else(|| {
            CliError::InvalidInput(
                "Key path is required (--key). Run: hessra config init".to_string(),
            )
        })?;

    // Try to load CA cert from server directory first, then fall back to provided path
    let ca = if let Some(provided_ca_path) = ca_path {
        fs::read_to_string(&provided_ca_path)
            .map_err(|e| CliError::FileNotFound(format!("CA file: {e}")))?
    } else {
        let server_ca_path = ServerConfig::ca_cert_path(&server)?;
        if server_ca_path.exists() {
            if verbose && !json_output {
                println!("  Using CA cert from: {}", server_ca_path.display());
            }
            fs::read_to_string(&server_ca_path)
                .map_err(|e| CliError::FileNotFound(format!("CA file: {e}")))?
        } else {
            // CA cert doesn't exist - try to fetch it automatically
            if !json_output {
                println!(
                    "  Fetching CA certificate from {}...",
                    server.bright_white()
                );
            }

            match hessra_sdk::fetch_ca_cert(&server, Some(resolved_port)).await {
                Ok(ca_cert) => {
                    // Save the fetched CA cert
                    if let Some(parent) = server_ca_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&server_ca_path, &ca_cert)?;

                    // Create a basic server config if it doesn't exist
                    if server_config.is_none() {
                        let mut new_config = ServerConfig::new(server.clone(), resolved_port);
                        // Store the cert/key paths if provided
                        new_config.cert_path = cert_path.clone().into();
                        new_config.key_path = key_path.clone().into();
                        new_config.save()?;

                        if !json_output {
                            println!(
                                "  {} Server configuration created for {}",
                                "✓".green(),
                                server.bright_white()
                            );
                        }
                    }

                    if !json_output {
                        println!("  {} CA certificate fetched and cached", "✓".green());
                    }

                    ca_cert
                }
                Err(e) => {
                    return Err(CliError::Config(format!(
                        "CA certificate not found for server '{server}' and auto-fetch failed: {e}\n\n\
                        Either:\n\
                        1. Run: hessra init {server} --cert <cert> --key <key> --set-default\n\
                        2. Or provide CA manually: --ca <path_to_ca.crt>"
                    )));
                }
            }
        }
    };

    // Load mTLS cert and key
    let cert = fs::read_to_string(&cert_path)
        .map_err(|e| CliError::FileNotFound(format!("Certificate file: {e}")))?;
    let key = fs::read_to_string(&key_path)
        .map_err(|e| CliError::FileNotFound(format!("Key file: {e}")))?;

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
        .port(resolved_port)
        .protocol(Protocol::Http1)
        .mtls_cert(&cert)
        .mtls_key(&key)
        .server_ca(&ca)
        .build()
        .map_err(|e| CliError::Sdk(e.to_string()))?;

    // Setup (fetch public key)
    client
        .setup()
        .await
        .map_err(|e| CliError::Sdk(e.to_string()))?;

    // Save the public key for future use
    if let Ok(public_key) = hessra_sdk::fetch_public_key(&server, Some(resolved_port), &ca).await {
        PublicKeyStorage::save_public_key(&server, &public_key, &config)?;
        if verbose && !json_output {
            println!("  {} Public key cached for {server}", "✓".green());
        }
    }

    // Request identity token
    let ttl_str = ttl.map(|t| t.to_string());
    let response = client
        .request_identity_token(ttl_str)
        .await
        .map_err(|e| CliError::Sdk(e.to_string()))?;

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
            // Save token to server-specific directory
            let token_path =
                TokenStorage::save_token_for_server(&server, &save_as, &token, &config)?;

            if json_output {
                let output = json!({
                    "success": true,
                    "server": server,
                    "identity": identity,
                    "expires_in": expires,
                    "token_saved_as": save_as,
                    "token_path": token_path,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", "✓ Authentication successful!".green());
                println!("  Server: {}", server.bright_white());
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
    public_key_file: Option<PathBuf>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Resolve server from parameter or config
    let server = config.resolve_server(server)?;

    // Load the source token from server-specific directory
    let token = TokenStorage::load_token_for_server(&server, &from_token, &config)?;

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

    // Try to get the public key in order of priority:
    // 1. Provided via --public-key flag (PEM content directly)
    // 2. Provided via --public-key-file flag (read from file)
    // 3. Cached public key from server directory
    // 4. Fetch from server using CA certificate from server directory
    let public_key = if let Some(pk) = public_key_provided {
        if verbose && !json_output && !token_only {
            println!("  Using provided public key (PEM content)");
        }
        pk
    } else if let Some(pk_path) = public_key_file {
        if verbose && !json_output && !token_only {
            println!("  Reading public key from file: {}", pk_path.display());
        }
        fs::read_to_string(&pk_path).map_err(|e| {
            CliError::FileNotFound(format!("Public key file {}: {e}", pk_path.display()))
        })?
    } else {
        // Try to load from server directory
        let server_pubkey_path = ServerConfig::public_key_path(&server)?;
        if server_pubkey_path.exists() {
            if verbose && !json_output && !token_only {
                println!("  Using cached public key for {server}");
            }
            fs::read_to_string(&server_pubkey_path)
                .map_err(|e| CliError::FileNotFound(format!("Public key file: {e}")))?
        } else {
            // Try to fetch from server using CA cert
            let server_config = ServerConfig::load(&server).ok();
            let resolved_port = server_config.as_ref().map(|c| c.port).unwrap_or(port);

            let ca = if let Some(provided_ca_path) = ca_path {
                fs::read_to_string(&provided_ca_path)
                    .map_err(|e| CliError::FileNotFound(format!("CA file: {e}")))?
            } else {
                let server_ca_path = ServerConfig::ca_cert_path(&server)?;
                if server_ca_path.exists() {
                    fs::read_to_string(&server_ca_path)
                        .map_err(|e| CliError::FileNotFound(format!("CA file: {e}")))?
                } else {
                    return Err(CliError::Config(format!(
                        "Public key not found for server '{server}'. Run: hessra config refresh {server}"
                    )));
                }
            };

            if verbose && !json_output && !token_only {
                println!("  Fetching public key from {server}");
            }
            let fetched_key = hessra_sdk::fetch_public_key(&server, Some(resolved_port), &ca)
                .await
                .map_err(|e| CliError::Sdk(e.to_string()))?;

            // Cache the fetched key for future use
            PublicKeyStorage::save_public_key(&server, &fetched_key, &config)?;
            if verbose && !json_output && !token_only {
                println!("  {} Public key cached for {server}", "✓".green());
            }

            fetched_key
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
    const DUMMY_CA: &str = include_str!("../../certs/ca-2030.pem");

    if let Some(ca_path) = config.default_ca_path.clone() {
        if let Ok(ca) = fs::read_to_string(ca_path) {
            builder = builder.server_ca(&ca);
        } else {
            builder = builder.server_ca(DUMMY_CA);
        }
    } else {
        builder = builder.server_ca(DUMMY_CA);
    }

    let client = builder.build().map_err(|e| CliError::Sdk(e.to_string()))?;

    // Attenuate the token locally
    let delegated_token = client
        .attenuate_identity_token(&token, &identity, ttl as i64)
        .map_err(|e| CliError::Sdk(e.to_string()))?;

    // Save the delegated token if requested to server-specific directory
    let token_saved = if let Some(ref name) = save_as {
        let path = TokenStorage::save_token_for_server(&server, name, &delegated_token, &config)?;
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
            "server": server,
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
        println!("  Server: {}", server.bright_white());
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
    const DUMMY_CA: &str = include_str!("../../certs/ca-2030.pem");
    if let Some(ca_path) = config.default_ca_path.as_ref() {
        if let Ok(ca) = fs::read_to_string(ca_path) {
            builder = builder.server_ca(&ca);
        } else {
            builder = builder.server_ca(DUMMY_CA);
        }
    } else {
        builder = builder.server_ca(DUMMY_CA);
    }

    let client = builder.build().map_err(|e| CliError::Sdk(e.to_string()))?;

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

    let mut client = builder.build().map_err(|e| CliError::Sdk(e.to_string()))?;
    client
        .setup()
        .await
        .map_err(|e| CliError::Sdk(e.to_string()))?;

    // Refresh the token
    let response = client
        .refresh_identity_token(&token, None)
        .await
        .map_err(|e| CliError::Sdk(e.to_string()))?;

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

async fn list_tokens(json_output: bool, details: bool) -> Result<()> {
    let config = CliConfig::load()?;
    let tokens = TokenStorage::list_tokens(&config)?;

    if details {
        // Load config for public key access
        let mut token_details = Vec::new();

        for token_name in &tokens {
            match get_token_info(token_name, &config).await {
                Ok(info) => token_details.push(info),
                Err(_) => {
                    token_details.push(json!({
                        "name": token_name,
                        "error": "Failed to inspect token"
                    }));
                }
            }
        }

        if json_output {
            let output = json!({
                "tokens": token_details,
                "count": tokens.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{}", "Saved tokens:".bright_cyan());
            for detail in token_details {
                if let Some(name) = detail.get("name").and_then(|v| v.as_str()) {
                    print!("  • {name}");
                    if let Some(identity) = detail.get("identity").and_then(|v| v.as_str()) {
                        print!(" ({})", identity.dimmed());
                    }
                    if let Some(status) = detail.get("status").and_then(|v| v.as_str()) {
                        if status == "expired" {
                            print!(" {}", "[EXPIRED]".red());
                        } else if let Some(expires_in) =
                            detail.get("expires_in_human").and_then(|v| v.as_str())
                        {
                            print!(" - expires {}", expires_in.yellow());
                        }
                    }
                    println!();
                }
            }
        }
    } else if json_output {
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

async fn get_token_info(token_name: &str, config: &CliConfig) -> Result<serde_json::Value> {
    let token = TokenStorage::load_token(token_name, config)?;

    // Try to get public key from config or cache
    let server = config
        .default_server
        .as_deref()
        .unwrap_or("test.hessra.net");
    let public_key = PublicKeyStorage::load_public_key(server, config)?;

    if let Some(public_key_str) = public_key {
        match inspect_token_contents(&token, &public_key_str) {
            Ok((identity, expiry, status, expires_in_human)) => Ok(json!({
                "name": token_name,
                "identity": identity,
                "expiry": expiry,
                "status": status,
                "expires_in_human": expires_in_human,
            })),
            Err(_) => Ok(json!({
                "name": token_name,
                "error": "Invalid or corrupted token"
            })),
        }
    } else {
        Ok(json!({
            "name": token_name,
            "error": "No public key available"
        }))
    }
}

fn inspect_token_contents(
    token: &str,
    public_key_str: &str,
) -> Result<(String, Option<i64>, String, String)> {
    use biscuit_auth::macros::authorizer;
    use biscuit_auth::{Biscuit, PublicKey};

    // Parse public key from PEM format
    let public_key = PublicKey::from_pem(public_key_str)
        .map_err(|e| CliError::Token(format!("Invalid public key: {e}")))?;

    // Parse token
    let biscuit = Biscuit::from_base64(token, public_key)
        .map_err(|e| CliError::Token(format!("Failed to parse token: {e}")))?;

    // Extract information from the token by building an authorizer
    let now = Utc::now().timestamp();

    // Try to extract facts using an authorizer
    let authorizer = authorizer!(
        r#"
            time({now});
            allow if true;
        "#
    );

    let mut authorizer = authorizer
        .build(&biscuit)
        .map_err(|e| CliError::Token(format!("Failed to build authorizer: {e}")))?;

    // Query for subject fact
    let subjects: Vec<(String,)> = authorizer
        .query("data($name) <- subject($name)")
        .unwrap_or_default();

    let identity = subjects
        .first()
        .map(|(s,)| s.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Try to extract expiry from checks in the token's datalog
    let token_content = biscuit.print();
    let expiry = extract_expiry_from_content(&token_content);

    // Check if token is expired
    let (status, expires_in_human) = if let Some(exp) = expiry {
        if exp < now {
            (
                "expired".to_string(),
                format!("{} ago", format_duration(now - exp)),
            )
        } else {
            (
                "valid".to_string(),
                format!("in {}", format_duration(exp - now)),
            )
        }
    } else {
        ("unknown".to_string(), "unknown".to_string())
    };

    Ok((identity, expiry, status, expires_in_human))
}

fn extract_expiry_from_content(content: &str) -> Option<i64> {
    // Look for check constraints with time comparisons
    // Pattern: "check if time($time), $time < NUMBER"
    for line in content.lines() {
        if line.contains("check if") && line.contains("time") && line.contains("<") {
            // Try to extract the number after <
            if let Some(pos) = line.rfind('<') {
                let after_lt = &line[pos + 1..].trim();
                // Find the number, it might be followed by comma, semicolon or other chars
                let number_str = after_lt
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect::<String>();

                if let Ok(timestamp) = number_str.parse::<i64>() {
                    return Some(timestamp);
                }
            }
        }
    }
    None
}

fn format_duration(seconds: i64) -> String {
    let seconds = seconds.abs();
    if seconds < 60 {
        format!("{seconds} seconds")
    } else if seconds < 3600 {
        format!("{} minutes", seconds / 60)
    } else if seconds < 86400 {
        format!("{} hours", seconds / 3600)
    } else {
        format!("{} days", seconds / 86400)
    }
}

async fn inspect_token(
    token_name: Option<String>,
    token_file: Option<PathBuf>,
    server: Option<String>,
    public_key: Option<String>,
    public_key_file: Option<PathBuf>,
    verbose: bool,
    json_output: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Load the token
    let (token, source) = if let Some(name) = token_name {
        (
            TokenStorage::load_token(&name, &config)?,
            format!("saved token '{name}'"),
        )
    } else if let Some(path) = token_file {
        (fs::read_to_string(path)?, "token file".to_string())
    } else {
        // Default to "default" token if it exists
        if TokenStorage::token_exists("default", &config) {
            (
                TokenStorage::load_token("default", &config)?,
                "saved token 'default'".to_string(),
            )
        } else {
            return Err(CliError::Validation(
                "No token specified. Use --token-name or --token-file".into(),
            ));
        }
    };

    // Get public key
    let server = server
        .or_else(|| config.default_server.clone())
        .unwrap_or_else(|| "test.hessra.net".to_string());

    let public_key_str = if let Some(pk) = public_key {
        pk
    } else if let Some(pk_path) = public_key_file {
        fs::read_to_string(&pk_path).map_err(|e| {
            CliError::FileNotFound(format!("Public key file {}: {e}", pk_path.display()))
        })?
    } else if let Some(pk) = PublicKeyStorage::load_public_key(&server, &config)? {
        pk
    } else {
        return Err(CliError::Config(
            "No public key available. Provide one of:\n  --public-key <PEM_CONTENT>\n  --public-key-file <PATH>\nOr run 'hessra identity authenticate' first to cache the public key".into(),
        ));
    };

    // Parse and inspect the token
    use biscuit_auth::{Biscuit, PublicKey};

    // Parse public key from PEM format
    let public_key = PublicKey::from_pem(&public_key_str)
        .map_err(|e| CliError::Token(format!("Invalid public key: {e}")))?;

    let biscuit = Biscuit::from_base64(&token, public_key)
        .map_err(|e| CliError::Token(format!("Failed to parse token: {e}")))?;

    // Get token info
    let (identity, expiry, status, expires_in_human) =
        inspect_token_contents(&token, &public_key_str)?;

    if json_output {
        let mut output = json!({
            "source": source,
            "identity": identity,
            "status": status,
            "expiry": expiry,
            "expires_in_human": expires_in_human,
        });

        if verbose {
            output["content"] = json!(biscuit.print());
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} Token: {}", "✓".green().bold(), source);
        println!("  Identity: {identity}");
        let status_colored = if status == "expired" {
            status.red().to_string()
        } else {
            status.green().to_string()
        };
        println!("  Status: {status_colored}");

        if let Some(exp) = expiry {
            let dt = DateTime::from_timestamp(exp, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "invalid date".to_string());
            println!("  Expires: {dt} ({expires_in_human})");
        }

        if verbose {
            println!("\n{}", "Biscuit content:".bright_cyan());
            println!("{}", biscuit.print());
        }
    }

    Ok(())
}

async fn prune_tokens(
    dry_run: bool,
    force: bool,
    server: Option<String>,
    public_key: Option<String>,
    public_key_file: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let tokens = TokenStorage::list_tokens(&config)?;

    if tokens.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "checked": 0,
                    "expired": 0,
                    "removed": 0,
                    "message": "No tokens found"
                }))?
            );
        } else {
            println!("No saved tokens found.");
        }
        return Ok(());
    }

    // Get public key
    let server = server
        .or_else(|| config.default_server.clone())
        .unwrap_or_else(|| "test.hessra.net".to_string());

    let public_key_str = if let Some(pk) = public_key {
        pk
    } else if let Some(pk_path) = public_key_file {
        fs::read_to_string(&pk_path).map_err(|e| {
            CliError::FileNotFound(format!("Public key file {}: {e}", pk_path.display()))
        })?
    } else if let Some(pk) = PublicKeyStorage::load_public_key(&server, &config)? {
        pk
    } else {
        return Err(CliError::Config(
            "No public key available. Provide one of:\n  --public-key <PEM_CONTENT>\n  --public-key-file <PATH>\nOr run 'hessra identity authenticate' first to cache the public key".into(),
        ));
    };

    // Check each token
    let mut expired_tokens = Vec::new();
    let mut errors = Vec::new();

    for token_name in &tokens {
        match TokenStorage::load_token(token_name, &config) {
            Ok(token) => match inspect_token_contents(&token, &public_key_str) {
                Ok((_, _, status, expires_in)) => {
                    if status == "expired" {
                        expired_tokens.push((token_name.clone(), expires_in));
                    }
                }
                Err(_) => {
                    errors.push(token_name.clone());
                }
            },
            Err(_) => {
                errors.push(token_name.clone());
            }
        }
    }

    if expired_tokens.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "checked": tokens.len(),
                    "expired": 0,
                    "removed": 0,
                    "errors": errors,
                    "message": "No expired tokens found"
                }))?
            );
        } else {
            println!("Scanned {} tokens, none are expired.", tokens.len());
        }
        return Ok(());
    }

    // Display what will be removed
    if !json_output {
        println!(
            "Found {} tokens, {} are expired",
            tokens.len(),
            expired_tokens.len()
        );
        println!("\n{}", "Expired tokens:".yellow());
        for (name, expires_in) in &expired_tokens {
            println!("  - {name} (expired {expires_in})");
        }
    }

    if dry_run {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "checked": tokens.len(),
                    "expired": expired_tokens.len(),
                    "would_remove": expired_tokens.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                    "dry_run": true,
                }))?
            );
        } else {
            println!("\n{} Dry run - no tokens were deleted", "ℹ".blue());
        }
        return Ok(());
    }

    // Ask for confirmation if not forced
    let should_remove = if force {
        true
    } else if json_output {
        // In JSON mode, require --force flag
        false
    } else {
        Confirm::new()
            .with_prompt(format!("Remove {} expired tokens?", expired_tokens.len()))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?
    };

    if should_remove {
        let mut removed = 0;
        for (name, _) in &expired_tokens {
            if TokenStorage::delete_token(name, &config).is_ok() {
                removed += 1;
            }
        }

        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "checked": tokens.len(),
                    "expired": expired_tokens.len(),
                    "removed": removed,
                    "success": true,
                }))?
            );
        } else {
            println!("{} Removed {} expired tokens", "✓".green(), removed);
        }
    } else if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "checked": tokens.len(),
                "expired": expired_tokens.len(),
                "removed": 0,
                "cancelled": true,
            }))?
        );
    } else {
        println!("Operation cancelled.");
    }

    Ok(())
}
