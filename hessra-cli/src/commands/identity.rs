use crate::cli::IdentityCommands;
use crate::config::{CliConfig, TokenStorage};
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
            server,
            port,
            ca,
        } => {
            delegate(
                identity,
                ttl,
                from_token,
                save_as,
                server,
                port,
                ca,
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
    save_as: String,
    server: Option<String>,
    port: u16,
    ca_path: Option<PathBuf>,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    let config = CliConfig::load()?;

    // Load the source token
    let token = TokenStorage::load_token(&from_token, &config)?;

    let progress = if !json_output {
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

    // We need to create an SDK instance to use the attenuation functionality
    // We need the public key for attenuation

    // Use provided server or fall back to config/default
    let server = server
        .or(config.default_server.clone())
        .unwrap_or_else(|| "test.hessra.net".to_string());

    // Use provided CA path or fall back to config
    let ca_path = ca_path.or(config.default_ca_path.clone());

    let ca = if let Some(ca_path) = ca_path.as_ref() {
        Some(
            fs::read_to_string(ca_path)
                .map_err(|e| CliError::FileNotFound(format!("CA certificate file: {e}")))?,
        )
    } else {
        None
    };

    // Fetch the public key from the server
    let public_key = if let Some(ca_cert) = ca.as_ref() {
        hessra_sdk::fetch_public_key(&server, Some(port), ca_cert).await?
    } else {
        return Err(CliError::Config(
            "CA certificate required for delegating tokens. Use --ca or set default_ca_path in config".to_string(),
        ));
    };

    let client = Hessra::builder()
        .base_url(&server)
        .port(port)
        .server_ca(ca.unwrap())
        .public_key(public_key)
        .build()?;

    // Attenuate the token locally
    let delegated_token = client.attenuate_identity_token(&token, &identity, ttl as i64)?;

    // Save the delegated token
    let token_path = TokenStorage::save_token(&save_as, &delegated_token, &config)?;

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    if json_output {
        let output = json!({
            "success": true,
            "delegated_identity": identity,
            "ttl": ttl,
            "from_token": from_token,
            "saved_as": save_as,
            "token_path": token_path,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", "✓ Delegated identity token created!".green());
        println!("  Delegated to: {}", identity.bright_cyan());
        println!("  TTL: {ttl} seconds");
        println!("  From token: {from_token}");
        println!("  Saved as: {}", save_as.bright_yellow());
        if verbose {
            println!("  Token path: {}", token_path.display());
        }
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
    // If server is provided, fetch it; otherwise try to use cached/configured one
    let mut builder = Hessra::builder();

    if let Some(server) = server.as_ref().or(config.default_server.as_ref()) {
        builder = builder.base_url(server);
        // We might need CA for server verification
        if let Some(ca_path) = config.default_ca_path.as_ref() {
            let ca = fs::read_to_string(ca_path)?;
            builder = builder.server_ca(&ca);
        }
    } else {
        // For local verification, we need a dummy base_url
        builder = builder.base_url("dummy");
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
