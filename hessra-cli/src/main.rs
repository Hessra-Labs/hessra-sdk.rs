mod cli;
mod commands;
mod config;
mod error;

use clap::Parser;
use cli::{Cli, Commands, ConfigCommands};
use colored::Colorize;
use config::{CliConfig, ServerConfig};
use error::Result;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "Error:".red(), e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            server,
            port,
            cert,
            key,
            set_default,
            skip_fetch,
            force,
        } => {
            init_server_interactive(
                server,
                port,
                cert,
                key,
                set_default,
                skip_fetch,
                force,
                cli.json,
            )
            .await
        }
        Commands::Identity { command } => {
            commands::handle_identity_command(command, cli.json, cli.verbose).await
        }
        Commands::Authorize { command } => {
            commands::handle_authorize_command(command, cli.json).await
        }
        Commands::Config { command } => handle_config_command(command, cli.json).await,
    }
}

async fn handle_config_command(command: ConfigCommands, json_output: bool) -> Result<()> {
    match command {
        ConfigCommands::Init {
            server,
            port,
            cert,
            key,
            set_default,
            skip_fetch,
            force,
        } => {
            init_server_direct(
                server,
                port,
                cert,
                key,
                set_default,
                skip_fetch,
                force,
                json_output,
            )
            .await?
        }

        ConfigCommands::List { details } => {
            list_servers(details, json_output)?;
        }

        ConfigCommands::Show { server } => {
            show_server(&server, json_output)?;
        }

        ConfigCommands::Switch { server } => {
            switch_server(&server, json_output)?;
        }

        ConfigCommands::Refresh { server } => {
            refresh_server(&server, json_output).await?;
        }

        ConfigCommands::Remove { server, force } => {
            remove_server(&server, force, json_output)?;
        }

        ConfigCommands::Set { key, value } => {
            let mut config = CliConfig::load()?;

            let value_display = value.clone();

            match key.as_str() {
                "default_server" => config.default_server = Some(value),
                "default_port" => {
                    let port = value.parse::<u16>().map_err(|_| {
                        error::CliError::InvalidInput("Invalid port number".to_string())
                    })?;
                    config.default_port = Some(port);
                }
                "default_cert_path" => config.default_cert_path = Some(value.into()),
                "default_key_path" => config.default_key_path = Some(value.into()),
                "default_ca_path" => config.default_ca_path = Some(value.into()),
                "token_storage_dir" => config.token_storage_dir = Some(value.into()),
                _ => {
                    return Err(error::CliError::InvalidInput(format!(
                        "Unknown configuration key: {key}"
                    )));
                }
            }

            config.save()?;

            if json_output {
                let output = json!({
                    "success": true,
                    "key": key,
                    "value": value_display.clone(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Set {key} = {value_display}", "✓".green());
            }
        }

        ConfigCommands::Get { key } => {
            let config = CliConfig::load()?;

            if let Some(key) = key {
                let value = match key.as_str() {
                    "default_server" => config.default_server.as_deref().unwrap_or("(not set)"),
                    "default_port" => &config
                        .default_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "(not set)".to_string()),
                    "default_cert_path" => config
                        .default_cert_path
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("(not set)"),
                    "default_key_path" => config
                        .default_key_path
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("(not set)"),
                    "default_ca_path" => config
                        .default_ca_path
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("(not set)"),
                    "token_storage_dir" => config
                        .token_storage_dir
                        .as_ref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("(not set)"),
                    _ => {
                        return Err(error::CliError::InvalidInput(format!(
                            "Unknown configuration key: {key}"
                        )));
                    }
                };

                if json_output {
                    let output = json!({
                        key: value,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{key} = {value}");
                }
            } else {
                // Show all configuration
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&config)?);
                } else {
                    println!("{}", "Configuration:".bright_cyan());
                    println!(
                        "  default_server: {}",
                        config.default_server.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "  default_port: {}",
                        config
                            .default_port
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "(not set)".to_string())
                    );
                    println!(
                        "  default_cert_path: {}",
                        config
                            .default_cert_path
                            .as_ref()
                            .and_then(|p| p.to_str())
                            .unwrap_or("(not set)")
                    );
                    println!(
                        "  default_key_path: {}",
                        config
                            .default_key_path
                            .as_ref()
                            .and_then(|p| p.to_str())
                            .unwrap_or("(not set)")
                    );
                    println!(
                        "  default_ca_path: {}",
                        config
                            .default_ca_path
                            .as_ref()
                            .and_then(|p| p.to_str())
                            .unwrap_or("(not set)")
                    );
                    println!(
                        "  token_storage_dir: {}",
                        config
                            .token_storage_dir
                            .as_ref()
                            .and_then(|p| p.to_str())
                            .unwrap_or("(default)")
                    );
                }
            }
        }

        ConfigCommands::Path => {
            let path = CliConfig::config_file_path()?;

            if json_output {
                let output = json!({
                    "config_path": path,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", path.display());
            }
        }
    }

    Ok(())
}

/// Interactive wizard for `hessra init`
#[allow(clippy::too_many_arguments)]
async fn init_server_interactive(
    server: Option<String>,
    port: u16,
    cert_path: Option<std::path::PathBuf>,
    key_path: Option<std::path::PathBuf>,
    set_default: bool,
    skip_fetch: bool,
    force: bool,
    json_output: bool,
) -> Result<()> {
    use config::TokenStorage;
    use dialoguer::{Confirm, Input};

    // JSON mode doesn't make sense for interactive wizard
    if json_output {
        return init_server_direct(
            server,
            port,
            cert_path,
            key_path,
            set_default,
            skip_fetch,
            force,
            json_output,
        )
        .await;
    }

    // Step 1: Display logo
    let logo = include_str!("../resources/hessra_unicode_logo.txt");
    println!("{logo}");
    println!("{}\n", "Welcome to Hessra!".bright_cyan().bold());

    // Step 2: Scan existing configuration
    let config_dir = CliConfig::config_dir()?;
    let has_config = config_dir.exists();
    let global_config = CliConfig::load().unwrap_or_default();
    let servers = ServerConfig::list_servers().unwrap_or_default();

    if has_config && !servers.is_empty() {
        // Existing configuration - show summary
        println!("{}", "Current Configuration:".bright_white().bold());
        println!(
            "  Configured servers: {}",
            servers.join(", ").bright_yellow()
        );

        if let Some(ref default_server) = global_config.default_server {
            println!("  Default server: {}", default_server.bright_green().bold());
        } else {
            println!("  Default server: {}", "(not set)".dimmed());
        }

        // Show token counts per server
        for server_name in &servers {
            let token_count = TokenStorage::list_tokens_for_server(server_name, &global_config)
                .unwrap_or_default()
                .len();
            if token_count > 0 {
                println!(
                    "  {}: {} token{}",
                    server_name.bright_white(),
                    token_count,
                    if token_count == 1 { "" } else { "s" }
                );
            }
        }

        println!();

        // Ask if they want to add a new server
        let add_server = Confirm::new()
            .with_prompt("Would you like to configure a new server?")
            .default(false)
            .interact()
            .map_err(|e| error::CliError::Io(std::io::Error::other(e)))?;

        if !add_server {
            println!("\n{} Setup complete!", "✓".green());
            return Ok(());
        }

        println!();
    } else {
        // New user
        println!(
            "{}",
            "It looks like this is your first time using Hessra.".dimmed()
        );
        println!("{}\n", "Let's get you set up!\n".dimmed());
    }

    // Step 3: Get server hostname
    let server_hostname = if let Some(s) = server {
        s
    } else {
        Input::new()
            .with_prompt("Enter your Hessra server hostname")
            .default("test.hessra.net".to_string())
            .interact_text()
            .map_err(|e| error::CliError::Io(std::io::Error::other(e)))?
    };

    // Check if already configured
    if ServerConfig::exists(&server_hostname) && !force {
        println!(
            "{} Server '{}' is already configured.",
            "!".yellow(),
            server_hostname
        );
        println!("Use --force to overwrite or run: hessra config show {server_hostname}");
        return Ok(());
    }

    // Step 4: Ask about default server
    let make_default = if !set_default {
        let prompt_text = if let Some(ref current_default) = global_config.default_server {
            format!(
                "Set '{server_hostname}' as default server? (current default: {current_default})"
            )
        } else {
            format!("Set '{server_hostname}' as default server?")
        };

        Confirm::new()
            .with_prompt(prompt_text)
            .default(global_config.default_server.is_none())
            .interact()
            .map_err(|e| error::CliError::Io(std::io::Error::other(e)))?
    } else {
        set_default
    };

    println!("\n{}", "Initializing server configuration...".bright_cyan());

    // Call the direct init function to do the actual work
    init_server_direct(
        Some(server_hostname.clone()),
        port,
        cert_path.clone(),
        key_path.clone(),
        make_default,
        skip_fetch,
        force,
        false, // Never JSON for interactive
    )
    .await?;

    // Step 5: Provide next steps with copy-paste commands
    println!("\n{}", "Next Steps:".bright_cyan().bold());

    let is_test_server = server_hostname == "test.hessra.net";

    if is_test_server {
        println!("{}", "  Get your first identity token:".bright_white());
        // Use the built-in certs for test.hessra.net
        println!("{}", "  Run this command:".dimmed());
        println!();
        println!(
            "    {}",
            "hessra identity authenticate --server test.hessra.net --cert ./certs/client.crt --key ./certs/client.key"
                .bright_green()
        );
    } else {
        println!("{}", "  Get your first identity token:".bright_white());
        println!(
            "{}",
            "  Run this command with your certificate paths:".dimmed()
        );
        println!();
        println!(
            "    {}",
            format!("hessra identity authenticate --server {server_hostname} --cert <path_to_cert> --key <path_to_key>")
            .bright_green()
        );
    }

    println!();
    println!(
        "{}",
        "  For more information, visit: https://docs.hessra.net".dimmed()
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn init_server_direct(
    server: Option<String>,
    port: u16,
    cert_path: Option<std::path::PathBuf>,
    key_path: Option<std::path::PathBuf>,
    set_default: bool,
    skip_fetch: bool,
    force: bool,
    json_output: bool,
) -> Result<()> {
    use dialoguer::Input;

    // Get server hostname (prompt if not provided)
    let server = match server {
        Some(s) => s,
        None => {
            if json_output {
                return Err(error::CliError::InvalidInput(
                    "Server hostname required in JSON mode".to_string(),
                ));
            }
            Input::new()
                .with_prompt("Server hostname (e.g., test.hessra.net)")
                .interact()
                .map_err(|e| error::CliError::Io(std::io::Error::other(e)))?
        }
    };

    // Check if server already configured
    if ServerConfig::exists(&server) && !force {
        if json_output {
            let output = json!({
                "success": false,
                "error": format!("Server '{}' already configured. Use --force to overwrite.", server),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{} Server '{}' already configured.", "!".yellow(), server);
            println!("Use --force to overwrite or run: hessra servers show {server}");
        }
        return Ok(());
    }

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Initializing configuration for {server}..."));
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    // Fetch CA certificate and public key unless skipped
    let mut ca_fetched = false;
    let mut pubkey_fetched = false;

    if !skip_fetch {
        if let Some(pb) = progress.as_ref() {
            pb.set_message(format!("Fetching CA certificate from {server}..."));
        }

        // Fetch CA certificate
        match hessra_sdk::fetch_ca_cert(&server, Some(port)).await {
            Ok(ca_cert) => {
                let ca_path = ServerConfig::ca_cert_path(&server)?;
                if let Some(parent) = ca_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&ca_path, ca_cert)?;
                ca_fetched = true;
            }
            Err(e) => {
                if let Some(pb) = progress.as_ref() {
                    pb.finish_and_clear();
                }
                if !json_output {
                    println!("{} Failed to fetch CA certificate: {}", "!".yellow(), e);
                    println!("  You can fetch it later with: hessra servers refresh {server}");
                }
            }
        }

        // Fetch public key (only if we have CA cert)
        if ca_fetched {
            if let Some(pb) = progress.as_ref() {
                pb.set_message(format!("Fetching public key from {server}..."));
            }

            let ca_path = ServerConfig::ca_cert_path(&server)?;
            let ca_cert = std::fs::read_to_string(&ca_path)?;

            match hessra_sdk::fetch_public_key(&server, Some(port), &ca_cert).await {
                Ok(public_key) => {
                    let pubkey_path = ServerConfig::public_key_path(&server)?;
                    std::fs::write(&pubkey_path, public_key)?;
                    pubkey_fetched = true;
                }
                Err(e) => {
                    if let Some(pb) = progress.as_ref() {
                        pb.finish_and_clear();
                    }
                    if !json_output {
                        println!("{} Failed to fetch public key: {}", "!".yellow(), e);
                        println!("  You can fetch it later with: hessra servers refresh {server}");
                    }
                }
            }
        }
    }

    // Create server configuration
    let mut server_config = ServerConfig::new(server.clone(), port);
    server_config.cert_path = cert_path;
    server_config.key_path = key_path;
    server_config.save()?;

    // Set as default if requested
    if set_default {
        let mut global_config = CliConfig::load().unwrap_or_default();
        global_config.default_server = Some(server.clone());
        global_config.save()?;
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    if json_output {
        let output = json!({
            "success": true,
            "server": server,
            "port": port,
            "ca_fetched": ca_fetched,
            "public_key_fetched": pubkey_fetched,
            "set_as_default": set_default,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} Initialized configuration for {}", "✓".green(), server);
        if ca_fetched {
            println!("  {} Fetched CA certificate", "✓".green());
        }
        if pubkey_fetched {
            println!("  {} Fetched public key", "✓".green());
        }
        if set_default {
            println!("  {} Set as default server", "✓".green());
        }

        println!(
            "\nConfiguration saved to: {}",
            CliConfig::server_dir(&server)?.display()
        );

        println!("\n{}", "Next steps:".bright_cyan());
        if server_config.cert_path.is_none() || server_config.key_path.is_none() {
            println!("  1. Authenticate with mTLS:");
            println!("     hessra identity authenticate --cert ./client.crt --key ./client.key");
        } else {
            println!("  1. Authenticate:");
            println!("     hessra identity authenticate");
        }
        println!("  2. Delegate tokens:");
        println!("     hessra identity delegate --identity \"uri:agent:bot\"");
    }

    Ok(())
}

fn list_servers(details: bool, json_output: bool) -> Result<()> {
    let servers = ServerConfig::list_servers()?;

    if servers.is_empty() {
        if json_output {
            println!("[]");
        } else {
            println!("{}", "No servers configured".yellow());
            println!("\nRun: hessra config init <server> to add a server");
        }
        return Ok(());
    }

    let config = CliConfig::load()?;

    if json_output {
        let mut server_list = Vec::new();
        for server in &servers {
            let mut server_info = json!({
                "hostname": server,
                "is_default": config.default_server.as_deref() == Some(server),
            });

            if details {
                if let Ok(server_config) = ServerConfig::load(server) {
                    let ca_exists = ServerConfig::ca_cert_path(server)
                        .ok()
                        .map(|p| p.exists())
                        .unwrap_or(false);
                    let pubkey_exists = ServerConfig::public_key_path(server)
                        .ok()
                        .map(|p| p.exists())
                        .unwrap_or(false);

                    server_info = json!({
                        "hostname": server,
                        "port": server_config.port,
                        "cert_path": server_config.cert_path,
                        "key_path": server_config.key_path,
                        "ca_cert_exists": ca_exists,
                        "public_key_exists": pubkey_exists,
                        "is_default": config.default_server.as_deref() == Some(server),
                    });
                }
            }

            server_list.push(server_info);
        }
        println!("{}", serde_json::to_string_pretty(&server_list)?);
    } else {
        println!("{}", "Configured servers:".bright_cyan());
        for server in &servers {
            let is_default = config.default_server.as_deref() == Some(server);
            let default_marker = if is_default { " (default)" } else { "" };

            if details {
                if let Ok(server_config) = ServerConfig::load(server) {
                    let ca_exists = ServerConfig::ca_cert_path(server)
                        .ok()
                        .map(|p| p.exists())
                        .unwrap_or(false);
                    let pubkey_exists = ServerConfig::public_key_path(server)
                        .ok()
                        .map(|p| p.exists())
                        .unwrap_or(false);

                    println!(
                        "\n  {} {}{}",
                        "●".green(),
                        server.bright_white(),
                        default_marker.bright_yellow()
                    );
                    println!("    Port: {}", server_config.port);
                    println!(
                        "    CA cert: {}",
                        if ca_exists {
                            "✓".green()
                        } else {
                            "✗".red()
                        }
                    );
                    println!(
                        "    Public key: {}",
                        if pubkey_exists {
                            "✓".green()
                        } else {
                            "✗".red()
                        }
                    );
                    if let Some(cert) = &server_config.cert_path {
                        println!("    mTLS cert: {}", cert.display());
                    }
                    if let Some(key) = &server_config.key_path {
                        println!("    mTLS key: {}", key.display());
                    }
                }
            } else {
                println!(
                    "  {} {}{}",
                    "●".green(),
                    server,
                    default_marker.bright_yellow()
                );
            }
        }

        if !details {
            println!("\nRun with --details to see more information");
        }
    }

    Ok(())
}

fn show_server(server: &str, json_output: bool) -> Result<()> {
    let server_config = ServerConfig::load(server)?;
    let config = CliConfig::load()?;

    let ca_path = ServerConfig::ca_cert_path(server)?;
    let pubkey_path = ServerConfig::public_key_path(server)?;
    let tokens_dir = ServerConfig::tokens_dir(server)?;

    let ca_exists = ca_path.exists();
    let pubkey_exists = pubkey_path.exists();
    let is_default = config.default_server.as_deref() == Some(server);

    let token_count = if tokens_dir.exists() {
        std::fs::read_dir(&tokens_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("token"))
            .count()
    } else {
        0
    };

    if json_output {
        let output = json!({
            "hostname": server_config.hostname,
            "port": server_config.port,
            "cert_path": server_config.cert_path,
            "key_path": server_config.key_path,
            "ca_cert_path": ca_path,
            "ca_cert_exists": ca_exists,
            "public_key_path": pubkey_path,
            "public_key_exists": pubkey_exists,
            "tokens_dir": tokens_dir,
            "token_count": token_count,
            "is_default": is_default,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} {}",
            "Server:".bright_cyan(),
            server_config.hostname.bright_white()
        );
        println!("  Port: {}", server_config.port);
        println!(
            "  Default: {}",
            if is_default {
                "yes".green()
            } else {
                "no".dimmed()
            }
        );
        println!("\n{}", "Files:".bright_cyan());
        println!(
            "  CA cert: {} {}",
            if ca_exists {
                "✓".green()
            } else {
                "✗".red()
            },
            ca_path.display().to_string().dimmed()
        );
        println!(
            "  Public key: {} {}",
            if pubkey_exists {
                "✓".green()
            } else {
                "✗".red()
            },
            pubkey_path.display().to_string().dimmed()
        );

        if let Some(cert) = &server_config.cert_path {
            println!("  mTLS cert: {}", cert.display());
        }
        if let Some(key) = &server_config.key_path {
            println!("  mTLS key: {}", key.display());
        }

        println!("\n{}", "Tokens:".bright_cyan());
        println!("  Directory: {}", tokens_dir.display().to_string().dimmed());
        println!("  Count: {token_count}");

        if !ca_exists || !pubkey_exists {
            println!("\n{}", "Missing files:".yellow());
            println!("  Run: hessra config refresh {server}");
        }
    }

    Ok(())
}

fn switch_server(server: &str, json_output: bool) -> Result<()> {
    if !ServerConfig::exists(server) {
        return Err(error::CliError::Config(format!(
            "Server '{server}' not configured. Run: hessra config init {server}"
        )));
    }

    let mut config = CliConfig::load()?;
    config.default_server = Some(server.to_string());
    config.save()?;

    if json_output {
        let output = json!({
            "success": true,
            "default_server": server,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Switched default server to {}",
            "✓".green(),
            server.bright_white()
        );
    }

    Ok(())
}

async fn refresh_server(server: &str, json_output: bool) -> Result<()> {
    let server_config = ServerConfig::load(server)?;

    let progress = if !json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Refreshing configuration for {server}..."));
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let mut ca_fetched = false;
    let mut pubkey_fetched = false;

    if let Some(pb) = progress.as_ref() {
        pb.set_message(format!("Fetching CA certificate from {server}..."));
    }

    match hessra_sdk::fetch_ca_cert(&server_config.hostname, Some(server_config.port)).await {
        Ok(ca_cert) => {
            let ca_path = ServerConfig::ca_cert_path(server)?;
            if let Some(parent) = ca_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&ca_path, ca_cert)?;
            ca_fetched = true;
        }
        Err(e) => {
            if let Some(pb) = progress.as_ref() {
                pb.finish_and_clear();
            }
            if !json_output {
                println!("{} Failed to fetch CA certificate: {}", "✗".red(), e);
            }
        }
    }

    if ca_fetched {
        if let Some(pb) = progress.as_ref() {
            pb.set_message(format!("Fetching public key from {server}..."));
        }

        let ca_path = ServerConfig::ca_cert_path(server)?;
        let ca_cert = std::fs::read_to_string(&ca_path)?;

        match hessra_sdk::fetch_public_key(
            &server_config.hostname,
            Some(server_config.port),
            &ca_cert,
        )
        .await
        {
            Ok(public_key) => {
                let pubkey_path = ServerConfig::public_key_path(server)?;
                std::fs::write(&pubkey_path, public_key)?;
                pubkey_fetched = true;
            }
            Err(e) => {
                if let Some(pb) = progress.as_ref() {
                    pb.finish_and_clear();
                }
                if !json_output {
                    println!("{} Failed to fetch public key: {}", "✗".red(), e);
                }
            }
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    if json_output {
        let output = json!({
            "success": true,
            "server": server,
            "ca_fetched": ca_fetched,
            "public_key_fetched": pubkey_fetched,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Refreshed configuration for {}",
            "✓".green(),
            server.bright_white()
        );
        if ca_fetched {
            println!("  {} Fetched CA certificate", "✓".green());
        }
        if pubkey_fetched {
            println!("  {} Fetched public key", "✓".green());
        }
    }

    Ok(())
}

fn remove_server(server: &str, force: bool, json_output: bool) -> Result<()> {
    if !ServerConfig::exists(server) {
        if json_output {
            let output = json!({
                "success": false,
                "error": format!("Server '{}' not configured", server),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{} Server '{}' not configured", "!".yellow(), server);
        }
        return Ok(());
    }

    if !force && !json_output {
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt(format!(
                "Remove server '{server}' and all associated data (tokens, keys, etc.)?"
            ))
            .default(false)
            .interact()
            .map_err(|e| error::CliError::Io(std::io::Error::other(e)))?;

        if !confirmed {
            println!("Cancelled");
            return Ok(());
        }
    }

    ServerConfig::delete(server)?;

    let mut config = CliConfig::load()?;
    if config.default_server.as_deref() == Some(server) {
        config.default_server = None;
        config.save()?;
    }

    if json_output {
        let output = json!({
            "success": true,
            "server": server,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} Removed server {}", "✓".green(), server.bright_white());
    }

    Ok(())
}
