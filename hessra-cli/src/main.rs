mod cli;
mod commands;
mod config;
mod error;

use clap::Parser;
use cli::{Cli, Commands, ConfigCommands};
use colored::Colorize;
use config::CliConfig;
use error::Result;
use serde_json::json;

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
        ConfigCommands::Init { force } => {
            let config_path = CliConfig::config_file_path()?;

            if config_path.exists() && !force {
                if json_output {
                    let output = json!({
                        "success": false,
                        "error": "Configuration file already exists. Use --force to overwrite.",
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Configuration file already exists at: {}",
                        "!".yellow(),
                        config_path.display()
                    );
                    println!("Use --force to overwrite.");
                }
                return Ok(());
            }

            let config = CliConfig::default();
            config.save()?;

            if json_output {
                let output = json!({
                    "success": true,
                    "path": config_path,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Configuration initialized at: {}",
                    "✓".green(),
                    config_path.display()
                );
            }
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
