use crate::error::{CliError, Result};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Global CLI configuration
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CliConfig {
    /// Default server to use when not specified
    pub default_server: Option<String>,
    /// Legacy fields (deprecated, kept for backward compatibility)
    pub default_port: Option<u16>,
    pub default_cert_path: Option<PathBuf>,
    pub default_key_path: Option<PathBuf>,
    pub default_ca_path: Option<PathBuf>,
    pub token_storage_dir: Option<PathBuf>,
}

/// Server-specific configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// Server hostname (e.g., "test.hessra.net")
    pub hostname: String,
    /// Server port (default: 443)
    pub port: u16,
    /// Optional path to mTLS client certificate
    pub cert_path: Option<PathBuf>,
    /// Optional path to mTLS client key
    pub key_path: Option<PathBuf>,
}

impl CliConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_file_path()?;

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| CliError::Config(format!("Failed to parse config: {e}")))?;

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_file_path()?;

        // Create parent directories if they don't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| CliError::Config(format!("Failed to serialize config: {e}")))?;

        fs::write(&config_path, content)?;
        Ok(())
    }

    pub fn config_dir() -> Result<PathBuf> {
        // Use ~/.hessra/ as the standard location
        let home = BaseDirs::new()
            .ok_or_else(|| CliError::Config("Could not determine home directory".to_string()))?
            .home_dir()
            .to_path_buf();
        Ok(home.join(".hessra"))
    }

    pub fn config_file_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    pub fn token_dir(&self) -> Result<PathBuf> {
        if let Some(ref dir) = self.token_storage_dir {
            Ok(dir.clone())
        } else {
            Ok(Self::config_dir()?.join("tokens"))
        }
    }

    pub fn ensure_token_dir(&self) -> Result<()> {
        let token_dir = self.token_dir()?;
        if !token_dir.exists() {
            fs::create_dir_all(&token_dir)?;
        }
        Ok(())
    }

    /// Get the servers directory path
    pub fn servers_dir() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("servers"))
    }

    /// Get the directory path for a specific server
    pub fn server_dir(server: &str) -> Result<PathBuf> {
        Ok(Self::servers_dir()?.join(server))
    }

    /// Resolve server from optional parameter or config default
    pub fn resolve_server(&self, server_opt: Option<String>) -> Result<String> {
        if let Some(server) = server_opt {
            return Ok(server);
        }

        if let Some(ref default) = self.default_server {
            return Ok(default.clone());
        }

        // No server parameter and no default - check if any servers configured
        let servers = ServerConfig::list_servers().unwrap_or_default();
        if servers.is_empty() {
            Err(CliError::Config(
                "No servers configured.\n\nRun: hessra init <server> --cert <cert> --key <key> --set-default\nExample: hessra init infra.hessra.net --cert ./client.crt --key ./client.key --set-default".to_string(),
            ))
        } else {
            Err(CliError::Config(format!(
                "No default server set. Available servers: {}\n\nRun: hessra config switch <server>\nOr specify server with: --server <server>",
                servers.join(", ")
            )))
        }
    }
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(hostname: String, port: u16) -> Self {
        Self {
            hostname,
            port,
            cert_path: None,
            key_path: None,
        }
    }

    /// Load server configuration from file
    pub fn load(server: &str) -> Result<Self> {
        let config_path = Self::config_file_path(server)?;

        if !config_path.exists() {
            return Err(CliError::Config(format!(
                "Server '{server}' not configured. Run: hessra init {server}"
            )));
        }

        let content = fs::read_to_string(&config_path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| CliError::Config(format!("Failed to parse server config: {e}")))?;

        Ok(config)
    }

    /// Save server configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_file_path(&self.hostname)?;

        // Create parent directories if they don't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| CliError::Config(format!("Failed to serialize server config: {e}")))?;

        fs::write(&config_path, content)?;
        Ok(())
    }

    /// Get the path to server config file
    pub fn config_file_path(server: &str) -> Result<PathBuf> {
        Ok(CliConfig::server_dir(server)?.join("server.toml"))
    }

    /// Get the path to server's CA certificate
    pub fn ca_cert_path(server: &str) -> Result<PathBuf> {
        Ok(CliConfig::server_dir(server)?.join("ca.crt"))
    }

    /// Get the path to server's public key
    pub fn public_key_path(server: &str) -> Result<PathBuf> {
        Ok(CliConfig::server_dir(server)?.join("public_key.pem"))
    }

    /// Get the path to server's tokens directory
    pub fn tokens_dir(server: &str) -> Result<PathBuf> {
        Ok(CliConfig::server_dir(server)?.join("tokens"))
    }

    /// Check if a server is configured
    pub fn exists(server: &str) -> bool {
        Self::config_file_path(server)
            .ok()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// List all configured servers
    pub fn list_servers() -> Result<Vec<String>> {
        let servers_dir = CliConfig::servers_dir()?;

        if !servers_dir.exists() {
            return Ok(vec![]);
        }

        let mut servers = Vec::new();
        for entry in fs::read_dir(servers_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Check if server.toml exists in this directory
                    if Self::config_file_path(name)
                        .ok()
                        .map(|p| p.exists())
                        .unwrap_or(false)
                    {
                        servers.push(name.to_string());
                    }
                }
            }
        }

        servers.sort();
        Ok(servers)
    }

    /// Delete a server's configuration and all associated data
    pub fn delete(server: &str) -> Result<()> {
        let server_dir = CliConfig::server_dir(server)?;

        if server_dir.exists() {
            fs::remove_dir_all(&server_dir)?;
        }

        Ok(())
    }
}

pub struct PublicKeyStorage;

impl PublicKeyStorage {
    /// Save public key for a server (new server-aware location)
    pub fn save_public_key(server: &str, public_key: &str, _config: &CliConfig) -> Result<PathBuf> {
        // Use new server-based structure
        let key_path = ServerConfig::public_key_path(server)?;

        // Create parent directories if they don't exist
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&key_path, public_key)?;
        Ok(key_path)
    }

    /// Load public key for a server (tries new location first, falls back to legacy)
    pub fn load_public_key(server: &str, config: &CliConfig) -> Result<Option<String>> {
        // Try new server-based location first
        let new_path = ServerConfig::public_key_path(server)?;
        if new_path.exists() {
            return Ok(Some(fs::read_to_string(new_path)?));
        }

        // Fall back to legacy location for backward compatibility
        let sanitized_server = server
            .replace("https://", "")
            .replace("http://", "")
            .replace(['/', ':'], "_");

        let legacy_path = Self::keys_dir(config)?.join(format!("{sanitized_server}.pub"));
        if legacy_path.exists() {
            Ok(Some(fs::read_to_string(legacy_path)?))
        } else {
            Ok(None)
        }
    }

    /// Get legacy keys directory (for backward compatibility)
    pub fn keys_dir(_config: &CliConfig) -> Result<PathBuf> {
        Ok(CliConfig::config_dir()?.join("public_keys"))
    }
}

pub struct TokenStorage;

impl TokenStorage {
    /// Save token for a specific server (new server-aware location)
    #[allow(dead_code)]
    pub fn save_token_for_server(
        server: &str,
        name: &str,
        token: &str,
        _config: &CliConfig,
    ) -> Result<PathBuf> {
        let tokens_dir = ServerConfig::tokens_dir(server)?;
        fs::create_dir_all(&tokens_dir)?;

        let token_path = tokens_dir.join(format!("{name}.token"));
        fs::write(&token_path, token)?;
        Ok(token_path)
    }

    /// Load token for a specific server
    #[allow(dead_code)]
    pub fn load_token_for_server(server: &str, name: &str, _config: &CliConfig) -> Result<String> {
        let token_path = ServerConfig::tokens_dir(server)?.join(format!("{name}.token"));
        if !token_path.exists() {
            return Err(CliError::FileNotFound(format!(
                "Token '{name}' not found for server '{server}'"
            )));
        }
        Ok(fs::read_to_string(token_path)?)
    }

    /// Delete token for a specific server
    #[allow(dead_code)]
    pub fn delete_token_for_server(server: &str, name: &str, _config: &CliConfig) -> Result<()> {
        let token_path = ServerConfig::tokens_dir(server)?.join(format!("{name}.token"));
        if token_path.exists() {
            fs::remove_file(token_path)?;
        }
        Ok(())
    }

    /// List tokens for a specific server
    #[allow(dead_code)]
    pub fn list_tokens_for_server(server: &str, _config: &CliConfig) -> Result<Vec<String>> {
        let token_dir = ServerConfig::tokens_dir(server)?;
        if !token_dir.exists() {
            return Ok(vec![]);
        }

        let mut tokens = Vec::new();
        for entry in fs::read_dir(token_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("token") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    tokens.push(stem.to_string());
                }
            }
        }
        Ok(tokens)
    }

    /// Check if token exists for a specific server
    #[allow(dead_code)]
    pub fn token_exists_for_server(server: &str, name: &str) -> bool {
        ServerConfig::tokens_dir(server)
            .ok()
            .map(|dir| dir.join(format!("{name}.token")).exists())
            .unwrap_or(false)
    }

    // Legacy methods (for backward compatibility)
    pub fn save_token(name: &str, token: &str, config: &CliConfig) -> Result<PathBuf> {
        config.ensure_token_dir()?;
        let token_path = config.token_dir()?.join(format!("{name}.token"));
        fs::write(&token_path, token)?;
        Ok(token_path)
    }

    pub fn load_token(name: &str, config: &CliConfig) -> Result<String> {
        let token_path = config.token_dir()?.join(format!("{name}.token"));
        if !token_path.exists() {
            return Err(CliError::FileNotFound(format!("Token '{name}' not found")));
        }
        Ok(fs::read_to_string(token_path)?)
    }

    pub fn delete_token(name: &str, config: &CliConfig) -> Result<()> {
        let token_path = config.token_dir()?.join(format!("{name}.token"));
        if token_path.exists() {
            fs::remove_file(token_path)?;
        }
        Ok(())
    }

    pub fn list_tokens(config: &CliConfig) -> Result<Vec<String>> {
        let token_dir = config.token_dir()?;
        if !token_dir.exists() {
            return Ok(vec![]);
        }

        let mut tokens = Vec::new();
        for entry in fs::read_dir(token_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("token") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    tokens.push(stem.to_string());
                }
            }
        }
        Ok(tokens)
    }

    pub fn token_exists(name: &str, config: &CliConfig) -> bool {
        config
            .token_dir()
            .ok()
            .map(|dir| dir.join(format!("{name}.token")).exists())
            .unwrap_or(false)
    }
}
