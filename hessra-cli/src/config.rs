use crate::error::{CliError, Result};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CliConfig {
    pub default_server: Option<String>,
    pub default_port: Option<u16>,
    pub default_cert_path: Option<PathBuf>,
    pub default_key_path: Option<PathBuf>,
    pub default_ca_path: Option<PathBuf>,
    pub token_storage_dir: Option<PathBuf>,
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
}

pub struct PublicKeyStorage;

impl PublicKeyStorage {
    pub fn save_public_key(server: &str, public_key: &str, config: &CliConfig) -> Result<PathBuf> {
        let keys_dir = Self::keys_dir(config)?;
        fs::create_dir_all(&keys_dir)?;

        // Sanitize server name for filesystem
        let sanitized_server = server
            .replace("https://", "")
            .replace("http://", "")
            .replace(['/', ':'], "_");

        let key_path = keys_dir.join(format!("{sanitized_server}.pub"));
        fs::write(&key_path, public_key)?;
        Ok(key_path)
    }

    pub fn load_public_key(server: &str, config: &CliConfig) -> Result<Option<String>> {
        let sanitized_server = server
            .replace("https://", "")
            .replace("http://", "")
            .replace(['/', ':'], "_");

        let key_path = Self::keys_dir(config)?.join(format!("{sanitized_server}.pub"));
        if key_path.exists() {
            Ok(Some(fs::read_to_string(key_path)?))
        } else {
            Ok(None)
        }
    }

    pub fn keys_dir(_config: &CliConfig) -> Result<PathBuf> {
        Ok(CliConfig::config_dir()?.join("public_keys"))
    }
}

pub struct TokenStorage;

impl TokenStorage {
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
}
