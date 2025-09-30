use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hessra",
    version,
    about = "Hessra CLI for authentication and identity management",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize configuration for a Hessra server (alias for 'config init')
    Init {
        /// Server hostname (e.g., test.hessra.net)
        server: Option<String>,

        /// Server port
        #[arg(short, long, default_value = "443")]
        port: u16,

        /// Path to mTLS client certificate
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Path to mTLS client key
        #[arg(long)]
        key: Option<PathBuf>,

        /// Set as default server
        #[arg(long)]
        set_default: bool,

        /// Skip fetching CA cert and public key
        #[arg(long)]
        skip_fetch: bool,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// Identity token management
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Authorization token operations
    Authorize {
        #[command(subcommand)]
        command: AuthorizeCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Authenticate with the Hessra service and obtain an identity token
    Authenticate {
        /// Server hostname or URL
        #[arg(short, long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server port
        #[arg(short, long, default_value = "443", env = "HESSRA_PORT")]
        port: u16,

        /// Path to client certificate for mTLS
        #[arg(long, env = "HESSRA_CERT")]
        cert: Option<PathBuf>,

        /// Path to client private key for mTLS
        #[arg(long, env = "HESSRA_KEY")]
        key: Option<PathBuf>,

        /// Path to CA certificate
        #[arg(long, env = "HESSRA_CA")]
        ca: Option<PathBuf>,

        /// Name to save the token as (default: "default")
        #[arg(long, default_value = "default")]
        save_as: String,

        /// Time-to-live for the token in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Create a delegated identity token
    Delegate {
        /// The delegated identity (e.g., "uri:urn:test:user:agent1")
        #[arg(short, long)]
        identity: String,

        /// Time-to-live for the delegated token in seconds (default: 3600)
        #[arg(long, default_value = "3600")]
        ttl: u64,

        /// Source token name to delegate from (default: "default")
        #[arg(long, default_value = "default")]
        from_token: String,

        /// Name to save the delegated token as (optional - if not provided, token is only output to stdout)
        #[arg(long)]
        save_as: Option<String>,

        /// Output only the token without any formatting (useful for piping)
        #[arg(long)]
        token_only: bool,

        /// Server hostname or URL (uses config default if not specified)
        #[arg(long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server port (default: 443)
        #[arg(long, default_value = "443", env = "HESSRA_PORT")]
        port: u16,

        /// Path to CA certificate (uses config default if not specified)
        #[arg(long, env = "HESSRA_CA")]
        ca: Option<PathBuf>,

        /// Public key PEM content to use for delegation (bypasses server communication)
        #[arg(long, env = "HESSRA_PUBLIC_KEY", conflicts_with = "public_key_file")]
        public_key: Option<String>,

        /// Path to public key file to use for delegation (bypasses server communication)
        #[arg(long, conflicts_with = "public_key")]
        public_key_file: Option<PathBuf>,
    },

    /// Verify an identity token
    Verify {
        /// Name of the saved token to verify
        #[arg(long, conflicts_with = "token_file")]
        token_name: Option<String>,

        /// Path to token file to verify
        #[arg(long, conflicts_with = "token_name")]
        token_file: Option<PathBuf>,

        /// The identity to verify against
        #[arg(short, long)]
        identity: Option<String>,

        /// Server to use for verification (optional, uses local verification if public key is available)
        #[arg(long)]
        server: Option<String>,
    },

    /// Refresh an identity token
    Refresh {
        /// Name of the saved token to refresh
        #[arg(long, default_value = "default")]
        token_name: String,

        /// Save refreshed token with a different name
        #[arg(long)]
        save_as: Option<String>,

        /// Server configuration (required if not in config)
        #[arg(long)]
        server: Option<String>,

        #[arg(long)]
        port: Option<u16>,
    },

    /// List all saved tokens
    List {
        /// Show detailed information for each token
        #[arg(long)]
        details: bool,
    },

    /// Inspect a token to see its contents
    Inspect {
        /// Name of saved token to inspect
        #[arg(long, conflicts_with = "token_file")]
        token_name: Option<String>,

        /// Path to token file to inspect
        #[arg(long, conflicts_with = "token_name")]
        token_file: Option<PathBuf>,

        /// Show verbose output including raw Biscuit content
        #[arg(short, long)]
        verbose: bool,

        /// Server hostname for public key (uses config default if not specified)
        #[arg(long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server public key PEM content
        #[arg(long, env = "HESSRA_PUBLIC_KEY", conflicts_with = "public_key_file")]
        public_key: Option<String>,

        /// Path to public key file
        #[arg(long, conflicts_with = "public_key")]
        public_key_file: Option<PathBuf>,
    },

    /// Remove expired tokens from storage
    Prune {
        /// Perform a dry run without actually deleting tokens
        #[arg(long)]
        dry_run: bool,

        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,

        /// Server hostname for public key (uses config default if not specified)
        #[arg(long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server public key PEM content
        #[arg(long, env = "HESSRA_PUBLIC_KEY", conflicts_with = "public_key_file")]
        public_key: Option<String>,

        /// Path to public key file
        #[arg(long, conflicts_with = "public_key")]
        public_key_file: Option<PathBuf>,
    },

    /// Delete a saved token
    Delete {
        /// Name of the token to delete
        token_name: String,
    },
}

#[derive(Subcommand)]
pub enum AuthorizeCommands {
    /// Request an authorization token for a resource
    Request {
        /// Resource to request access for
        #[arg(short, long)]
        resource: String,

        /// Operation to perform (e.g., read, write, delete)
        #[arg(short, long)]
        operation: String,

        /// Name of saved identity token to use for authentication
        #[arg(short = 'i', long)]
        identity_token: Option<String>,

        /// Path to identity token file
        #[arg(short = 't', long, conflicts_with = "identity_token")]
        token_file: Option<PathBuf>,

        /// Output only the token without any formatting (useful for piping)
        #[arg(long)]
        token_only: bool,

        /// Path to client certificate for mTLS (used if no identity token)
        #[arg(long, env = "HESSRA_CERT")]
        cert: Option<PathBuf>,

        /// Path to client private key for mTLS (used if no identity token)
        #[arg(long, env = "HESSRA_KEY")]
        key: Option<PathBuf>,

        /// Path to CA certificate
        #[arg(long, env = "HESSRA_CA")]
        ca: Option<PathBuf>,

        /// Server hostname or URL
        #[arg(short, long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server port
        #[arg(short = 'p', long, default_value = "443", env = "HESSRA_PORT")]
        port: u16,

        /// Server public key (base64 encoded) - for offline verification
        #[arg(long, env = "HESSRA_PUBLIC_KEY")]
        public_key: Option<String>,
    },

    /// Verify an authorization token
    Verify {
        /// The authorization token to verify (reads from stdin if not provided)
        #[arg(long)]
        token: Option<String>,

        /// Subject identifier to verify against
        #[arg(short, long)]
        subject: String,

        /// Resource identifier to verify against
        #[arg(short, long)]
        resource: String,

        /// Operation to verify
        #[arg(short, long)]
        operation: String,

        /// Server hostname or URL (uses config default if not specified)
        #[arg(long, env = "HESSRA_SERVER")]
        server: Option<String>,

        /// Server port
        #[arg(long, default_value = "443", env = "HESSRA_PORT")]
        port: u16,

        /// Server public key (base64 encoded) - for offline verification
        #[arg(long, env = "HESSRA_PUBLIC_KEY")]
        public_key: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Initialize configuration for a Hessra server
    Init {
        /// Server hostname (e.g., test.hessra.net)
        server: Option<String>,

        /// Server port
        #[arg(short, long, default_value = "443")]
        port: u16,

        /// Path to mTLS client certificate
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Path to mTLS client key
        #[arg(long)]
        key: Option<PathBuf>,

        /// Set as default server
        #[arg(long)]
        set_default: bool,

        /// Skip fetching CA cert and public key
        #[arg(long)]
        skip_fetch: bool,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// List all configured servers
    List {
        /// Show detailed information for each server
        #[arg(long)]
        details: bool,
    },

    /// Show configuration for a specific server
    Show {
        /// Server hostname
        server: String,
    },

    /// Switch default server
    Switch {
        /// Server hostname to set as default
        server: String,
    },

    /// Refresh CA cert and public key from server
    Refresh {
        /// Server hostname
        server: String,
    },

    /// Remove a server configuration
    Remove {
        /// Server hostname
        server: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Set a configuration value
    Set {
        /// Configuration key to set
        key: String,

        /// Value to set
        value: String,
    },

    /// Get a configuration value
    Get {
        /// Configuration key to get (omit to show all)
        key: Option<String>,
    },

    /// Show the configuration file path
    Path,
}
