use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nyx")]
#[command(about = "A fast vulnerability scanner with project indexing")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan project for vulnerabilities
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Skip using/building index, scan directly
        #[arg(long)]
        no_index: bool,

        /// Force rebuild index before scanning
        #[arg(long)]
        rebuild_index: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value = "")]
        format: String,

        /// Show only high severity issues
        #[arg(long)]
        high_only: bool,
    },

    /// Manage project indexes
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },

    /// List all indexed projects
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove project from index
    Clean {
        /// Project name or path to clean
        project: Option<String>,

        /// Clean all projects
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum IndexAction {
    /// Build or update index for current project
    Build {
        /// Path to index (defaults to current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Force full rebuild
        #[arg(short, long)]
        force: bool,
    },

    /// Show index status and statistics
    Status {
        /// Project path to check
        #[arg(default_value = ".")]
        path: String,
    },
}
