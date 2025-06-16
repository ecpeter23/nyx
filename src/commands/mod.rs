pub mod scan;
pub mod index;
pub mod list;
pub mod clean;

use crate::cli::Commands;
use std::path::Path;
use crate::utils::config::Config;

pub fn handle_command(
    command: Commands,
    database_dir: &Path,
    config: &Config
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Scan { path, no_index, rebuild_index, format, high_only } => {
            scan::handle(&path, no_index, rebuild_index, format, high_only, database_dir, config)
        }
        Commands::Index { action } => {
            index::handle(action, database_dir)
        }
        Commands::List { verbose } => {
            list::handle(verbose, database_dir)
        }
        Commands::Clean { project, all } => {
            clean::handle(project, all, database_dir)
        }
    }
}