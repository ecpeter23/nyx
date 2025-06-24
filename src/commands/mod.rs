pub mod clean;
pub mod index;
pub mod list;
pub mod scan;

use crate::cli::Commands;
use crate::errors::NyxResult;
use crate::patterns::Severity;
use crate::utils::config::Config;
use std::path::Path;

pub fn handle_command(
    command: Commands,
    database_dir: &Path,
    config: &mut Config,
) -> NyxResult<()> {
    match command {
        Commands::Scan {
            path,
            no_index,
            rebuild_index,
            format,
            high_only,
        } => {
            if high_only {
                config.scanner.min_severity = Severity::High
            };

            scan::handle(&path, no_index, rebuild_index, format, database_dir, config)
        }
        Commands::Index { action } => index::handle(action, database_dir, config),
        Commands::List { verbose } => list::handle(verbose, database_dir),
        Commands::Clean { project, all } => clean::handle(project, all, database_dir),
    }
}
