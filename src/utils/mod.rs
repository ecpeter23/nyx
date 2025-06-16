pub mod project;
pub mod config;

// Re-export commonly used functions for convenience
pub use project::{get_project_info};
pub use config::Config;