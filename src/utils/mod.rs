pub mod project;
pub mod config;

// Re-export commonly used functions for convenience
pub use project::{get_project_info, sanitize_project_name};
pub use config::Config;