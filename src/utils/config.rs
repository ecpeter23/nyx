use serde::{Deserialize, Serialize};
use std::path::{Path};
use std::fs;
use toml;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ScannerConfig {
    /// The maximum file size to scan, in megabytes. TODO: IMPLEMENT
    pub max_file_size_mb: u64,
    
    /// File extensions to exclude from scanning. TODO: IMPLEMENT
    pub excluded_extensions: Vec<String>,
    
    /// Directories to exclude from scanning. TODO: IMPLEMENT
    pub excluded_directories: Vec<String>,

    /// Whether to respect the global ignore file or not. TODO: IMPLEMENT
    pub read_global_ignore: bool,

    /// Whether to respect VCS ignore files (`.gitignore`, ..) or not. TODO: IMPLEMENT
    pub read_vcsignore: bool,

    /// Whether to require a `.git` directory to respect gitignore files. TODO: IMPLEMENT
    pub require_git_to_read_vcsignore: bool,

    /// Whether to limit the search to starting file system or not. TODO: IMPLEMENT
    pub one_file_system: bool,
    
    /// Whether to follow symlinks or not. TODO: IMPLEMENT
    pub follow_symlinks: bool,
    
    /// Whether to scan hidden files or not. TODO: IMPLEMENT
    pub scan_hidden_files: bool,
}
impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 100,
            excluded_extensions: vec![
                "jpg", "png", "gif", "mp4", "avi", "mkv",
                "zip", "tar", "gz", "exe", "dll", "so",
            ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            excluded_directories: vec![
                "node_modules", ".git", "target", ".vscode", ".idea", "build", "dist",
            ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            read_global_ignore: false,
            read_vcsignore: true,
            require_git_to_read_vcsignore: true,
            one_file_system: false,
            follow_symlinks: false,
            scan_hidden_files: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct DatabaseConfig {
    /// The number of days to keep database files for. TODO: IMPLEMENT
    pub auto_cleanup_days: u32,
    
    /// The maximum size of the database, in megabytes. TODO: IMPLEMENT
    pub max_db_size_mb: u64,
    
    /// Whether to run a VACUUM on startup or not. TODO: IMPLEMENT
    pub vacuum_on_startup: bool,
}
impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            auto_cleanup_days: 30,
            max_db_size_mb: 1024,
            vacuum_on_startup: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct OutputConfig {
    /// The default output format. TODO: IMPLEMENT
    pub default_format: String,
    
    /// Whether to show progress or not. TODO: IMPLEMENT
    pub show_progress: bool,
    
    /// Whether to colorize output or not. TODO: IMPLEMENT
    pub color_output: bool,
    
    /// The maximum number of results to show. TODO: IMPLEMENT
    pub max_results: Option<u32>, 
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            default_format: "table".into(),
            show_progress: true,
            color_output: true,
            max_results: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct PerformanceConfig {
    /// The maximum search depth, or `None` if no maximum search depth should be set.
    ///
    /// A depth of `1` includes all files under the current directory, a depth of `2` also includes
    /// all files under subdirectories of the current directory, etc. 
    pub max_depth: Option<usize>, // TODO: IMPLEMENT

    /// The minimum depth for reported entries, or `None`.
    pub min_depth: Option<usize>, // TODO: IMPLEMENT

    /// Whether to stop traversing into matching directories.
    pub prune: bool, // TODO: IMPLEMENT

    /// The maximum number of worker threads to use., or `None` to auto-detect.
    pub worker_threads: Option<u32>, // TODO: IMPLEMENT
    
    /// The maximum number of entries to index in a single chunk.
    pub index_chunk_size: u32, // TODO: IMPLEMENT
    
    /// The maximum amount of memory to use, in megabytes.
    pub memory_limit_mb: u64, // TODO: IMPLEMENT
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_depth: None,
            min_depth: None,
            prune: false,
            worker_threads: None,
            index_chunk_size: 1_000,
            memory_limit_mb: 512,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub database: DatabaseConfig,
    pub output: OutputConfig,
    pub performance: PerformanceConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scanner: ScannerConfig::default(),
            database: DatabaseConfig::default(),
            output: OutputConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Config {
    pub fn load(
        config_dir: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Config::default();

        let default_config_path = config_dir.join("nano.conf");
        if !default_config_path.exists() {
            create_example_config(config_dir)?;
        }

        let user_config_path = config_dir.join("nano.local");
        if user_config_path.exists() {
            let user_config_content = fs::read_to_string(&user_config_path)?;
            let user_config: Config = toml::from_str(&user_config_content)?;

            config = merge_configs(config, user_config);

            println!("Loaded user config from: {}", user_config_path.display());
        } else {
            println!("Using default configuration. Create {} to customize.", user_config_path.display());
        }

        Ok(config)
    }
}

fn create_example_config(
    config_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let example_path = config_dir.join("nano.conf");

    let default_config = Config::default();
    let toml_content = toml::to_string_pretty(&default_config)?;

    // Add comments to make it user-friendly
    let commented_content = format!(
            "# Nano Vulnerability Scanner Configuration\n\
             # YOU SHOULD NOT MODIFY THIS FILE.\n\
             # Create/modify 'nano.local' to set configs\n\
             # Only include the sections you want to override\n\n{}",
        toml_content
    );

    fs::write(&example_path, commented_content)?;
    println!("Example config created at: {}", example_path.display());

    Ok(())
}

/// Merge user config into default config, preserving defaults where the user didn't
/// supply new exclusions and overriding everything else.
fn merge_configs(mut default: Config, user: Config) -> Config {
    // --- ScannerConfig ---
    default.scanner.max_file_size_mb               = user.scanner.max_file_size_mb;
    default.scanner.read_global_ignore             = user.scanner.read_global_ignore;
    default.scanner.read_vcsignore                 = user.scanner.read_vcsignore;
    default.scanner.require_git_to_read_vcsignore  = user.scanner.require_git_to_read_vcsignore;
    default.scanner.one_file_system                = user.scanner.one_file_system;
    default.scanner.follow_symlinks                = user.scanner.follow_symlinks;
    default.scanner.scan_hidden_files              = user.scanner.scan_hidden_files;

    // Merge exclusion lists (default ⊔ user), then sort & dedupe
    default.scanner.excluded_extensions.extend(user.scanner.excluded_extensions);
    default.scanner.excluded_directories.extend(user.scanner.excluded_directories);
    default.scanner.excluded_extensions.sort_unstable();
    default.scanner.excluded_extensions.dedup();
    default.scanner.excluded_directories.sort_unstable();
    default.scanner.excluded_directories.dedup();

    // --- DatabaseConfig ---
    default.database.auto_cleanup_days  = user.database.auto_cleanup_days;
    default.database.max_db_size_mb     = user.database.max_db_size_mb;
    default.database.vacuum_on_startup  = user.database.vacuum_on_startup;

    // --- OutputConfig ---
    default.output.default_format  = user.output.default_format;
    default.output.show_progress   = user.output.show_progress;
    default.output.color_output    = user.output.color_output;
    default.output.max_results     = user.output.max_results;

    // --- PerformanceConfig ---
    default.performance.max_depth        = user.performance.max_depth;
    default.performance.min_depth        = user.performance.min_depth;
    default.performance.prune            = user.performance.prune;
    default.performance.worker_threads   = user.performance.worker_threads;
    default.performance.index_chunk_size = user.performance.index_chunk_size;
    default.performance.memory_limit_mb  = user.performance.memory_limit_mb;

    default
}