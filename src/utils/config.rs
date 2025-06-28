use crate::errors::NyxResult;
use crate::patterns::Severity;
use console::style;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use toml;

static DEFAULT_CONFIG_TOML: &str = include_str!("../../default-nyx.conf");

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisMode {
    #[default]
    Full,
    Ast,
    Taint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ScannerConfig {
    /// The analysis mode to use.
    pub mode: AnalysisMode,

    /// The minimum severity level to output
    pub min_severity: Severity,

    /// The maximum file size to scan, in megabytes.
    pub max_file_size_mb: Option<u64>,

    /// File extensions to exclude from scanning.
    pub excluded_extensions: Vec<String>,

    /// Directories to exclude from scanning.
    pub excluded_directories: Vec<String>,

    /// Excluded files
    pub excluded_files: Vec<String>,

    /// Whether to respect the global ignore file or not.
    pub read_global_ignore: bool,

    /// Whether to respect VCS ignore files (`.gitignore`, ..) or not.
    pub read_vcsignore: bool,

    /// Whether to require a `.git` directory to respect gitignore files.
    pub require_git_to_read_vcsignore: bool,

    /// Whether to limit the search to starting file system or not.
    pub one_file_system: bool,

    /// Whether to follow symlinks or not.
    pub follow_symlinks: bool,

    /// Whether to scan hidden files or not.
    pub scan_hidden_files: bool,
}
impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            mode: AnalysisMode::Full,
            min_severity: Severity::Low,
            max_file_size_mb: None,
            excluded_extensions: vec![
                "jpg", "png", "gif", "mp4", "avi", "mkv", "zip", "tar", "gz", "exe", "dll", "so",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            excluded_directories: vec![
                "node_modules",
                ".git",
                "target",
                ".vscode",
                ".idea",
                "build",
                "dist",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            excluded_files: vec![].into_iter().map(str::to_owned).collect(),
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
    /// Custom path for database
    pub path: String,

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
            path: String::from(""),
            auto_cleanup_days: 30,
            max_db_size_mb: 1024,
            vacuum_on_startup: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct OutputConfig {
    /// The default output format. TODO: IMPLEMENT others
    pub default_format: String,

    /// Whether to print anything to the console or not. TODO: IMPLEMENT
    pub quiet: bool,

    /// The maximum number of results to show.
    pub max_results: Option<u32>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            default_format: "console".into(),
            quiet: false,
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
    pub prune: bool,

    /// The maximum number of worker threads to use., or `None` to auto-detect.
    pub worker_threads: Option<usize>,

    /// The maximum number of entries to index in a single chunk.
    pub batch_size: usize,

    /// capacity = threads × this
    pub channel_multiplier: usize,

    /// The stack size for Rayon threads, in bytes.
    pub rayon_thread_stack_size: usize,

    /// Timeout on individual files // TODO: IMPLEMENT
    pub scan_timeout_secs: Option<u64>,

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
            batch_size: 100usize,
            channel_multiplier: 4usize,
            rayon_thread_stack_size: 8 * 1024 * 1024, // 2 MiB
            scan_timeout_secs: None,
            memory_limit_mb: 512,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub database: DatabaseConfig,
    pub output: OutputConfig,
    pub performance: PerformanceConfig,
}

impl Config {
    pub fn load(config_dir: &Path) -> NyxResult<Self> {
        let mut config = Config::default();

        let default_config_path = config_dir.join("nyx.conf");
        if !default_config_path.exists() {
            create_example_config(config_dir)?;
        }

        let user_config_path = config_dir.join("nyx.local");
        if user_config_path.exists() {
            let user_config_content = fs::read_to_string(&user_config_path)?;
            let user_config: Config = toml::from_str(&user_config_content)?;

            config = merge_configs(config, user_config);

            println!(
                "{}: Loaded user config from: {}\n",
                style("note").green().bold(),
                style(user_config_path.display())
                    .underlined()
                    .white()
                    .bold()
            );
        } else {
            println!(
                "{}: Using {} configuration.\n      Create file in '{}'to customize.\n",
                style("note").green().bold(),
                style("default").bold(),
                style(user_config_path.display())
                    .underlined()
                    .white()
                    .bold()
            );
        }

        Ok(config)
    }
}

fn create_example_config(config_dir: &Path) -> NyxResult<()> {
    let example_path = config_dir.join("nyx.conf");
    if !example_path.exists() {
        fs::write(&example_path, DEFAULT_CONFIG_TOML)?;
        tracing::debug!("Example config created at: {}", example_path.display());
    }
    Ok(())
}

/// Merge user config into default config, preserving defaults where the user didn't
/// supply new exclusions and overriding everything else.
fn merge_configs(mut default: Config, user: Config) -> Config {
    // --- ScannerConfig ---
    default.scanner.mode = user.scanner.mode;
    default.scanner.min_severity = user.scanner.min_severity;
    default.scanner.max_file_size_mb = user.scanner.max_file_size_mb;
    default.scanner.read_global_ignore = user.scanner.read_global_ignore;
    default.scanner.read_vcsignore = user.scanner.read_vcsignore;
    default.scanner.require_git_to_read_vcsignore = user.scanner.require_git_to_read_vcsignore;
    default.scanner.one_file_system = user.scanner.one_file_system;
    default.scanner.follow_symlinks = user.scanner.follow_symlinks;
    default.scanner.scan_hidden_files = user.scanner.scan_hidden_files;

    // Merge exclusion lists (default ⊔ user), then sort & dedupe
    default
        .scanner
        .excluded_extensions
        .extend(user.scanner.excluded_extensions);
    default
        .scanner
        .excluded_directories
        .extend(user.scanner.excluded_directories);
    default.scanner.excluded_extensions.sort_unstable();
    default.scanner.excluded_extensions.dedup();
    default.scanner.excluded_directories.sort_unstable();
    default.scanner.excluded_directories.dedup();

    // --- DatabaseConfig ---
    default.database.path = user.database.path;
    default.database.auto_cleanup_days = user.database.auto_cleanup_days;
    default.database.max_db_size_mb = user.database.max_db_size_mb;
    default.database.vacuum_on_startup = user.database.vacuum_on_startup;

    // --- OutputConfig ---
    default.output.default_format = user.output.default_format;
    default.output.quiet = user.output.quiet;
    default.output.max_results = user.output.max_results;

    // --- PerformanceConfig ---
    default.performance.max_depth = user.performance.max_depth;
    default.performance.min_depth = user.performance.min_depth;
    default.performance.prune = user.performance.prune;
    default.performance.worker_threads = user.performance.worker_threads;
    default.performance.batch_size = user.performance.batch_size;
    default.performance.channel_multiplier = user.performance.channel_multiplier;
    default.performance.rayon_thread_stack_size = user.performance.rayon_thread_stack_size;
    default.performance.scan_timeout_secs = user.performance.scan_timeout_secs;
    default.performance.memory_limit_mb = user.performance.memory_limit_mb;

    default
}

#[test]
fn merge_configs_dedupes_and_keeps_order() {
    let mut default_cfg = Config::default();
    default_cfg.scanner.excluded_extensions = vec!["rs".into(), "toml".into()];

    let mut user_cfg = Config::default();
    user_cfg.scanner.excluded_extensions = vec!["jpg".into(), "rs".into()];

    let merged = merge_configs(default_cfg, user_cfg);

    assert_eq!(
        merged.scanner.excluded_extensions,
        vec!["jpg", "rs", "toml"]
    );
}

#[test]
fn load_creates_example_and_reads_user_overrides() {
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path();

    let user_toml = r#"
        [scanner]
        one_file_system = true
        excluded_extensions = ["foo"]

        [output]
        quiet = true
    "#;
    fs::write(cfg_path.join("nyx.local"), user_toml).unwrap();

    let cfg = Config::load(cfg_path).expect("Config::load should succeed");

    assert!(cfg_path.join("nyx.conf").is_file());

    assert!(cfg.scanner.one_file_system);
    assert!(cfg.output.quiet);
    assert!(cfg.scanner.excluded_extensions.contains(&"foo".to_string()));

    assert!(!cfg.scanner.follow_symlinks);
}
