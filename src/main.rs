mod cli;
mod commands;
mod utils;

use crate::utils::Config;
use cli::Cli;
use clap::Parser;
use directories::ProjectDirs;
use std::fs;

use tracing_subscriber::{fmt, EnvFilter, Registry};
use tracing_subscriber::prelude::*;
use tracing_subscriber::fmt::time;

// use tracing_appender::rolling::{RollingFileAppender, Rotation};
// use tracing_appender::non_blocking;

fn init_tracing() {
    // let file_appender = RollingFileAppender::new(Rotation::HOURLY, "logs", "nano-scanner.log");
    // let (file_writer, guard) = non_blocking(file_appender);
    
    let fmt_layer = fmt::layer()
        .pretty()                           
        .with_thread_ids(true)     
        .with_timer(time::UtcTime::rfc_3339());
    
    // let file_layer = fmt::layer()
    //     .with_writer(file_writer)          
    //     .without_time()                     
    //     .json();

    Registry::default()
        .with(EnvFilter::from_default_env()) // obey RUST_LOG
        .with(fmt_layer)         
        .init();                             // install as the global subscriber
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    tracing::debug!("CLI starting up");
    let cli = Cli::parse();

    let proj_dirs = ProjectDirs::from("dev", "ecpeter23", "nano")
        .ok_or("Unable to determine project directories")?;

    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    let database_dir = proj_dirs.data_local_dir();
    fs::create_dir_all(database_dir)?;

    let config = Config::load(config_dir)?;

    commands::handle_command(cli.command, database_dir, &config)?;

    Ok(())
}

