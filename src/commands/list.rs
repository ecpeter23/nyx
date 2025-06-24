use crate::errors::NyxResult;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use console::style;
use std::fs;

pub fn handle(verbose: bool, database_dir: &std::path::Path) -> NyxResult<()> {
    println!("{}", style("Indexed projects").blue().bold().underlined());

    if !database_dir.exists() {
        println!("  {}", style("∅ No indexed projects found").dim());
        std::process::exit(0);
    }

    for entry in fs::read_dir(database_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sqlite") {
            continue;
        }

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        println!("  {}", style(name).white().bold());

        if verbose {
            let meta = fs::metadata(&path)?;
            let size = ByteSize::b(meta.len());
            let mtime: DateTime<Local> = meta.modified()?.into();
            println!(
                "    {:10} {}",
                style("Path"),
                style(path.display()).underlined()
            );
            println!("    {:10} {}", style("Size"), size);
            println!(
                "    {:10} {}",
                style("Modified"),
                mtime.format("%Y-%m-%d %H:%M:%S")
            );
        }
    }

    std::process::exit(0);
}
