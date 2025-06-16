use std::{env, fs};
use crate::utils::get_project_info;

pub fn handle(
    project: Option<String>,
    all: bool,
    config_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if all {
        println!("Cleaning all indexes...");
        if config_dir.exists() {
            fs::remove_dir_all(config_dir)?;
            fs::create_dir_all(config_dir)?;
        }
        println!("All indexes cleaned.");
    } else if let Some(proj_name) = project {
        let db_path = config_dir.join(format!("{}.sqlite", proj_name));
        if db_path.exists() {
            fs::remove_file(&db_path)?;
            println!("Cleaned index for: {}", proj_name);
        } else {
            println!("No index found for: {}", proj_name);
        }
    } else {
        let current_dir = env::current_dir()?;
        let (project_name, db_path) = get_project_info(&current_dir, config_dir)?;

        if db_path.exists() {
            fs::remove_file(&db_path)?;
            println!("Cleaned index for: {}", project_name);
        } else {
            println!("No index found for current project: {}", project_name);
        }
    }

    Ok(())
}