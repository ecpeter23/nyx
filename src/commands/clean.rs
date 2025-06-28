use crate::errors::NyxResult;
use crate::utils::get_project_info;
use console::style;
use std::{env, fs};

pub fn handle(project: Option<String>, all: bool, config_dir: &std::path::Path) -> NyxResult<()> {
    if all {
        println!("{}", style("Cleaning all indexes...").cyan().bold());
        if config_dir.exists() {
            fs::remove_dir_all(config_dir)?;
            fs::create_dir_all(config_dir)?;
        }
        println!("{}", style("✔ All indexes cleaned").green().bold());
    } else if let Some(proj_name) = project {
      let db_path = config_dir.join(format!("{proj_name}.sqlite"));
        if db_path.exists() {
            fs::remove_file(&db_path)?;
            println!(
                "{} {}",
                style("✔ Cleaned index for").green(),
                style(&proj_name).white().bold()
            );
        } else {
            println!(
                "{} {}",
                style("✖ No index found for").red(),
                style(&proj_name).white().bold()
            );
        }
    } else {
        let current_dir = env::current_dir()?;
        let (project_name, db_path) = get_project_info(&current_dir, config_dir)?;

        if db_path.exists() {
            fs::remove_file(&db_path)?;
            println!(
                "{} {}",
                style("✔ Cleaned index for").green(),
                style(&project_name).white().bold()
            );
        } else {
            println!(
                "{} {}",
                style("✖ No index found for current project").red(),
                style(&project_name).white().bold()
            );
        }
    }

    std::process::exit(0);
}
