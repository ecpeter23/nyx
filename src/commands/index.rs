use std::fs;
use crate::cli::IndexAction;
use crate::utils::project::get_project_info;

pub fn handle(
    action: IndexAction,
    database_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IndexAction::Build { path, force } => {
            let build_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&build_path, database_dir)?;

            if force || !db_path.exists() {
                println!("Building index for: {}", project_name);
                build_index(&build_path, &db_path)?;
                println!("Index built: {}", db_path.display());
            } else {
                println!("Index already exists. Use --force to rebuild.");
            }
        }
        IndexAction::Status { path } => {
            let status_path = std::path::Path::new(&path).canonicalize()?;
            let (project_name, db_path) = get_project_info(&status_path, database_dir)?;

            println!("Project: {}", project_name);
            println!("Index path: {}", db_path.display());
            println!("Index exists: {}", db_path.exists());

            if db_path.exists() {
                let metadata = fs::metadata(&db_path)?;
                println!("Index size: {} bytes", metadata.len());
                println!("Last modified: {:?}", metadata.modified()?);
            }
        }
    }
    Ok(())
}

pub fn build_index(
    _project_path: &std::path::Path,
    db_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Implement actual index building
    fs::File::create(db_path)?;
    println!("Index building logic goes here...");
    Ok(())
}