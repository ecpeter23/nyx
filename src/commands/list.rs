use std::fs;

pub fn handle(
    verbose: bool,
    database_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Indexed projects:");

    if database_dir.exists() {
        for entry in fs::read_dir(database_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("sqlite") {
                let project_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");

                println!("  {}", project_name);

                if verbose {
                    let metadata = fs::metadata(&path)?;
                    println!("    Path: {}", path.display());
                    println!("    Size: {} bytes", metadata.len());
                    println!("    Modified: {:?}", metadata.modified()?);
                }
            }
        }
    } else {
        println!("  No indexed projects found.");
    }

    Ok(())
}