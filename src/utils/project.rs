use std::path::{Path, PathBuf};

pub fn get_project_info(
    project_path: &Path,
    config_dir: &Path,
) -> Result<(String, PathBuf), Box<dyn std::error::Error>> {
    let project_name = project_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Unable to determine project name")?;

    let db_name = sanitize_project_name(project_name);
    let db_path = config_dir.join(format!("{}.sqlite", db_name));

    Ok((project_name.to_string(), db_path))
}

pub fn sanitize_project_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| match c {
            ' ' | '\t' | '\n' | '\r' => '_',
            c if c.is_alphanumeric() || c == '_' || c == '-' => c,
            _ => '_'
        })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}