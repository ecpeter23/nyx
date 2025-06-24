use crate::errors::{NyxError, NyxResult};
use std::path::{Path, PathBuf};

/// Determine `<project-name, path/to/<project>.sqlite>`.
pub fn get_project_info(project_path: &Path, config_dir: &Path) -> NyxResult<(String, PathBuf)> {
    let project_name = project_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NyxError::Other("Unable to determine project name".into()))?;

    let db_name = sanitize_project_name(project_name);
    let db_path = config_dir.join(format!("{}.sqlite", db_name));

    Ok((project_name.to_owned(), db_path))
}

pub fn sanitize_project_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| match c {
            ' ' | '\t' | '\n' | '\r' => '_',
            c if c.is_alphanumeric() || c == '_' || c == '-' => c,
            _ => '_',
        })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

#[test]
fn sanitize_project_name_is_idempotent_and_lossless_enough() {
    let samples = [
        ("My Project", "my_project"),
        ("Hello-World", "hello-world"),
        ("mixed_case", "mixed_case"),
        ("tabs\tspaces\n", "tabs_spaces"),
        ("   multiple   ", "multiple"),
        ("weird@$*chars", "weird_chars"),
    ];

    for (input, expected) in samples {
        assert_eq!(sanitize_project_name(input), expected, "input: {}", input);
        assert_eq!(sanitize_project_name(expected), expected);
    }
}

#[test]
fn get_project_info_uses_sanitized_name_in_sqlite_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let project_dir = root.join("Example Project");
    std::fs::create_dir(&project_dir).unwrap();

    let (project_name, db_path) =
        get_project_info(&project_dir, root).expect("should detect project");

    assert_eq!(project_name, "Example Project");
    assert_eq!(db_path, root.join("example_project.sqlite"));
}
