pub fn lowercase_ext(path: &std::path::Path) -> Option<&'static str> {
    path.extension().and_then(|s| match s.to_str()? {
        "rs" | "RS" => Some("rs"),
        "c" => Some("c"),
        "cpp" | "c++" => Some("cpp"),
        "java" => Some("java"),
        "go" => Some("go"),
        "php" => Some("php"),
        "py" | "PY" => Some("py"),
        "ts" | "TSX" | "tsx" => Some("ts"),
        "js" => Some("js"),
        _ => None,
    })
}
