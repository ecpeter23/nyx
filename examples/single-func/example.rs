fn source_env(var: &str) -> String {
    env::var(var).unwrap_or_default()                          // Source(env-var)
}