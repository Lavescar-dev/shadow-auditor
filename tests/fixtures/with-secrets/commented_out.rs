// Fixture: AWS key suppressed by inline allowlist — should produce 0 findings.
pub fn demo() {
    // Example only — safe to commit:
    let _example = "AKIAIOSFODNN7EXAMPLE"; // shaudit:allow secrets
}
