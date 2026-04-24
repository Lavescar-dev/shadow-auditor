//! Function length variance. Signal (0.10).
//!
//! Pragmatic: use simple regex to find function definitions per language,
//! measure line counts, compute coefficient of variation (std dev / mean).
//! AI tends to write longer, more uniform functions → low CV.

use regex::Regex;

use std::sync::LazyLock;

use shaudit_core::Language;

static RUST_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:pub\s+(?:\(\w+\)\s+)?)?(?:async\s+)?fn\s+\w+").unwrap()
});
static TS_FN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+\w+").unwrap());
static PY_FN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:async\s+)?def\s+\w+").unwrap());

pub fn evaluate(source: &str, language: Language) -> f32 {
    let fn_re = match language {
        Language::Rust => &*RUST_FN,
        Language::TypeScript | Language::JavaScript => &*TS_FN,
        Language::Python => &*PY_FN,
        _ => return 0.0,
    };

    let starts: Vec<usize> = fn_re
        .find_iter(source)
        .map(|m| source[..m.start()].lines().count())
        .collect();

    if starts.len() < 3 {
        return 0.0; // too few samples
    }

    let total_lines = source.lines().count();
    let mut lengths: Vec<f32> = Vec::with_capacity(starts.len());
    for w in starts.windows(2) {
        lengths.push((w[1] - w[0]) as f32);
    }
    lengths.push((total_lines - starts.last().copied().unwrap_or(0)) as f32);

    let mean = lengths.iter().sum::<f32>() / lengths.len() as f32;
    if mean < 3.0 {
        return 0.0;
    }
    let variance = lengths.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / lengths.len() as f32;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean;

    // Low CV (< 0.4) = uniform functions = AI signal. Ramp 0.4 → 0.2.
    if cv >= 0.4 {
        0.0
    } else if cv <= 0.2 {
        1.0
    } else {
        (0.4 - cv) / 0.2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_few_functions_no_signal() {
        let src = "fn one() {}";
        assert_eq!(evaluate(src, Language::Rust), 0.0);
    }

    #[test]
    fn highly_uniform_full_signal() {
        let src = "\
fn a() {
    let x = 1;
    let y = 2;
    let z = x + y;
    println!(\"{z}\");
}
fn b() {
    let x = 3;
    let y = 4;
    let z = x + y;
    println!(\"{z}\");
}
fn c() {
    let x = 5;
    let y = 6;
    let z = x + y;
    println!(\"{z}\");
}
";
        let v = evaluate(src, Language::Rust);
        assert!(v > 0.5, "expected uniform signal, got {v}");
    }
}
