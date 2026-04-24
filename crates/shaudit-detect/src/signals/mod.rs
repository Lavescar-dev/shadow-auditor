//! AI-authorship signals (plan §3.2). Each signal returns a value in `[0.0, 1.0]`
//! and has a fixed weight. Aggregation happens in `crate::scorer`.

pub mod commit_msg;
pub mod commit_size;
pub mod docstring_ratio;
pub mod function_variance;
pub mod marketing_comments;
pub mod null_density;
pub mod time_of_day;
pub mod unused_imports;

#[derive(Debug, Clone, Copy)]
pub struct Signal {
    pub name: &'static str,
    pub weight: f32,
    pub value: f32,
}

impl Signal {
    pub fn contribution(&self) -> f32 {
        self.weight * self.value.clamp(0.0, 1.0)
    }
}

/// Plan §3.2 weight table.
pub const WEIGHTS: &[(&str, f32)] = &[
    ("commit_msg", 0.40),
    ("commit_size", 0.10),
    ("time_of_day", 0.05),
    ("docstring_ratio", 0.10),
    ("null_density", 0.10),
    ("marketing_comments", 0.05),
    ("unused_imports", 0.10),
    ("function_variance", 0.10),
];

pub fn weight_for(name: &str) -> f32 {
    WEIGHTS
        .iter()
        .find_map(|(n, w)| if *n == name { Some(*w) } else { None })
        .unwrap_or(0.0)
}
