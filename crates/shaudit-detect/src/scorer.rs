//! Aggregates the eight signals into a single provenance score.

use shaudit_core::Language;

use crate::git::GitContext;
use crate::signals;

#[derive(Debug, Clone)]
pub struct ProvenanceReport {
    pub score: f32,
    pub signals: Vec<signals::Signal>,
}

pub fn score(source: &str, language: Language, git: &GitContext) -> ProvenanceReport {
    let items = vec![
        signals::Signal {
            name: "commit_msg",
            weight: signals::weight_for("commit_msg"),
            value: signals::commit_msg::evaluate(&git.commit_message),
        },
        signals::Signal {
            name: "commit_size",
            weight: signals::weight_for("commit_size"),
            value: signals::commit_size::evaluate(git.additions),
        },
        signals::Signal {
            name: "time_of_day",
            weight: signals::weight_for("time_of_day"),
            value: signals::time_of_day::evaluate(git.author_date_hour),
        },
        signals::Signal {
            name: "docstring_ratio",
            weight: signals::weight_for("docstring_ratio"),
            value: signals::docstring_ratio::evaluate(source, language),
        },
        signals::Signal {
            name: "null_density",
            weight: signals::weight_for("null_density"),
            value: signals::null_density::evaluate(source),
        },
        signals::Signal {
            name: "marketing_comments",
            weight: signals::weight_for("marketing_comments"),
            value: signals::marketing_comments::evaluate(source),
        },
        signals::Signal {
            name: "unused_imports",
            weight: signals::weight_for("unused_imports"),
            value: signals::unused_imports::evaluate(source, language),
        },
        signals::Signal {
            name: "function_variance",
            weight: signals::weight_for("function_variance"),
            value: signals::function_variance::evaluate(source, language),
        },
    ];
    let score = items.iter().map(|s| s.contribution()).sum::<f32>().min(1.0);
    ProvenanceReport {
        score,
        signals: items,
    }
}
