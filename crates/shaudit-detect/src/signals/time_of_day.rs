//! Commits outside typical working hours. Signal (0.05).
//!
//! Pragmatic simplification per plan: no z-score; instead bool-check whether
//! commit hour is in the typical human working range 08–22 local time. The
//! author date's tz-local hour is supplied by the git log collector.

pub fn evaluate(hour: Option<u32>) -> f32 {
    let Some(h) = hour else {
        return 0.0;
    };
    if (8..=22).contains(&h) {
        0.0
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_hour_no_signal() {
        assert_eq!(evaluate(Some(14)), 0.0);
    }

    #[test]
    fn midnight_full_signal() {
        assert_eq!(evaluate(Some(2)), 1.0);
    }

    #[test]
    fn unknown_hour_no_signal() {
        assert_eq!(evaluate(None), 0.0);
    }
}
