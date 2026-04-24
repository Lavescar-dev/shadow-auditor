//! Shannon entropy calculator for arbitrary byte strings.

/// Compute Shannon entropy of `bytes` in bits. Empty input returns 0.
///
/// Values typically fall in [0.0, 8.0]. Short-alphabet or repeated strings
/// score low (< 3.0); base64-ish blobs and random tokens score high (> 4.5).
pub fn shannon(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0_f32;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_zero() {
        assert_eq!(shannon(b""), 0.0);
    }

    #[test]
    fn single_char_zero() {
        assert_eq!(shannon(b"aaaaaaaa"), 0.0);
    }

    #[test]
    fn random_hex_high() {
        let e = shannon(b"a1b2c3d4e5f67890abcdef1234567890");
        assert!(e > 3.0, "expected hex entropy > 3.0, got {e}");
    }

    #[test]
    fn uniform_bytes_max_entropy() {
        let mut buf = Vec::with_capacity(256);
        for i in 0..=255u8 {
            buf.push(i);
        }
        let e = shannon(&buf);
        assert!(e >= 7.5, "uniform bytes should approach 8.0, got {e}");
    }
}
