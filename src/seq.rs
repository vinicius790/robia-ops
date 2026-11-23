//! Aritmética modular de números de sequência TCP 32-bit (RFC 793 / RFC 7323).

pub fn wrapping_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

pub fn wrapping_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

pub fn wrapping_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

pub fn wrapping_ge(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

pub fn in_window(seq: u32, una: u32, nxt: u32) -> bool {
    seq.wrapping_sub(una) < nxt.wrapping_sub(una)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraparound_comparisons() {
        let a = u32::MAX - 5;
        let b = 10u32;
        assert!(wrapping_lt(a, b));
        assert!(wrapping_gt(b, a));
        assert!(in_window(u32::MAX, a, b));
        assert!(in_window(0, a, b));
        assert!(!in_window(11, a, b));
    }
}
