pub fn in_window(seq: u32, una: u32, nxt: u32) -> bool {
    seq.wrapping_sub(una) < nxt.wrapping_sub(una)
}
