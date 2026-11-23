//! Checksum Internet (RFC 1071) — ones' complement usado por IP/ICMP/UDP/TCP.

/// Soma 16-bit ones' complement sobre `data` (padding implícito com 0 se ímpar).
pub fn internet_checksum(data: &[u8]) -> u16 {
    internet_checksum_with_seed(data, 0)
}

/// Igual a [`internet_checksum`], mas inicia o acumulador com `seed` (útil para
/// pseudo-header UDP/TCP: some o pseudo-header e depois o segmento).
pub fn internet_checksum_with_seed(data: &[u8], seed: u32) -> u16 {
    let mut sum: u32 = seed;
    let (chunks, remainder) = data.as_chunks::<2>();
    for c in chunks {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let Some(&b) = remainder.first() {
        sum += u16::from_be_bytes([b, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pseudo-header IPv4 para UDP/TCP (RFC 768 / 793).
pub fn ipv4_pseudo_header_sum(src: [u8; 4], dst: [u8; 4], protocol: u8, length: u16) -> u32 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += protocol as u32;
    sum += length as u32;
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_empty_is_ffff() {
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn checksum_known_vector() {
        // Exemplo clássico: bytes que somam para um valor conhecido.
        let data = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let c = internet_checksum(&data);
        // Recomputar com checksum no campo deve dar 0.
        let mut with_c = data;
        with_c[10] = (c >> 8) as u8;
        with_c[11] = (c & 0xff) as u8;
        assert_eq!(internet_checksum(&with_c), 0);
    }

    #[test]
    fn odd_length_pads_zero() {
        let a = internet_checksum(&[0x01, 0x02, 0x03]);
        let b = internet_checksum(&[0x01, 0x02, 0x03, 0x00]);
        assert_eq!(a, b);
    }
}
