const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub(crate) fn hash_parts(parts: &[&[u8]]) -> u64 {
    let mut h = FNV_OFFSET;
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            h ^= 0xff;
            h = h.wrapping_mul(FNV_PRIME);
        }
        for byte in *part {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separating_the_parts_keeps_different_splits_apart() {
        assert_ne!(hash_parts(&[b"ab", b"c"]), hash_parts(&[b"a", b"bc"]));
        assert_ne!(hash_parts(&[b"abc"]), hash_parts(&[b"ab", b"c"]));
    }
}
