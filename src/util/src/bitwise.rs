/// Computes the xor of two byte slices.
/// For slices of unequal length, the xor of the min(len(a),len(b))-prefix is computed
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod test {
    use crate::bitwise::xor;

    #[test]
    fn test_xor() {
        assert_eq!(xor(&[0xde, 0xad], &[0xbe, 0xef]), [0x60, 0x42])
    }
}
