pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert!(
        a.len() == b.len(),
        "Byte strings must be of the same length!"
    );
    let mut c = vec![];
    for (b1, b2) in a.iter().zip(b.iter()) {
        c.push(*b1 ^ *b2);
    }
    c
}

#[cfg(test)]
mod test {
    use crate::bitwise::xor;

    #[test]
    fn test_xor() {
        assert_eq!(xor(&[0xde, 0xad], &[0xbe, 0xef]), [0x60, 0x42])
    }
}
