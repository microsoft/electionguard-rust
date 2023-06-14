// XOR two byte arrays
pub fn xor(a: &[u8], b: &[u8], l: usize) -> Vec<u8> {
    let mut c = Vec::new();
    for i in 0..l {
        c.push(a[i] ^ b[i]);
    }
    c
}
