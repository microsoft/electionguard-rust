use num_bigint::BigUint;

// XOR two byte arrays
pub fn xor(a: &[u8], b: &[u8], l: usize) -> Vec<u8> {
    let mut c = Vec::new();
    for i in 0..l {
        c.push(a[i] ^ b[i]);
    }
    c
}

// Returns an l-byte array with the bytes of u, padded with zeros if necessary
pub fn pad_with_zeros(u: &BigUint, l: usize) -> Vec<u8> {
    let byte_array = u.to_bytes_be();
    let padding = (0..l - byte_array.len()).map(|_| 0u8).collect();
    [padding, byte_array].concat()
}
