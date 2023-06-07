// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use num_traits::{CheckedSub, Zero};
use std::num::{NonZeroU64, NonZeroUsize};

pub struct Csprng(Box<dyn sha3::digest::XofReader>);

impl Csprng {
    //? FIXME TODO really a csprng must have a large seed, maybe take an `IntoIterator<Into<u64>>`?
    pub fn new(seed: u64) -> Csprng {
        use sha3::digest::{ExtendableOutput, Update};

        let mut hasher = sha3::Shake256::default();

        let buf = b"csprng for electionguard-rust";
        hasher.update(&(buf.len() as u64).to_le_bytes());
        hasher.update(&buf[..]);

        let buf: [u8; 8] = seed.to_le_bytes();
        hasher.update(&(buf.len() as u64).to_le_bytes());
        hasher.update(&buf);

        Csprng(Box::new(hasher.finalize_xof()))
    }

    /// Returns a uniformly random `u8`.
    pub fn next_u8(&mut self) -> u8 {
        let mut buf = [0u8];
        self.0.read(&mut buf);
        buf[0]
    }

    /// Returns a uniformly random `u32`.
    pub fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.read(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Returns a uniformly random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.read(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Returns a uniformly random `bool`.
    pub fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }

    // Returns a random number chosen uniformly from 0 <= n < 2^bits.
    pub fn next_biguint(&mut self, bits: NonZeroUsize) -> BigUint {
        self.next_biguint_impl(bits, false)
    }

    /// Returns a random number that requires exactly the specified number of bits to represent.
    /// If `bits == 1`, chosen uniformly `0` or `1`.
    /// else `bits > 1`, chosen uniformly from `2^(bits - 1) <= n < 2^bits`.
    /// I.e., the high bit position `bits - 1` is guaranteed to be set, but all lower
    /// bit positions are uniform random.
    pub fn next_biguint_requiring_bits(&mut self, bits: NonZeroUsize) -> BigUint {
        self.next_biguint_impl(bits, true)
    }

    fn next_biguint_impl(&mut self, bits: NonZeroUsize, set_high_bit: bool) -> BigUint {
        let bits: usize = bits.get();

        let cnt_bytes = (bits + 7) / 8;
        let mut buf = vec![0; cnt_bytes];
        self.0.read(buf.as_mut_slice());

        if bits == 1 {
            buf[0] &= 1;
        } else {
            // Turn off any extra bits.
            let cnt_bits_filled = cnt_bytes * 8;
            let cnt_extra_bits = cnt_bits_filled - bits;
            if 0 < cnt_extra_bits {
                debug_assert!(cnt_extra_bits < 8);
                let mask = !(((1u8 << cnt_extra_bits) - 1) << (8 - cnt_extra_bits));
                buf[0] &= mask;
            }

            if set_high_bit {
                // Turn on the high bit.
                let high_bit_pos = (bits - 1) % 8;
                buf[0] |= 1u8 << high_bit_pos;
            }
        }

        BigUint::from_bytes_be(buf.as_slice())
    }

    /// Returns a random number uniformly from `0 <= n < end`.
    /// `end` must be greater than `0`.
    pub fn next_biguint_lt(&mut self, end: &BigUint) -> BigUint {
        assert!(!end.is_zero(), "end must be greater than 0");

        // The `.unwrap()` is justified here because `end` is nonzero.
        #[allow(clippy::unwrap_used)]
        let bits = NonZeroU64::new(end.bits()).unwrap();

        // The `.unwrap()` is justified here because surely `log2(end)` will fit into `usize`.
        #[allow(clippy::unwrap_used)]
        let bits: NonZeroUsize = bits.try_into().unwrap();

        loop {
            let n = self.next_biguint(bits);
            if &n < end {
                break n;
            }
        }
    }

    /// Returns a random number uniformly from `start <= n < end`.
    /// `start` must be less than `end`.
    pub fn next_biguint_range(&mut self, start: &BigUint, end: &BigUint) -> BigUint {
        #[allow(clippy::expect_used)]
        let diff = end
            .checked_sub(start)
            .expect("`start` must be less than `end`.");
        start + &self.next_biguint_lt(&diff)
    }
}

impl rand::RngCore for Csprng {
    fn next_u32(&mut self) -> u32 {
        self.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.read(dest);
        Ok(())
    }
}

#[cfg(test)]
mod test_csprng {
    use super::*;
    use num_traits::One;
    use rand::prelude::Distribution;
    use std::num::NonZeroUsize;

    #[test]
    fn test_csprng() {
        let mut csprng = Csprng::new(0);
        assert_eq!(csprng.next_u64(), 10686075903840013692);
        assert_eq!(csprng.next_u8(), 168);
        assert_eq!(csprng.next_bool(), false);
    }

    #[test]
    fn next_biguint() {
        let mut csprng = Csprng::new(0);
        for bits in 1..100 {
            let j = csprng.next_biguint(NonZeroUsize::new(bits).unwrap());
            assert!(j < (BigUint::one() << bits));
        }
    }

    #[test]
    fn next_biguint_requiring_bits() {
        let mut csprng = Csprng::new(0);
        for bits in 1..100 {
            let j = csprng.next_biguint_requiring_bits(NonZeroUsize::new(bits).unwrap());

            if bits == 1 {
                assert!(j == 0_u8.into() || j == 1_u8.into());
            } else {
                let beg = BigUint::one() << (bits - 1);
                let end = BigUint::one() << bits;
                assert!((beg..end).contains(&j));
            }
        }
    }

    #[test]
    fn next_biguint_lt() {
        let mut csprng = Csprng::new(0);
        for end in 1usize..100 {
            let end: BigUint = end.into();
            let j = csprng.next_biguint_lt(&end);
            //dbg!((&j, &end));
            assert!(j < end);
        }
    }

    #[test]
    fn next_biguint_range() {
        let mut csprng = Csprng::new(0);
        for start_usize in 0usize..100 {
            let start: BigUint = start_usize.into();
            for end in start_usize + 1..101 {
                let end: BigUint = end.into();
                let j = csprng.next_biguint_range(&start, &end);
                assert!(&start <= &j && &j < &end);
            }
        }
    }

    #[test]
    fn test_csprng_rand_rngcore() {
        let mut csprng = Csprng::new(0);

        let n: u64 = rand::distributions::Standard.sample(&mut csprng);
        assert_eq!(n, 10686075903840013692);
    }
}
