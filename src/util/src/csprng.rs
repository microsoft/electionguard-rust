// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::{NonZeroU64, NonZeroUsize};

use num_bigint::BigUint;
use num_traits::{CheckedSub, Zero};

/// CSPRNG based on the SHA-3 extendable output function SHAKE256.
/// Defined By
/// NIST FIPS Pub 202 SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
/// <https://dx.doi.org/10.6028/NIST.FIPS.202>
///
/// SHAKE256(M, d) = KECCAK\[512\] (M || 1111, d)
/// KECCAK\[c\] = SPONGE\[KECCAK-p\[1600, 24\], pad10*1, 1600–c\]
/// Capacity `c` = 512 bits
/// Rate `r` = 1088 bits
pub struct Csprng(Box<dyn sha3::digest::XofReader>);

impl Csprng {
    /// Width of the underlying KECCAK permutation in bits.
    /// This is the effecitve internal state size or bandwidth.
    pub const fn permutation_bits() -> usize {
        1600 // Defined by NIST FIPS Pub 202 SHA-3 Standard
    }

    /// Width in bits of the underlying permutation minus the rate.
    pub const fn capacity_bits() -> usize {
        512 // Defined by NIST FIPS Pub 202 SHA-3 Standard
    }

    /// Bits consumed or generated for each invocation of the underlying permutation.
    pub const fn rate_bits() -> usize {
        Csprng::permutation_bits() - Csprng::capacity_bits()
    }

    /// The effecitve internal state size or bandwidth, in bytes.
    pub const fn permutation_bytes() -> usize {
        Csprng::permutation_bits() / 8
    }

    /// Bytes consumed or generated for each invocation of the underlying permutation.
    pub const fn rate_bytes() -> usize {
        Csprng::rate_bits() / 8
    }

    /// Width of the underlying permutation minus the rate, in bytes.
    pub const fn capacity_bytes() -> usize {
        Csprng::capacity_bits() / 8
    }

    // The number of bytes needed to seed the entire internal state by processing the optimum
    // number of message input blocks.
    // But if you are planning to append more entropy or customization data to the seed data,
    // consider just starting with `permutation_bytes()` instead.
    pub const fn recommended_max_seed_bytes() -> usize {
        // The number of blocks needed to completely fill the internal state.
        let msg_blocks =
            (Csprng::permutation_bits() + Csprng::rate_bits() - 1) / Csprng::rate_bits();

        // The final message block is padded with at least 6 bits (1111 || 1 0* 1),
        // so we take off one byte.
        msg_blocks * Csprng::rate_bytes() - 1
    }

    pub fn new(seed: &[u8]) -> Csprng {
        use sha3::digest::{ExtendableOutput, Update};

        let mut hasher = sha3::Shake256::default();

        let buf = b"csprng for electionguard-rust";
        hasher.update(&(buf.len() as u64).to_be_bytes());
        hasher.update(&buf[..]);

        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);

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
#[allow(clippy::unwrap_used)]
mod test_csprng {
    use super::*;
    use num_traits::One;
    use rand::prelude::Distribution;
    use std::num::NonZeroUsize;

    #[test]
    fn test_csprng_basics() {
        // The bit quantities match the spec.
        assert_eq!(Csprng::permutation_bits(), 1600);
        assert_eq!(Csprng::rate_bits(), 1088);
        assert_eq!(Csprng::capacity_bits(), 512);

        // The byte quantites match the bit quantities.
        assert_eq!(Csprng::permutation_bits(), Csprng::permutation_bytes() * 8);
        assert_eq!(Csprng::rate_bits(), Csprng::rate_bytes() * 8);
        assert_eq!(Csprng::capacity_bits(), Csprng::capacity_bytes() * 8);

        // The recommended seed bytes is not less than the internal state.
        assert!(Csprng::permutation_bytes() <= Csprng::recommended_max_seed_bytes());

        let mut csprng = Csprng::new(b"test_csprng::test_csprng_basics");
        assert_eq!(csprng.next_u64(), 11117081707462498600);
        assert_eq!(csprng.next_u8(), 202);
        assert!(csprng.next_bool());
    }

    #[test]
    fn next_biguint() {
        let mut csprng = Csprng::new(b"test_csprng::next_biguint");
        for bits in 1..100 {
            let j = csprng.next_biguint(NonZeroUsize::new(bits).unwrap());
            assert!(j < (BigUint::one() << bits));
        }
    }

    #[test]
    fn next_biguint_requiring_bits() {
        let mut csprng = Csprng::new(b"test_csprng::next_biguint_requiring_bits");
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
        let mut csprng = Csprng::new(b"test_csprng::next_biguint_lt");
        for end in 1usize..100 {
            let end: BigUint = end.into();
            let j = csprng.next_biguint_lt(&end);
            //dbg!((&j, &end));
            assert!(j < end);
        }
    }

    #[test]
    fn next_biguint_range() {
        let mut csprng = Csprng::new(b"test_csprng::next_biguint_range");
        for start_usize in 0usize..100 {
            let start: BigUint = start_usize.into();
            for end in start_usize + 1..101 {
                let end: BigUint = end.into();
                let j = csprng.next_biguint_range(&start, &end);
                assert!(start <= j && j < end);
            }
        }
    }

    #[test]
    fn test_csprng_rand_rngcore() {
        let mut csprng = Csprng::new(b"test_csprng::test_csprng_rand_rngcore");

        let n: u64 = rand::distributions::Standard.sample(&mut csprng);
        assert_eq!(n, 8275017704394333465);
    }
}
