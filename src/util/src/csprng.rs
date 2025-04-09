// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::{NonZeroU64, NonZeroUsize};

use num_bigint::BigUint;
use num_traits::{CheckedSub, Zero};
use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, ExtendableOutputReset, Update, XofReader},
};
use static_assertions::assert_impl_all;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::const_minmax::{const_max_usize, const_min_usize};

//=================================================================================================|

/// Builder for initializing a new CSPRNG.
pub struct CsprngBuilder(Box<Shake256>);

impl CsprngBuilder {
    /// Writes a value as big-endian u64.
    #[inline]
    pub fn write_u64<IntoU64>(mut self, u: IntoU64) -> Self
    where
        IntoU64: Into<u64> + Copy,
    {
        self.0.update(&Into::<u64>::into(u).to_be_bytes());
        self
    }

    /// Writes a string into the builder, as UTF-8 preceded by its length in bytes
    /// as a big-endian u64.
    #[inline]
    pub fn write_str<AsRefStr>(self, s: AsRefStr) -> Self
    where
        AsRefStr: AsRef<str>,
    {
        self.write_bytes(s.as_ref().as_bytes())
    }

    /// Writes a slice of bytes into the builder, preceded by its length as a big-endian u64.
    #[inline]
    pub fn write_bytes<AsRefSliceU8>(self, data: AsRefSliceU8) -> Self
    where
        AsRefSliceU8: AsRef<[u8]>,
    {
        let slice_u8 = data.as_ref();
        let mut self_ = self.write_u64(slice_u8.len() as u64);
        self_.0.update(slice_u8);
        self_
    }

    /// Writes a sequence of slices of bytes, each preceded by its length as a big-endian u64,
    /// preceded and followed by `begin` and `end` symbols.
    ///
    /// The `begin` and `end` symbols are not plausible values for lengths, so
    /// they should be unambiguous delimiters.
    #[allow(non_camel_case_types)]
    #[allow(dead_code)] // This warning seems to be a false positive.
    #[inline]
    fn write_seq_bytes<II_AsRefSliceU8, AsRefSliceU8>(self, seq_bytes: II_AsRefSliceU8) -> Self
    where
        II_AsRefSliceU8: IntoIterator<Item = AsRefSliceU8>,
        AsRefSliceU8: AsRef<[u8]>,
    {
        const MARK_BEGIN: u64 = 0x_FFFFFFFF_FFFFFFFB_u64; // u64::MAX - 4;
        const MARK_ENDIN: u64 = 0x_FFFFFFFF_FFFFFFFE_u64; // u64::MAX - 1;

        let mut self_ = self.write_u64(MARK_BEGIN);
        for as_ref_bytes in seq_bytes {
            self_ = self_.write_bytes(as_ref_bytes);
        }
        self_.write_u64(MARK_ENDIN)
    }

    /// Finishes the builder and returns the CSPRNG.
    pub fn finish(mut self) -> Csprng {
        let csprng = Csprng(Box::new(self.0.finalize_xof_reset()));

        drop(self); // calls zeroize()

        csprng
    }
}

impl Zeroize for CsprngBuilder {
    fn zeroize(&mut self) {
        let mut shake256reader = Shake256::default().finalize_xof();
        zeroize_shake256_and_reader(&mut self.0, &mut shake256reader);
    }
}

impl Drop for CsprngBuilder {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CsprngBuilder {}

impl Default for CsprngBuilder {
    /// Constructs a new [`CsprngBuilder`] in the initial state.
    ///
    /// Equivalent to [`CsprngBuilder::default()`].
    ///
    /// ```
    /// # use util::csprng::{Csprng, CsprngBuilder};
    /// let mut csprng = CsprngBuilder::default()
    ///     .write_str("Fixed customization string")
    ///     .write_bytes(b"data containing sufficient entropy goes here")
    ///     .finish();
    /// assert_ne!(csprng.next_u128(), 0, "Unlikely");
    /// ```
    fn default() -> Self {
        CsprngBuilder(Box::default())
    }
}

/// CSPRNG based on the SHA-3 extendable output function SHAKE256.
/// Defined By
/// NIST FIPS Pub 202 SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
/// <https://dx.doi.org/10.6028/NIST.FIPS.202>
///
/// SHAKE256(M, d) = KECCAK\[512\] (M || 1111, d)
/// KECCAK\[c\] = SPONGE\[KECCAK-p\[1600, 24\], pad10*1, 1600–c\]
/// Capacity `c` = 512 bits
/// Rate `r` = 1088 bits
pub struct Csprng(Box<Shake256Reader>);
//#[derive(Zeroize, ZeroizeOnDrop)]

impl Csprng {
    /// Max rated collision security strength in bits, for a sufficiently-long output.
    pub const fn max_rated_collision_strength_bits() -> usize {
        256 // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
    }

    /// Rated collision security strength in bits.
    pub const fn rated_collision_strength_bits(output_len: usize) -> usize {
        // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
        const_min_usize(&[output_len / 2, Self::max_rated_collision_strength_bits()])
    }

    /// Max rated preimage security strength in bits, for a sufficiently-long output.
    pub const fn max_rated_preimage_strength_bits() -> usize {
        256 // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
    }

    /// Rated preimage security strength in bits.
    pub const fn rated_preimage_strength_bits(output_len: usize) -> usize {
        // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
        if Self::max_rated_preimage_strength_bits() < output_len {
            Self::max_rated_preimage_strength_bits()
        } else {
            output_len
        }
    }

    /// Max rated second preimage security strength in bits, for a sufficiently-long output.
    pub const fn max_rated_second_preimage_strength_bits() -> usize {
        256 // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
    }

    /// Rated second preimage security strength in bits.
    pub const fn rated_second_preimage_strength_bits(output_len: usize) -> usize {
        // NIST FIPS Pub 202 SHA-3 Standard, Table 4, pg 23
        if Self::max_rated_second_preimage_strength_bits() < output_len {
            Self::max_rated_second_preimage_strength_bits()
        } else {
            output_len
        }
    }

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

    /// The effective internal state size or bandwidth, in bytes.
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

    /// The number of bytes needed to seed the entire internal state,
    /// plus an additional 1/8 (or 200 bits, whichever is greater) for
    /// good measure. There is probably no point to seeding with more
    /// entropy than this.
    ///
    /// Guaranteed to be:
    /// - at least 512 bits, and
    /// - a multiple of 128 bits (16 bytes).
    pub const fn max_entropy_seed_bytes() -> usize {
        // Start with the width in bits of the underlying permutation.
        let bits = Self::permutation_bits();
        // Add ceil(bits * 1/8), or at least 200 bits.
        let bits = bits + const_max_usize(&[200, bits.div_ceil(8)]);
        // Ensure is a multiple of 128 and at least 512.
        let bits = const_max_usize(&[512, bits.next_multiple_of(128)]);
        // Convert to bytes.
        bits / 8
    }

    /// Initializes a new CSPRNG from a sequence of bytes.
    ///
    /// Equivalent to using a builder with a single call
    /// to [`CsprngBuilder::write_bytes()`].
    #[inline]
    pub fn from_seed_bytes<AsRefSliceU8>(seed_bytes: AsRefSliceU8) -> Self
    where
        AsRefSliceU8: AsRef<[u8]>,
    {
        CsprngBuilder::default().write_bytes(seed_bytes).finish()
    }

    /// Initializes a new CSPRNG from a string.
    ///
    /// Equivalent to using a builder with a single call
    /// to [`CsprngBuilder::write_str()`].
    #[inline]
    pub fn from_seed_str<AsRefStr>(seed_str: AsRefStr) -> Self
    where
        AsRefStr: AsRef<str>,
    {
        CsprngBuilder::default().write_str(seed_str).finish()
    }

    /// Returns a new default [`CsprngBuilder`], for initializing a new [`Csprng`].
    ///
    /// Equivalent to [`CsprngBuilder::default()`].
    ///
    /// ```
    /// # use util::csprng::Csprng;
    /// let mut csprng = Csprng::build()
    ///     .write_str("Fixed customization string")
    ///     .write_bytes(b"data containing sufficient entropy goes here")
    ///     .finish();
    /// assert_ne!(csprng.next_u128(), 0, "Unlikely");
    /// ```
    #[inline]
    pub fn build() -> CsprngBuilder {
        CsprngBuilder::default()
    }

    /// Fills the supplied buffer with generated bytes.
    ///
    /// Compare to `rand::RngCore::fill_bytes`.
    pub fn fill_buf(&mut self, buf: &mut [u8]) {
        use sha3::digest::XofReader;
        self.0.read(buf);
    }

    /// Returns an array of uniformly random `u8`s.
    ///
    /// ```
    /// # use util::csprng::Csprng;
    /// let csprng = &mut Csprng::from_seed_bytes(b"my seed data");
    /// let buf: [u8; 32] = csprng.next_arr_u8();
    /// assert_ne!(buf, [0_u8; 32]);
    /// ```
    pub fn next_arr_u8<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0_u8; N];
        self.fill_buf(&mut buf);
        buf
    }

    /// Returns a uniformly random `bool`.
    ///
    /// ```
    /// # use util::csprng::Csprng;
    /// let csprng = &mut Csprng::default();
    /// let bools: [bool; 128] = std::array::from_fn(|_ix| csprng.next_bool());
    /// assert!(bools.iter().any(|&b|b));
    /// assert!(bools.iter().any(|&b|!b));
    /// ```
    pub fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }

    /// Returns a uniformly random `u8`.
    pub fn next_u8(&mut self) -> u8 {
        self.next_arr_u8::<1>()[0]
    }

    /// Returns a uniformly random `u32`.
    pub fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.next_arr_u8())
    }

    /// Returns a uniformly random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.next_arr_u8())
    }

    /// Returns a uniformly random `u128`.
    ///
    /// ```
    /// # use util::csprng::Csprng;
    /// assert_ne!(Csprng::default().next_u128(), 0);
    /// ```
    pub fn next_u128(&mut self) -> u128 {
        u128::from_le_bytes(self.next_arr_u8())
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

        let cnt_bytes = bits.div_ceil(8);
        let mut buf = vec![0; cnt_bytes];
        self.fill_buf(buf.as_mut_slice());

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
    pub fn next_biguint_lt(&mut self, end: &BigUint) -> Option<BigUint> {
        debug_assert!(!end.is_zero(), "end must be greater than 0");

        let bits = NonZeroU64::new(end.bits())?;
        let bits = NonZeroUsize::try_from(bits).ok()?;

        loop {
            let n = self.next_biguint(bits);
            if &n < end {
                return Some(n);
            }
        }
    }

    /// Returns a random number uniformly from `start <= n < end`.
    /// `start` must be less than `end`.
    pub fn next_biguint_range(&mut self, start: &BigUint, end: &BigUint) -> Option<BigUint> {
        debug_assert!(start < end, "`start` must be less than `end`");

        end.checked_sub(start)
            .and_then(|diff| self.next_biguint_lt(&diff))
            .map(|add_to_start| start + &add_to_start)
    }

    /// Returns a new [`CsprngBuilder`] loaded with the max effective entropy,
    /// generated from this source.
    pub fn next_builder(&mut self) -> CsprngBuilder {
        const SEED_BYTES: usize = Csprng::max_entropy_seed_bytes();
        let mut buf = Zeroizing::new([0_u8; SEED_BYTES]);
        self.fill_buf(&mut buf[0..SEED_BYTES]);
        CsprngBuilder::default().write_bytes(&buf[0..SEED_BYTES])
    }

    /// Returns a new [`Csprng`] loaded with the max effective entropy,
    /// generated from this source.
    pub fn next_csprng(&mut self) -> Csprng {
        self.next_builder().finish()
    }
}

impl Default for Csprng {
    fn default() -> Self {
        CsprngBuilder::default().finish()
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
        self.fill_buf(dest);
    }
}

impl<const N: usize> From<Csprng> for [CsprngBuilder; N] {
    /// Converts the [`Csprng`] into an array of [`CsprngBuilder`]s, each loaded
    /// with the max effective entropy generated by the source.
    ///
    /// You may write additional data into the CsprngBuilder, or just call
    /// [`.finish()`](CsprngBuilder::finish) immediately.
    fn from(mut csprng: Csprng) -> Self {
        const SEED_BYTES: usize = Csprng::max_entropy_seed_bytes();
        let mut buf = Zeroizing::new([0_u8; SEED_BYTES]);
        std::array::from_fn(|_i| {
            // Init the CsprngBuilder
            csprng.fill_buf(&mut buf[0..SEED_BYTES]);
            CsprngBuilder::default().write_bytes(&buf[0..SEED_BYTES])
        })
    }
}

impl<const N: usize> From<Csprng> for [Csprng; N] {
    /// Converts the [`Csprng`] into an array of `Csprng`s, each initialized
    /// with the max effective entropy generated by the source.
    fn from(csprng: Csprng) -> Self {
        <[CsprngBuilder; N]>::from(csprng).map(CsprngBuilder::finish)
    }
}

impl Zeroize for Csprng {
    fn zeroize(&mut self) {
        let mut shake256 = Shake256::default();
        zeroize_shake256_and_reader(&mut shake256, &mut self.0);
    }
}

impl Drop for Csprng {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Csprng {}

assert_impl_all!(CsprngBuilder: Send, Sync, Zeroize, ZeroizeOnDrop);
assert_impl_all!(Csprng: Send, Sync, Zeroize, ZeroizeOnDrop);

/// Shake256 and/or Shake256reader could have secrets, but they do not support the
/// 'Zeroize' trait. This code is inefficient and, frankly, superstitious.
/// But in the absence of a defined contract from the code generator, optimizer,
/// and even the linker, we're reduced to ritualistic methods.
///
fn zeroize_shake256_and_reader(shake256: &mut Shake256, shake256reader: &mut Shake256Reader) {
    use rand::{Rng, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    // Well-known constant 'pi' in BCD (binary coded decimal) format.
    const UNINTERESTING_SEED_U64: u64 = 0x_3141_5926_5358_9793_u64;

    let mut notsecret_rng = XorShiftRng::seed_from_u64(UNINTERESTING_SEED_U64);
    let notsecret_rng = &mut notsecret_rng;

    use crate::const_minmax::const_max_usize;
    const OVERWRITE_LEN: usize = const_max_usize(&[
        Csprng::rate_bytes() * 11 / 5,
        Csprng::permutation_bytes() * 8 / 7,
    ]);

    const BUF_LEN: usize = Csprng::rate_bytes() * 6 / 7;
    let mut uninteresting_buf = [0_u8; BUF_LEN];
    let uninteresting_buf = &mut uninteresting_buf[..];

    fn random_subslice<'a>(rng: &mut XorShiftRng, buf: &'a mut [u8]) -> &'a mut [u8] {
        let qty = rng.random_range(1..=buf.len());
        let start = rng.random_range(0..=(buf.len() - qty));
        let end = start + qty;
        &mut buf[start..end]
    }

    /// Overwrite the internal partial-block input buffer with uninteresting data
    /// several times, using no write greater than than its input block size.
    fn overwrite_sh(sh: &mut Shake256, buf: &mut [u8], rng: &mut XorShiftRng) {
        let mut qty_written = 0;
        while qty_written < OVERWRITE_LEN {
            let partial_buf = random_subslice(rng, buf);
            rng.fill_bytes(partial_buf);
            sh.update(partial_buf);
            qty_written += partial_buf.len();
        }
    }

    /// Over-read the internal partial-block input buffer with uninteresting data
    /// several times, using no read greater than than its output block size.
    fn overread_sh(sh_reader: &mut Shake256Reader, buf: &mut [u8], rng: &mut XorShiftRng) {
        let mut qty_was_read = 0;
        while qty_was_read < OVERWRITE_LEN {
            let partial_buf = random_subslice(rng, buf);
            sh_reader.read(partial_buf);
            rng.fill_bytes(partial_buf);
            qty_was_read += partial_buf.len();
        }
    }

    // Write uninteresting data to shake256.
    overwrite_sh(shake256, uninteresting_buf, notsecret_rng);

    // Create another shake256 and write uninteresting data to it.
    let mut uninteresting_shake256 = Shake256::default();
    overwrite_sh(
        &mut uninteresting_shake256,
        uninteresting_buf,
        notsecret_rng,
    );

    // Replace shake256 and write more uninteresting data to it.
    shake256.clone_from(&uninteresting_shake256);
    overwrite_sh(shake256, uninteresting_buf, notsecret_rng);

    // Replace shake256reader and extract data from it.
    shake256reader.clone_from(&uninteresting_shake256.finalize_xof_reset());
    overread_sh(shake256reader, uninteresting_buf, notsecret_rng);

    // Derive a u64 from the resulting buffer and, with negligible probablility,
    // yield the thread for negligible time.
    #[allow(clippy::unwrap_used)]
    {
        let mut u = 0u64;
        let mut aby = [0u8; 8];
        for chunk in uninteresting_buf.chunks_exact(aby.len()) {
            // Unwrap() is justified here because we requested chunks exact of the same len.
            aby = chunk.try_into().unwrap();
            u ^= u64::from_le_bytes(aby);
        }
        if u == 0 {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::num::NonZeroUsize;

    use anyhow::Result;
    use num_bigint::BigUint;
    use num_traits::One;
    use rand::prelude::Distribution;

    use super::{Csprng, CsprngBuilder};

    #[test]
    fn test_csprng_consts() {
        // The bit quantities match the spec.
        assert_eq!(Csprng::permutation_bits(), 1600);
        assert_eq!(Csprng::rate_bits(), 1088);
        assert_eq!(Csprng::capacity_bits(), 512);

        // The byte quantites match the bit quantities.
        assert_eq!(Csprng::permutation_bits(), Csprng::permutation_bytes() * 8);
        assert_eq!(Csprng::rate_bits(), Csprng::rate_bytes() * 8);
        assert_eq!(Csprng::capacity_bits(), Csprng::capacity_bytes() * 8);

        // The max seed entropy bytes is not less than the internal width.
        assert!(Csprng::permutation_bytes() <= Csprng::max_entropy_seed_bytes());
    }

    #[test]
    fn test_csprng_builder() {
        let mut csprng = Csprng::build()
            .write_u64(0x_12345678_90ABCDEF_u64)
            .write_bytes(b"this can be a slice")
            .write_seq_bytes([
                b"wow look".as_slice(),
                b"a sequence".as_slice(),
                b"of slices".as_slice(),
            ])
            .finish();

        assert_eq!(csprng.next_u64(), 8717361090630221184);
    }

    #[allow(clippy::bool_assert_comparison)]
    #[test]
    fn csprng_new_default_equivalence() {
        let a = CsprngBuilder::default().finish().next_u128();
        assert_ne!(a, 0);
        let b = Csprng::build().finish().next_u128();
        assert_eq!(a, b);
        let c = Csprng::default().next_u128();
        assert_eq!(a, c);
    }

    #[allow(clippy::bool_assert_comparison)]
    #[test]
    fn csprng_initialization_effects() {
        let a = Csprng::build().write_bytes(b"").finish().next_u128();
        let b = Csprng::build().finish().next_u128();
        assert_ne!(
            a, b,
            "Writing a 'bytes' of length 0 is different from not having written one at all."
        );

        let a = Csprng::build().write_bytes(b"a").finish().next_u128();
        let b = Csprng::build().write_bytes(b"b").finish().next_u128();
        assert_ne!(a, b, "Writing two different 'bytes'es is different.");

        let a = Csprng::build().write_str("").finish().next_u128();
        let b = Csprng::build().finish().next_u128();
        assert_ne!(
            a, b,
            "Writing a 'str' of length 0 is different from not having written one at all."
        );

        let a = Csprng::build().write_str("a").finish().next_u128();
        let b = Csprng::build().write_str("b").finish().next_u128();
        assert_ne!(a, b, "Writing two different 'str's is different.");

        let a = Csprng::build().write_bytes(b"a").finish().next_u128();
        let b = Csprng::build().write_str("b").finish().next_u128();
        assert_ne!(
            a, b,
            "Writing a 'bytes' and a 'str' with the same value is the same."
        );

        let a = Csprng::build().write_u64(0_u64).finish().next_u128();
        let b = Csprng::build().write_u64(1_u64).finish().next_u128();
        assert_ne!(a, b, "Writing two different 'u64's is different.");
    }

    #[test]
    fn next_biguint() -> Result<()> {
        let csprng = &mut Csprng::from_seed_bytes(b"t::next_biguint");
        for bits in 1..100 {
            //? let j = csprng.next_biguint(NonZeroUsize::new(bits).unwrap());
            let j = csprng.next_biguint(bits.try_into()?);
            assert!(j < (BigUint::one() << bits));
        }
        Ok(())
    }

    #[test]
    fn next_biguint_requiring_bits() {
        let csprng = &mut Csprng::from_seed_bytes(b"t::next_biguint_requiring_bits");
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
        let csprng = &mut Csprng::from_seed_bytes(b"t::next_biguint_lt");
        for end in 1usize..100 {
            let end: BigUint = end.into();
            let j = csprng.next_biguint_lt(&end).unwrap();
            //dbg!((&j, &end));
            assert!(j < end);
        }
    }

    #[test]
    fn next_biguint_range() {
        let csprng = &mut Csprng::from_seed_bytes(b"t::next_biguint_range");
        for start_usize in 0usize..100 {
            let start: BigUint = start_usize.into();
            for end in start_usize + 1..101 {
                let end: BigUint = end.into();
                let j = csprng.next_biguint_range(&start, &end).unwrap();
                assert!(start <= j && j < end);
            }
        }
    }

    #[test]
    fn test_csprng_rand_rngcore() {
        let csprng = &mut Csprng::from_seed_bytes(b"t::test_csprng_rand_rngcore");

        let n: u64 = rand::distr::StandardUniform.sample(csprng);
        assert_eq!(n, 9005870331027573340, "actual (left) != (right) expected");
    }

    #[test]
    fn into_array() {
        let csprng = Csprng::default();
        let arr_builders = <[CsprngBuilder; 8]>::from(csprng);
        for builder in arr_builders {
            let mut csprng = builder.finish();
            assert_ne!(csprng.next_u128(), 0, "Unlikely");
        }

        for mut csprng in <[Csprng; 8]>::from(Csprng::default()) {
            assert_ne!(csprng.next_u128(), 0, "Unlikely");
        }
    }
}
