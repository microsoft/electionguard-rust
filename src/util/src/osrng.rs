// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![allow(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use tracing::error;

use crate::csprng::Csprng;

//=================================================================================================|
/// Read the data from the OS RNG for purposes of seeding.
///
/// Panics if the requested amount of data is not available.
///
/// The minimum request is 32 bytes (256 bits).
///
/// `OsRng` is implemented by the `getrandom` crate, which describes itself as an "Interface to
/// the operating system's random number generator."
///
/// On Linux, this uses the `getrandom` system call
/// https://man7.org/linux/man-pages/man2/getrandom.2.html
///
/// On Windows, this uses the `BCryptGenRandom` function
/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
///
pub fn get_osrng_data_for_seeding<const N: usize>(seed_buf: &mut [u8; N]) {
    //? TODO someday Rust will allow us to say: static_assertions::const_assert!(32 <= N);
    const {
        let bits_requested_minimum = 256_usize;

        let pad_bytes_worst_case = std::mem::align_of::<[u8; N]>() - 1;
        let bytes_requested_low_estimate = std::mem::size_of::<[u8; N]>() - pad_bytes_worst_case;
        let bits_requested_low_estimate = bytes_requested_low_estimate * 8;

        // Note that this is a compile-time panic.
        #[allow(clippy::manual_assert)]
        if bits_requested_low_estimate < bits_requested_minimum {
            panic!(
                "get_osrng_data_for_seeding() is requesting less than the required minimum 256 bits."
            );
        }
    };

    let zero_buf = [0u8; N];

    *seed_buf = zero_buf;

    let result = getrandom::fill(seed_buf);

    // This is a rare case worth panicking on.
    #[allow(clippy::panic)]
    if let Err(e) = result {
        let e = format!(
            "Couldn't read {} bytes from the OS RNG: {e}",
            zero_buf.len()
        );
        error!("{e}");
        panic!("{e}");
    }

    // We can't defend against a faulty OS RNG, but we can at least do a simple sanity check for an
    // unmodified or zeroed buffer resulting from one possible failure mode.
    {
        let customization = b"Sanity check for OS RNG";
        let prng_from_os = &mut Csprng::build()
            .write_bytes(seed_buf)
            .write_bytes(customization)
            .finish();
        let prng_zero_buf = &mut Csprng::build()
            .write_bytes(zero_buf)
            .write_bytes(customization)
            .finish();

        let cnt_64bit_comparisons = 512 / 64;

        let mut diff = 0_u64;
        for _ in 0..cnt_64bit_comparisons {
            diff |= prng_from_os.next_u64() ^ prng_zero_buf.next_u64();
        }

        // This is a rare case worth panicking on.
        #[allow(clippy::panic)]
        if diff == 0 {
            let e = format!(
                "The OS secure random number generator has produced {} consecutive zero-valued bytes. This is an error.",
                zero_buf.len()
            );
            error!("{e}");
            panic!("{e}");
        }
    }
}
