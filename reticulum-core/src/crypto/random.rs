//! Functions that return arrays of random bytes.

/// Generate random bytes using the provided RNG
#[cfg(feature = "std")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::OsRng;
    let mut bytes = [0u8; N];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    bytes
}

/// Generate random bytes using a provided RNG (for no_std)
pub fn random_bytes_with_rng<R: rand_core::RngCore, const N: usize>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
