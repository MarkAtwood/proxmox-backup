//! SHA helpers.
//!
//! SHA-256 goes through OpenSSL's EVP interface, so whichever provider OpenSSL is configured with
//! computes it. `openssl::sha::Sha256` calls OpenSSL's low-level `SHA256_Update`, which always
//! runs libcrypto's built-in code and is never dispatched to a provider.

use std::io::Read;

use anyhow::Error;
use openssl::hash::{Hasher, MessageDigest};

use proxmox_io::vec;

const EVP_SHA256_FAILED: &str =
    "OpenSSL could not compute SHA-256: no provider supplies it, or the provider is in an error state";

/// Streaming SHA-256 with the interface of `openssl::sha::Sha256`, computed through EVP.
///
/// # Panics
///
/// When OpenSSL cannot compute SHA-256, because no loaded provider implements it or the provider
/// is in an error state (a FIPS module after a failed self-test). The built-in code this replaces
/// cannot fail, so callers have no error path, and a digest that was not computed must not be
/// used. `CryptConfig::compute_auth_tag` handles a failing EVP HMAC the same way.
#[derive(Clone)]
pub struct Sha256(Hasher);

impl Sha256 {
    pub fn new() -> Self {
        Self(Hasher::new(MessageDigest::sha256()).expect(EVP_SHA256_FAILED))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect(EVP_SHA256_FAILED);
    }

    pub fn finish(mut self) -> [u8; 32] {
        let digest = self.0.finish().expect(EVP_SHA256_FAILED);
        <[u8; 32]>::try_from(&*digest).expect("SHA-256 digest is 32 bytes")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 of `data`, computed through EVP. Panics like [`Sha256`].
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

/// Calculate the sha256sum from a readable object.
pub fn sha256(file: &mut dyn Read) -> Result<([u8; 32], u64), Error> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    let mut buffer = vec::undefined(256 * 1024);
    let mut size: u64 = 0;

    loop {
        let count = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        size += count as u64;
        hasher.update(&buffer[..count])?;
    }

    let csum = <[u8; 32]>::try_from(&*hasher.finish()?)?;

    Ok((csum, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-2 appendix B.1 and B.2 test vectors.
    const ABC: &[u8] = b"abc";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const TWO_BLOCK: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const TWO_BLOCK_SHA256: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    #[test]
    fn one_shot_matches_fips_180_vectors() {
        assert_eq!(hex::encode(sha256_digest(ABC)), ABC_SHA256);
        assert_eq!(hex::encode(sha256_digest(TWO_BLOCK)), TWO_BLOCK_SHA256);
    }

    #[test]
    fn streaming_in_pieces_matches_fips_180_vector() {
        let mut hasher = Sha256::new();
        for piece in TWO_BLOCK.chunks(7) {
            hasher.update(piece);
        }
        assert_eq!(hex::encode(hasher.finish()), TWO_BLOCK_SHA256);
    }

    #[test]
    fn clone_continues_independently() {
        // both vectors start with "ab"
        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        let mut copy = hasher.clone();
        hasher.update(b"c");
        copy.update(&TWO_BLOCK[2..]);
        assert_eq!(hex::encode(hasher.finish()), ABC_SHA256);
        assert_eq!(hex::encode(copy.finish()), TWO_BLOCK_SHA256);
    }

    #[test]
    fn reader_matches_fips_180_vector() {
        let (csum, size) = sha256(&mut &TWO_BLOCK[..]).unwrap();
        assert_eq!(hex::encode(csum), TWO_BLOCK_SHA256);
        assert_eq!(size, TWO_BLOCK.len() as u64);
    }
}
