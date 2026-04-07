//! Accumulation-based Blake2b-256 transcript for Plutus on-chain compatibility.
//!
//! Absorption accumulates all transcript data in a `Vec<u8>`.  Squeezing calls
//! keyless Blake2b-256 twice with a single domain-separation byte prepended (0
//! and 1), concatenating the two 32-byte outputs to obtain 64 bytes of entropy
//! for `Sampleable::sample`.
//!
//! On-chain (Plutus), each squeeze is exactly two `blake2b_256` built-in calls:
//! ```text
//! h1 = blake2b_256(0x00 ++ transcript_data)
//! h2 = blake2b_256(0x01 ++ transcript_data)
//! challenge_bytes = h1 ++ h2
//! ```

use std::{io, io::Read};

use blake2b_simd::Params;
use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use midnight_curves::{Fq, G1Projective};
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};

/// Keyless Blake2b-256 hash of `[prefix] ++ data`.
fn blake2b_256_with_prefix(data: &[u8], prefix: u8) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(prefix);
    input.extend_from_slice(data);
    let hash = Params::new().hash_length(32).to_state().update(&input).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Accumulation-based transcript using Blake2b-256, designed for Plutus
/// on-chain verifier compatibility.
#[derive(Clone, Debug)]
pub struct PlutusBlake2b {
    transcript_data: Vec<u8>,
}

impl TranscriptHash for PlutusBlake2b {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn init() -> Self {
        Self { transcript_data: vec![] }
    }

    fn absorb(&mut self, input: &Self::Input) {
        self.transcript_data.extend_from_slice(input);
    }

    fn squeeze(&mut self) -> Self::Output {
        let h1 = blake2b_256_with_prefix(&self.transcript_data, 0);
        let h2 = blake2b_256_with_prefix(&self.transcript_data, 1);
        [h1.as_slice(), h2.as_slice()].concat()
    }
}

impl Hashable<PlutusBlake2b> for G1Projective {
    fn to_input(&self) -> Vec<u8> {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as GroupEncoding>::Repr::default();
        buffer.read_exact(bytes.as_mut())?;
        Option::from(Self::from_bytes(&bytes))
            .ok_or_else(|| io::Error::other("Invalid BLS12-381 point encoding in proof"))
    }
}

impl Hashable<PlutusBlake2b> for Fq {
    fn to_input(&self) -> Vec<u8> {
        self.to_repr().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_repr().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as PrimeField>::Repr::default();
        buffer.read_exact(bytes.as_mut())?;
        Option::from(Self::from_repr(bytes))
            .ok_or_else(|| io::Error::other("Invalid BLS12-381 scalar encoding in proof"))
    }
}

impl Sampleable<PlutusBlake2b> for Fq {
    fn sample(hash_output: Vec<u8>) -> Self {
        assert!(hash_output.len() <= 64);
        assert!(hash_output.len() >= (Fq::NUM_BITS as usize / 8) + 12);
        let mut bytes = [0u8; 64];
        bytes[..hash_output.len()].copy_from_slice(&hash_output);
        Fq::from_uniform_bytes(&bytes)
    }
}
