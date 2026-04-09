//! Accumulation-based Blake2b-256 transcript for Plutus on-chain compatibility.
//!
//! Absorption accumulates all transcript data in a `Vec<u8>`.  Squeezing hashes
//! the accumulated transcript data with a single keyless Blake2b-256 call and
//! immediately extends the transcript state with the 32-byte output, so that
//! consecutive squeezes automatically produce distinct outputs through state
//! feedback rather than domain-separation prefix bytes.
//!
//! On-chain (Plutus), each squeeze is exactly one `blake2b_256` built-in call:
//! ```text
//! challenge_bytes = blake2b_256(transcript_data)
//! transcript_data = transcript_data ++ challenge_bytes
//! ```

use std::{io, io::Read};

use blake2b_simd::Params;
use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use midnight_curves::{Fq, G1Projective};
use midnight_proofs::transcript::{Hashable, Sampleable, TranscriptHash};

/// Keyless Blake2b-256 hash of `data`.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = Params::new().hash_length(32).to_state().update(data).finalize();
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
        let h = blake2b_256(&self.transcript_data);
        self.transcript_data.extend_from_slice(&h);
        h.to_vec()
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
        assert_eq!(hash_output.len(), 32);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash_output);
        Fq::from_uniform_bytes(&bytes)
    }
}
