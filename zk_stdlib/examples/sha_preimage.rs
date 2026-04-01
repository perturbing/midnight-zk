//! Examples on how to perform sha256 operations using midnight_lib.
//!
//! In this example we show how to build a circuit for proving the knowledge of
//! a SHA256 preimage. Concretely, given public input x, we will argue that we
//! know w ∈ {0,1}^192 such that x = SHA-256(w).

#[cfg(feature = "heap_profiling")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use midnight_circuits::{
    instructions::{AssignmentInstructions, PublicInputInstructions},
    types::{AssignedByte, Instantiable},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::rngs::OsRng;
use sha2::Digest;

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
pub struct ShaPreImageCircuit;

impl Relation for ShaPreImageCircuit {
    type Instance = [u8; 32];

    type Witness = [u8; 24]; // 192 = 24 * 8

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(instance.iter().flat_map(AssignedByte::<F>::as_public_input).collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let witness_bytes = witness.transpose_array();
        let assigned_input = std_lib.assign_many(layouter, &witness_bytes)?;
        let output = std_lib.sha2_256(layouter, &assigned_input)?;
        output.iter().try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(ShaPreImageCircuit)
    }
}

fn main() {
    const K: u32 = 13;
    let srs = filecoin_srs(K);

    let relation = ShaPreImageCircuit;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    // Use "hello world" as the preimage, zero-padded to 24 bytes.
    let mut witness = [0u8; 24];
    let preimage = b"hello worl";
    witness[..preimage.len()].copy_from_slice(preimage);

    let instance: [u8; 32] = sha2::Sha256::digest(witness).into();
    println!("input  = {:?}", String::from_utf8_lossy(&witness));
    println!("input  = {}", witness.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("SHA-256 = {}", instance.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let proof = midnight_zk_stdlib::prove::<ShaPreImageCircuit, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, witness, OsRng,
    )
    .expect("Proof generation should not fail");

    // Write artifacts to disk so sha_preimage_verify_manual can load them.
    {
        use midnight_proofs::utils::SerdeFormat;
        use std::fs;

        let dir = "examples/assets";
        fs::write(format!("{dir}/sha_preimage_proof.bin"), &proof)
            .expect("failed to write proof");

        let mut f = fs::File::create(format!("{dir}/sha_preimage_vk.bin"))
            .expect("failed to create vk file");
        vk.write(&mut f, SerdeFormat::Processed).expect("failed to write vk");

        // verifier_params() serialises as a single compressed G2 point (96 bytes).
        let mut f = fs::File::create(format!("{dir}/sha_preimage_verifier_params.bin"))
            .expect("failed to create verifier params file");
        srs.verifier_params()
            .write(&mut f, SerdeFormat::Processed)
            .expect("failed to write verifier params");

        // Raw 32-byte SHA-256 hash (public instance).
        fs::write(format!("{dir}/sha_preimage_instance.bin"), &instance)
            .expect("failed to write instance");

        println!("Artifacts written to {dir}/sha_preimage_{{proof,vk,verifier_params,instance}}.bin");
    }

    assert!(
        midnight_zk_stdlib::verify::<ShaPreImageCircuit, blake2b_simd::State>(
            &srs.verifier_params(),
            &vk,
            &instance,
            None,
            &proof
        )
        .is_ok()
    )
}
