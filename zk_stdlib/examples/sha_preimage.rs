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
    plonk::{Error, VerifyingKey},
    poly::kzg::KZGCommitmentScheme,
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

fn dump_circuit_constants(vk: &VerifyingKey<midnight_curves::Fq, KZGCommitmentScheme<midnight_curves::Bls12>>) {
    use ff::PrimeField;
    println!("\n=== Circuit Constants (for sha_preimage_verify_manual.rs) ===");

    let repr = vk.transcript_repr().to_repr();
    let bytes: &[u8] = repr.as_ref();
    println!("TRANSCRIPT_REPR: [u8; 32] = {:?};", bytes);

    let cs = vk.cs();
    println!("N_ADVICE_COLS: usize = {};", cs.num_advice_columns());
    println!("ADVICE_PHASES: &[u8] = &{:?};", cs.advice_column_phase());
    println!("N_CHALLENGES: usize = {};", cs.num_challenges());
    println!("CHALLENGE_PHASES: &[u8] = &{:?};", cs.challenge_phase());
    println!("N_LOOKUPS: usize = {};", cs.lookups().len());

    let n_perm_cols = vk.permutation().commitments().len();
    println!("N_PERM_COLS: usize = {};", n_perm_cols);

    let cs_degree = cs.degree();
    println!("CS_DEGREE: usize = {};", cs_degree);

    let chunk_len = cs_degree - 2;
    let perm_arg_cols = cs.permutation().get_columns().len();
    let n_perm_products = (perm_arg_cols + chunk_len - 1) / chunk_len;
    println!("N_PERM_PRODUCTS: usize = {}; // chunk_len={}, perm_arg_cols={}", n_perm_products, chunk_len, perm_arg_cols);

    println!("N_ADVICE_QUERIES: usize = {};", cs.advice_queries().len());
    println!("N_FIXED_QUERIES: usize = {};", cs.fixed_queries().len());
    println!("N_INSTANCE_QUERIES: usize = {};", cs.instance_queries().len());
    println!("BLINDING_FACTORS: usize = {};", cs.blinding_factors());
    println!("N_FIXED_COLS: usize = {};", vk.fixed_commitments().len());

    let advice_rotations: Vec<i32> = cs.advice_queries().iter().map(|(_, r)| r.0).collect();
    println!("ADVICE_ROTATIONS: &[i32] = &{:?};", advice_rotations);

    let advice_col_indices: Vec<usize> = cs.advice_queries().iter().map(|(c, _)| c.index()).collect();
    println!("ADVICE_COL_INDICES: &[usize] = &{:?};  // which column each advice query references", advice_col_indices);

    let fixed_rotations: Vec<i32> = cs.fixed_queries().iter().map(|(_, r)| r.0).collect();
    println!("FIXED_ROTATIONS: &[i32] = &{:?};", fixed_rotations);

    let fixed_col_indices: Vec<usize> = cs.fixed_queries().iter().map(|(c, _)| c.index()).collect();
    println!("FIXED_COL_INDICES: &[usize] = &{:?};", fixed_col_indices);

    let instance_rotations: Vec<i32> = cs.instance_queries().iter().map(|(_, r)| r.0).collect();
    println!("INSTANCE_ROTATIONS: &[i32] = &{:?};", instance_rotations);

    let instance_col_indices: Vec<usize> = cs.instance_queries().iter().map(|(c, _)| c.index()).collect();
    println!("INSTANCE_COL_INDICES: &[usize] = &{:?};", instance_col_indices);

    // Print per-column rotation sets (for understanding GWC point sets)
    println!("--- Advice column rotation sets (column -> set of rotations) ---");
    let mut col_rotations: std::collections::BTreeMap<usize, std::collections::BTreeSet<i32>> = Default::default();
    for (col, rot) in cs.advice_queries() {
        col_rotations.entry(col.index()).or_default().insert(rot.0);
    }
    for (col, rots) in &col_rotations {
        println!("  advice col {} -> rotations {:?}", col, rots.iter().cloned().collect::<Vec<_>>());
    }

    println!("=== End Circuit Constants ===\n");
}

fn main() {
    const K: u32 = 13;
    let srs = filecoin_srs(K);

    let relation = ShaPreImageCircuit;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    dump_circuit_constants(vk.vk());
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    // Use "hello world" as the preimage, zero-padded to 24 bytes.
    let mut witness = [0u8; 24];
    let preimage = b"hello world";
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
