//! Explicit step-by-step PLONK + GWC verifier for the SHA-256 preimage proof.
//!
//! This file documents the full verification protocol so that it can be
//! re-implemented in another language.  Every logical protocol step is a
//! separate function whose name, arguments, and return value correspond to
//! the mathematical objects involved.
//!
//! Run `cargo run --example sha_preimage` first to generate the artifact files.
//!
//! # Transcript protocol (Blake2b-512)
//!
//! ```text
//! key     = b"Domain separator for transcript"
//! absorb  : state.update(&[0x01]); state.update(data)
//! squeeze : state.update(&[0x00]); output = state.finalize()  (64 bytes)
//! to_fq   : Fq::from_uniform_bytes(&output[..64])
//! ```
//!
//! G1 commitments are absorbed as 48-byte compressed encodings.
//! Fq elements are absorbed as 32-byte little-endian canonical encodings.

use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};
use midnight_curves::{
    pairing::{MillerLoopResult, MultiMillerLoop},
    Bls12, Fq, G1Projective, G2Affine, G2Prepared, G2Projective,
};
use midnight_proofs::{
    plonk::{parse_trace, prepare_with_gwc_data_from_trace, VerifierTrace, VerifyingKey},
    poly::kzg::{msm::DualMSM, GwcOpeningData, KZGCommitmentScheme},
    transcript::{CircuitTranscript, Transcript},
    utils::SerdeFormat,
};
use midnight_zk_stdlib::MidnightVK;
use std::fs;

// ── Top-level driver ─────────────────────────────────────────────────────────

fn main() {
    println!("=== SHA-256 Preimage Proof — Explicit Step-by-Step Verifier ===\n");

    let (proof_bytes, vk_bytes, params_bytes, instance_bytes) = step0_load_artifacts();
    let pi = step1_format_public_inputs(&instance_bytes);
    let (s_g2_prepared, neg_g2_prepared) = step2_parse_s_g2(&params_bytes);
    let midnight_vk = step3_load_vk(&vk_bytes);
    let vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>> = midnight_vk.vk();

    let (trace, mut transcript) =
        step4_parse_plonk_trace(vk, &proof_bytes, &pi);

    let gwc = step5_verify_plonk_constraints_and_gwc(
        vk,
        trace,
        &pi,
        &mut transcript,
    );

    step6_pairing_check(&gwc, &s_g2_prepared, &neg_g2_prepared);

    println!("\nProof verified! The prover knows a 24-byte preimage whose");
    println!("SHA-256 hash matches the 32 public field elements.");
}

// ── Step 0 ───────────────────────────────────────────────────────────────────

/// Load the four artifact files written by `sha_preimage.rs`.
fn step0_load_artifacts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let proof = fs::read("examples/assets/sha_preimage_proof.bin")
        .expect("run sha_preimage first");
    let vk = fs::read("examples/assets/sha_preimage_vk.bin")
        .expect("run sha_preimage first");
    let params = fs::read("examples/assets/sha_preimage_verifier_params.bin")
        .expect("run sha_preimage first");
    let instance = fs::read("examples/assets/sha_preimage_instance.bin")
        .expect("run sha_preimage first");

    println!(
        "Step 0: proof={} B, vk={} B, params={} B, instance={} B",
        proof.len(), vk.len(), params.len(), instance.len()
    );
    (proof, vk, params, instance)
}

// ── Step 1 ───────────────────────────────────────────────────────────────────

/// Format raw instance bytes as field elements.
///
/// `ShaPreImageCircuit::format_instance` maps each SHA-256 output byte `b`
/// to `Fq::from(b as u64)`.  The 32 hash bytes become 32 field elements.
fn step1_format_public_inputs(instance_bytes: &[u8]) -> Vec<Fq> {
    assert_eq!(instance_bytes.len(), 32, "expected 32 instance bytes");
    let pi: Vec<Fq> = instance_bytes.iter().map(|b| Fq::from(*b as u64)).collect();
    println!(
        "Step 1: {} public inputs (SHA-256 hash bytes as Fq elements)",
        pi.len()
    );
    pi
}

// ── Step 2 ───────────────────────────────────────────────────────────────────

/// Decode the verifier parameters and build the two G2Prepared objects used in
/// the final pairing.
///
/// `ParamsVerifierKZG::write(Processed)` serialises exactly one compressed G2
/// point: `s_g2 = [secret]·G₂` from the Filecoin trusted setup (96 bytes).
///
/// The pairing equation is:
///
/// ```text
/// e(π, [s]G₂) · e(final_com + x₃·π − v·G₁, −G₂)  =  1_{GT}
/// ```
fn step2_parse_s_g2(params_bytes: &[u8]) -> (G2Prepared, G2Prepared) {
    const G2_COMPRESSED_BYTES: usize = 96;
    assert_eq!(
        params_bytes.len(),
        G2_COMPRESSED_BYTES,
        "verifier params should be exactly {} bytes (one compressed G2 point)",
        G2_COMPRESSED_BYTES
    );

    let mut repr = <G2Projective as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(params_bytes);
    let s_g2: G2Projective =
        Option::from(G2Projective::from_bytes(&repr)).expect("invalid s_g2 encoding");

    let s_g2_prepared = G2Prepared::from(s_g2.to_affine());
    let neg_g2_prepared = G2Prepared::from(-G2Affine::generator());

    println!(
        "Step 2: s_g2 parsed from {} bytes; G2Prepared objects ready",
        G2_COMPRESSED_BYTES
    );
    (s_g2_prepared, neg_g2_prepared)
}

// ── Step 3 ───────────────────────────────────────────────────────────────────

/// Load the verifying key.
///
/// `MidnightVK` on disk (Processed format):
/// ```text
/// ZkStdLibArch   (chip-enable bitmask)
/// k              (1 byte: log₂ of domain size)
/// nb_public_inputs (4 bytes LE)
/// VerifyingKey {
///   version byte
///   k byte
///   num_fixed_commitments (4 bytes LE)
///   fixed_commitments[]   (48 bytes each, compressed G1)
///   permutation_commitments[]
/// }
/// ```
///
/// The inner `VerifyingKey` stores `transcript_repr : Fq` — a Blake2b-Halo2
/// hash of the circuit description that is the first value absorbed into the
/// proof transcript.
fn step3_load_vk(vk_bytes: &[u8]) -> MidnightVK {
    let midnight_vk =
        MidnightVK::read(&mut &vk_bytes[..], SerdeFormat::Processed)
            .expect("failed to read VK");
    let vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>> = midnight_vk.vk();
    println!(
        "Step 3: VK loaded — domain n = 2^{} = {} rows",
        vk.n().ilog2(),
        vk.n()
    );
    midnight_vk
}

// ── Step 4 ───────────────────────────────────────────────────────────────────

/// Parse the proof transcript up to (and including) the `y` challenge.
///
/// `parse_trace` absorbs/reads from the transcript in this order:
///
/// (a) `vk.transcript_repr` (32 B) — Blake2b-Halo2 hash of the VK
/// (b) committed-instance commitment: `G1::identity()` (48 B)
/// (c) instance length (32 B) + each of the 32 public inputs (32 B each)
/// (d) for each advice column in each phase: read G1 commitment (48 B);
///     for each circuit challenge in each phase: squeeze → `challenges[i]`
/// (e) squeeze → `theta`  (lookup column independence)
/// (f) for each lookup: read permuted_input_com (48 B), permuted_table_com (48 B)
/// (g) squeeze → `beta`, squeeze → `gamma`  (permutation/lookup product)
/// (h) for each permutation chunk: read product_commitment (48 B)
/// (i) for each lookup: read product_commitment (48 B)
/// (j) squeeze → `trash_challenge`  (trashcan argument; no trashcans in SHA)
/// (k) read vanishing random_poly_commitment (48 B)
/// (l) squeeze → `y`  (gate-linearity challenge)
fn step4_parse_plonk_trace<'a>(
    vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    proof_bytes: &[u8],
    pi: &[Fq],
) -> (
    VerifierTrace<Fq, KZGCommitmentScheme<Bls12>>,
    CircuitTranscript<blake2b_simd::State>,
) {
    let committed_pi = G1Projective::identity();
    let pi_slice: &[Fq] = pi;
    let mut transcript =
        CircuitTranscript::<blake2b_simd::State>::init_from_bytes(proof_bytes);

    let trace = parse_trace::<Fq, KZGCommitmentScheme<Bls12>, _>(
        vk,
        &[&[committed_pi]],
        &[&[pi_slice]],
        &mut transcript,
    )
    .expect("parse_trace failed");

    // ── Fiat-Shamir challenges squeezed during parse_trace ────────────────
    let theta = trace.theta();
    let beta  = trace.beta();
    let gamma = trace.gamma();
    let y     = trace.y();
    let trash = trace.trash_challenge();
    let chs   = trace.challenges();
    let advice_coms = trace.advice_commitments();

    println!("Step 4: Fiat-Shamir challenges from parse_trace:");
    println!("  theta          = {theta:?}  (lookup column independence)");
    println!("  beta           = {beta:?}  (permutation/lookup product, 1st)");
    println!("  gamma          = {gamma:?}  (permutation/lookup product, 2nd)");
    println!("  y              = {y:?}  (gate-linearity)");
    println!("  trash_challenge= {trash:?}  (trashcan arg)");
    println!("  circuit challenges: {} element(s)", chs.len());
    let total_advice: usize = advice_coms.iter().map(|v| v.len()).sum();
    println!("  advice commitments read: {total_advice} G1 point(s)");

    (trace, transcript)
}

// ── Step 5 ───────────────────────────────────────────────────────────────────

/// Verify algebraic constraints and run the GWC multi-open protocol.
///
/// This step has two logical sub-phases:
///
/// ## Sub-phase A — verify_algebraic_constraints
///
/// (m) read h_com[0..degree-1] from proof, absorb each (48 B each)
///     (quotient polynomial pieces)
/// (n) squeeze → `x`  (random evaluation point); compute `xn = x^n`
/// (o) compute instance evals at x via Lagrange interpolation:
///       `l_i(x) = (x^n − 1) / (n · (x − ω^i))`
///       `instance_eval = Σ_i pi_i · l_i(x)`
/// (p) read advice_evals (32 B each), fixed_evals (32 B each)
/// (q) read vanishing random_eval, permutation_evals, lookup_evals
/// (r) call `evaluate_identities`: verify `h(x) = expected / (x^n − 1)`
/// (s) build `VerifierQuery` list (advice, fixed, permutation, lookup,
///     vanishing commitments evaluated at appropriate rotations of x)
///
/// ## Sub-phase B — GWC multi-open  (gwc_multi_open_explicit)
///
/// (t) squeeze → `x1`, `x2`  (commitment-batching randomness)
///     group queries by evaluation-point set; combine with x1 powers → q_com_i
/// (u) read `f_com` (batched quotient commitment, 48 B)
/// (v) squeeze → `x3`  (final evaluation point)
///     read `q_eval_i(x3)` for each point set (32 B each)
///     compute `f_eval` via Lagrange interpolation over point sets:
///       `r_poly_i = lagrange_interpolate(points_i, evals_i)`
///       `eval_i = (q_eval_i − r_poly_i(x3)) / Π_j (x3 − point_j)`
///       `f_eval = Σ_i x2^i · eval_i`
/// (w) squeeze → `x4`  (final batching randomness)
///     `final_com = Σ_i x4^i · q_com_i + x4^|sets| · f_com`
///     `v = Σ_i x4^i · q_eval_i + x4^|sets| · f_eval`
/// (x) read `π` (KZG opening proof, 48 B)
///     `left  = π`
///     `right = final_com + x3·π − v·G₁`
fn step5_verify_plonk_constraints_and_gwc(
    vk: &VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    trace: VerifierTrace<Fq, KZGCommitmentScheme<Bls12>>,
    pi: &[Fq],
    transcript: &mut CircuitTranscript<blake2b_simd::State>,
) -> GwcOpeningData<Bls12> {
    let committed_pi = G1Projective::identity();
    let pi_slice: &[Fq] = pi;

    let (_dual_msm, gwc): (DualMSM<Bls12>, GwcOpeningData<Bls12>) =
        prepare_with_gwc_data_from_trace::<Fq, Bls12, _>(
            vk,
            trace,
            &[&[committed_pi]],
            &[&[pi_slice]],
            transcript,
        )
        .expect("PLONK protocol failed: algebraic constraints not satisfied");

    transcript.assert_empty().expect("proof has unexpected trailing bytes");

    // ── Display all named GWC intermediate values ─────────────────────────
    println!("Step 5: PLONK + GWC protocol complete");
    println!("  GWC challenges:");
    println!("    x1 = {:?}  (batches coms at same eval point)", gwc.x1);
    println!("    x2 = {:?}  (batches across point sets)", gwc.x2);
    println!("    x3 = {:?}  (random eval point for f-poly check)", gwc.x3);
    println!("    x4 = {:?}  (final batching randomness)", gwc.x4);
    println!("  f_com    = {:?}  (prover's aux commitment, read from proof)", gwc.f_com);
    println!(
        "  q_evals_on_x3: {} value(s) (prover's q_i(x3), read from proof)",
        gwc.q_evals_on_x3.len()
    );
    for (i, e) in gwc.q_evals_on_x3.iter().enumerate() {
        println!("    q_eval[{i}](x3) = {e:?}");
    }
    println!("  f_eval   = {:?}  (verifier-computed f(x3) via Lagrange)", gwc.f_eval);
    println!(
        "  v        = {:?}  (= Σ x4^i·q_eval_i + x4^|sets|·f_eval)",
        gwc.v
    );
    println!("  pi       = {:?}  (KZG opening proof, read from proof)", gwc.pi);
    println!(
        "  final_com_g1 = {:?}  (= Σ x4^i·q_com_i + x4^|sets|·f_com)",
        gwc.final_com_g1
    );
    println!("  left_g1  = {:?}  (= π)", gwc.left_g1);
    println!("  right_g1 = {:?}  (= final_com + x3·π − v·G₁)", gwc.right_g1);

    gwc
}

// ── Step 6 ───────────────────────────────────────────────────────────────────

/// BLS12-381 pairing check.
///
/// The KZG opening reduces to:
///
/// ```text
/// e(left, [s]G₂) · e(right, −G₂)  =  1_{GT}
/// ```
///
/// where `left = π` and `right = final_com + x₃·π − v·G₁`.
fn step6_pairing_check(
    gwc: &GwcOpeningData<Bls12>,
    s_g2_prepared: &G2Prepared,
    neg_g2_prepared: &G2Prepared,
) {
    let left  = gwc.left_g1;   // = π
    let right = gwc.right_g1;  // = final_com + x3·π − v·G₁

    println!("Step 6: pairing check  e(left, [s]G₂) · e(right, −G₂) = 1_{{GT}}");

    let result = Bls12::multi_miller_loop(&[
        (&left.to_affine(),  s_g2_prepared),
        (&right.to_affine(), neg_g2_prepared),
    ])
    .final_exponentiation();

    assert!(
        bool::from(result.is_identity()),
        "PAIRING CHECK FAILED — proof is invalid"
    );

    println!("Step 6: pairing identity confirmed  ✓");
}
