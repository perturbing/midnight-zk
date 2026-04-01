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
//!
//! # Circuit constants (SHA circuit with ZkStdLibArch { sha2_256: true }, K=13)
//!
//! These were extracted by running `sha_preimage.rs` with `dump_circuit_constants`.
//! They are fixed for this specific circuit configuration and hardcoded here.

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};
use midnight_curves::{
    pairing::{MillerLoopResult, MultiMillerLoop},
    Bls12, Fq, G1Projective, G2Affine, G2Prepared, G2Projective,
};
use midnight_proofs::{
    plonk::{parse_trace, prepare_with_gwc_data_from_trace},
    poly::kzg::GwcOpeningData,
    transcript::{CircuitTranscript, Transcript},
    utils::SerdeFormat,
};
use midnight_zk_stdlib::MidnightVK;
use std::fs;

// ── SHA circuit constants (hardcoded) ────────────────────────────────────────

/// Blake2b-Halo2 hash of the VK circuit description.
/// Absorbed first into every proof transcript.
const TRANSCRIPT_REPR: [u8; 32] = [
    183, 133, 103, 247, 105, 79, 107, 44, 128, 90, 72, 37, 41, 189, 60, 185,
    222, 30, 4, 122, 238, 112, 81, 155, 173, 169, 251, 185, 43, 87, 118, 32,
];

/// Domain size N = 2^K
const K: u32 = 13;
const N: u64 = 1 << K;

const CS_DEGREE: usize = 5;
const N_ADVICE_COLS: usize = 8;
const N_LOOKUPS: usize = 3;
const N_PERM_COLS: usize = 9;       // permutation sigma columns
const N_PERM_PRODUCTS: usize = 3;   // chunk_len=3, perm_arg_cols=9
const N_H_COMS: usize = CS_DEGREE - 1;  // 4 vanishing-quotient pieces
const N_ADVICE_QUERIES: usize = 24;
const N_FIXED_QUERIES: usize = 32;
const BLINDING_FACTORS: usize = 5;
const N_FIXED_COLS: usize = 32;

/// For each advice query (0..24): which column is queried.
/// Used to reconstruct per-column evaluation indices in the GWC q_eval_sets.
#[allow(dead_code)]
const ADVICE_COL_INDICES: &[usize] = &[0, 1, 2, 3, 4, 0, 1, 2, 5, 6, 7, 3, 4, 0, 1, 3, 4, 6, 6, 2, 7, 5, 5, 7];
/// For each advice query (0..24): rotation (0 = x, 1 = xω, -1 = xω⁻¹).
#[allow(dead_code)]
const ADVICE_ROTATIONS: &[i32] = &[0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, -1, -1, -1, -1, 1, 1, -1, 1, -1, -1, -1, 1, 1];
/// For each fixed query (0..32): which fixed column is queried (all at rotation 0).
const FIXED_COL_INDICES: &[usize] = &[9, 4, 5, 6, 7, 8, 0, 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

/// ZkStdLibArch header size at the start of the VK binary.
const ZKSTD_ARCH_BYTES: usize = 16;

// ── Transcript ────────────────────────────────────────────────────────────────

/// Blake2b-512 Fiat-Shamir sponge used in the PLONK proof system.
///
/// Absorb calls prefix data with 0x01; squeeze calls prefix with 0x00 before
/// finalizing the hash.  The key is "Domain separator for transcript".
struct ProofTranscript {
    state: blake2b_simd::State,
    proof: Vec<u8>,
    pos: usize,
}

impl ProofTranscript {
    fn new(proof: &[u8]) -> Self {
        let state = Blake2bParams::new()
            .hash_length(64)
            .key(b"Domain separator for transcript")
            .to_state();
        ProofTranscript { state, proof: proof.to_vec(), pos: 0 }
    }

    /// Absorb raw bytes: prefix with 0x01 then data.
    fn absorb(&mut self, data: &[u8]) {
        self.state.update(&[0x01]);
        self.state.update(data);
    }

    /// Absorb a 32-byte canonical Fq representation.
    fn absorb_fq(&mut self, x: &Fq) {
        self.absorb(x.to_repr().as_ref());
    }

    /// Absorb a compressed G1 point (48 bytes).
    fn absorb_g1(&mut self, pt: &G1Projective) {
        self.absorb(<G1Projective as GroupEncoding>::to_bytes(pt).as_ref());
    }

    /// Squeeze 64 bytes and convert to Fq via from_uniform_bytes.
    fn squeeze_fq(&mut self) -> Fq {
        self.state.update(&[0x00]);
        let out = self.state.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(out.as_bytes());
        Fq::from_uniform_bytes(&bytes)
    }

    /// Read 48 bytes from proof, absorb, and decode as G1.
    fn read_g1(&mut self) -> G1Projective {
        let mut buf = [0u8; 48];
        buf.copy_from_slice(&self.proof[self.pos..self.pos + 48]);
        self.pos += 48;
        self.absorb(&buf);
        let mut repr = <G1Projective as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&buf);
        Option::from(G1Projective::from_bytes(&repr)).expect("invalid G1 in proof")
    }

    /// Read 32 bytes from proof, absorb, and decode as Fq.
    fn read_fq(&mut self) -> Fq {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.proof[self.pos..self.pos + 32]);
        self.pos += 32;
        self.absorb(&buf);
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&buf);
        Option::from(Fq::from_repr(repr)).expect("invalid Fq in proof")
    }

    fn assert_empty(&self) {
        assert_eq!(self.pos, self.proof.len(), "proof has trailing bytes");
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute ω, the primitive 2^k-th root of unity for the BLS12-381 scalar field.
fn compute_omega(k: u32) -> Fq {
    // ROOT_OF_UNITY is the primitive 2^S-th root of unity (S = 32 for BLS12-381).
    // ω = ROOT_OF_UNITY ^ (2^(S-k))
    Fq::ROOT_OF_UNITY.pow_vartime([1u64 << (Fq::S - k)])
}

/// Lagrange interpolation at x3 given (points, evals) of the same length.
fn lagrange_eval(points: &[Fq], evals: &[Fq], x3: Fq) -> Fq {
    let n = points.len();
    if n == 1 {
        return evals[0];
    }
    (0..n)
        .map(|i| {
            let (num, den) = (0..n)
                .filter(|&j| j != i)
                .fold((Fq::ONE, Fq::ONE), |(num, den), j| {
                    (num * (x3 - points[j]), den * (points[i] - points[j]))
                });
            evals[i] * num * den.invert().unwrap()
        })
        .fold(Fq::ZERO, |a, b| a + b)
}

/// Compute Σ scalars[i] * bases[i] as a G1 multi-scalar multiplication.
fn msm(scalars: &[Fq], bases: &[G1Projective]) -> G1Projective {
    assert_eq!(scalars.len(), bases.len());
    scalars.iter().zip(bases.iter()).fold(G1Projective::identity(), |acc, (s, b)| acc + b * s)
}

/// Powers of `x`: [1, x, x², …, n elements].
fn powers(x: Fq, n: usize) -> Vec<Fq> {
    let mut out = Vec::with_capacity(n);
    let mut cur = Fq::ONE;
    for _ in 0..n {
        out.push(cur);
        cur *= x;
    }
    out
}

// ── Step 0 ────────────────────────────────────────────────────────────────────

fn load_artifacts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let proof = fs::read("examples/assets/sha_preimage_proof.bin").expect("run sha_preimage first");
    let vk    = fs::read("examples/assets/sha_preimage_vk.bin").expect("run sha_preimage first");
    let params = fs::read("examples/assets/sha_preimage_verifier_params.bin").expect("run sha_preimage first");
    let instance = fs::read("examples/assets/sha_preimage_instance.bin").expect("run sha_preimage first");
    println!("Step 0: proof={} B, vk={} B, params={} B, instance={} B",
        proof.len(), vk.len(), params.len(), instance.len());
    (proof, vk, params, instance)
}

// ── Step 1 ────────────────────────────────────────────────────────────────────

/// Each SHA-256 output byte becomes Fq::from(b as u64).
fn format_public_inputs(instance_bytes: &[u8]) -> Vec<Fq> {
    assert_eq!(instance_bytes.len(), 32);
    let pi: Vec<Fq> = instance_bytes.iter().map(|&b| Fq::from(b as u64)).collect();
    println!("Step 1: {} public inputs (SHA-256 hash bytes as Fq)", pi.len());
    pi
}

// ── Step 2 ────────────────────────────────────────────────────────────────────

/// Parse the 96-byte verifier params (one compressed G2 point: [s]G₂).
fn parse_s_g2(params_bytes: &[u8]) -> (G2Prepared, G2Prepared) {
    assert_eq!(params_bytes.len(), 96);
    let mut repr = <G2Projective as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(params_bytes);
    let s_g2: G2Projective = Option::from(G2Projective::from_bytes(&repr)).expect("invalid s_g2");
    println!("Step 2: s_g2 parsed; G2Prepared objects ready");
    (G2Prepared::from(s_g2.to_affine()), G2Prepared::from(-G2Affine::generator()))
}

// ── Step 3 ────────────────────────────────────────────────────────────────────

/// Parse fixed_commitments and permutation_commitments from the raw VK bytes.
///
/// VK binary layout (Processed format):
/// ```text
/// [ZkStdLibArch: 16 bytes]
/// [k: 1 byte]
/// [nb_public_inputs: 4 bytes LE]
/// [version: 1 byte = 0x03]
/// [k: 1 byte (repeated)]
/// [num_fixed: 4 bytes LE = 32]
/// [fixed_commitments: 32 × 48 bytes compressed G1]
/// [permutation_commitments: 9 × 48 bytes compressed G1]
/// ```
fn parse_vk_g1_commitments(vk_bytes: &[u8]) -> (Vec<G1Projective>, Vec<G1Projective>) {
    let fixed_start = ZKSTD_ARCH_BYTES + 1 + 4 + 1 + 1 + 4;  // = 27
    let perm_start  = fixed_start + N_FIXED_COLS * 48;         // = 1563

    let read_g1 = |off: usize| {
        let mut repr = <G1Projective as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&vk_bytes[off..off + 48]);
        Option::from(G1Projective::from_bytes(&repr)).expect("invalid G1 in VK")
    };

    let fixed_coms: Vec<G1Projective> = (0..N_FIXED_COLS).map(|i| read_g1(fixed_start + i * 48)).collect();
    let perm_coms:  Vec<G1Projective> = (0..N_PERM_COLS) .map(|i| read_g1(perm_start  + i * 48)).collect();

    println!("Step 3: parsed {} fixed G1 coms and {} perm-sigma G1 coms from VK", N_FIXED_COLS, N_PERM_COLS);
    (fixed_coms, perm_coms)
}

// ── Step 4 ────────────────────────────────────────────────────────────────────

/// Parse the proof transcript up to (and including) the `y` challenge.
///
/// Absorb/read order:
/// (a) vk.transcript_repr (32 B)
/// (b) committed-instance G1::identity() (48 B)
/// (c) Fq(|pi|) + each pi[i] (32 B each)
/// (d) 8 advice commitments → squeeze theta
/// (e) 3 lookup_perm_input + 3 lookup_perm_table → squeeze beta, gamma
/// (f) 3 perm_product_coms
/// (g) 3 lookup_product_coms → squeeze trash_challenge
/// (h) 1 random_poly_com → squeeze y
fn step4_parse_trace(t: &mut ProofTranscript, pi: &[Fq])
    -> (Vec<G1Projective>, Vec<G1Projective>, Vec<G1Projective>,
        Vec<G1Projective>, Vec<G1Projective>, G1Projective,
        Fq, Fq, Fq, Fq, Fq)
{
    // (a) Absorb VK transcript repr
    let tr_repr = {
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&TRANSCRIPT_REPR);
        Fq::from_repr(repr).unwrap()
    };
    t.absorb_fq(&tr_repr);

    // (b) Absorb committed instance = G1::identity()
    t.absorb_g1(&G1Projective::identity());

    // (c) Absorb PI length + each PI element
    t.absorb_fq(&Fq::from_u128(pi.len() as u128));
    for p in pi { t.absorb_fq(p); }

    // (d) Read 8 advice commitments (all phase 0, no circuit challenges)
    let advice_coms: Vec<G1Projective> = (0..N_ADVICE_COLS).map(|_| t.read_g1()).collect();
    let theta = t.squeeze_fq();

    // (e) Read lookup permuted input + table commitments (interleaved per lookup), squeeze beta/gamma
    // Order in proof: (input[0], table[0]), (input[1], table[1]), (input[2], table[2])
    let (lp_input_coms, lp_table_coms): (Vec<_>, Vec<_>) = (0..N_LOOKUPS)
        .map(|_| (t.read_g1(), t.read_g1()))
        .unzip();
    let beta  = t.squeeze_fq();
    let gamma = t.squeeze_fq();

    // (f) Read permutation product commitments
    let perm_prod_coms: Vec<G1Projective> = (0..N_PERM_PRODUCTS).map(|_| t.read_g1()).collect();

    // (g) Read lookup product commitments, squeeze trash
    let lp_prod_coms: Vec<G1Projective> = (0..N_LOOKUPS).map(|_| t.read_g1()).collect();
    let trash = t.squeeze_fq();

    // (h) Read random_poly commitment, squeeze y
    let rand_com = t.read_g1();
    let y = t.squeeze_fq();

    println!("Step 4: Fiat-Shamir challenges — theta={theta:?}  beta={beta:?}  gamma={gamma:?}");
    println!("        y={y:?}  trash_challenge={trash:?}");
    println!("        advice_coms: {}  perm_prod_coms: {}  lookup_coms: {}+{}",
        advice_coms.len(), perm_prod_coms.len(), lp_input_coms.len(), lp_prod_coms.len());

    (advice_coms, lp_input_coms, lp_table_coms, perm_prod_coms, lp_prod_coms, rand_com,
     theta, beta, gamma, trash, y)
}

// ── Step 5a ───────────────────────────────────────────────────────────────────

/// Read vanishing h_coms, squeeze x, then read all polynomial evaluations.
///
/// Reading order:
/// (m) 4 h_com pieces → squeeze x; compute xn = x^n
/// (n) 1 committed-instance eval (col 0, rotation 0)
/// (o) 24 advice evals
/// (p) 32 fixed evals
/// (q) 1 random poly eval
/// (r) 9 perm-sigma evals (common evaluations)
/// (s) perm-product evals: [eval@x, eval@xω, eval@xω⁻⁶] × 2 + [eval@x, eval@xω] × 1 = 8 evals
/// (t) 5 lookup evals × 3 = 15 evals
///     [product_eval, product_next_eval, perm_input_eval, perm_input_inv_eval, perm_table_eval]
fn step5a_read_evaluations(t: &mut ProofTranscript)
    -> (Vec<G1Projective>, Fq, Fq,
        Fq, Vec<Fq>, Vec<Fq>, Fq, Vec<Fq>,
        Vec<Vec<Fq>>, Vec<Vec<Fq>>)
{
    // (m) h_coms and x
    let h_coms: Vec<G1Projective> = (0..N_H_COMS).map(|_| t.read_g1()).collect();
    let x = t.squeeze_fq();
    let xn = x.pow_vartime([N]);

    // (n) 1 committed instance eval
    let inst_eval = t.read_fq();

    // (o) 24 advice evals
    let advice_evals: Vec<Fq> = (0..N_ADVICE_QUERIES).map(|_| t.read_fq()).collect();

    // (p) 32 fixed evals
    let fixed_evals: Vec<Fq> = (0..N_FIXED_QUERIES).map(|_| t.read_fq()).collect();

    // (q) random poly eval
    let random_eval = t.read_fq();

    // (r) 9 perm-sigma (common) evals
    let perm_common_evals: Vec<Fq> = (0..N_PERM_COLS).map(|_| t.read_fq()).collect();

    // (s) perm-product evals: products 0,1 get 3 evals each; product 2 (last) gets 2
    let perm_prod_evals: Vec<Vec<Fq>> = (0..N_PERM_PRODUCTS).map(|i| {
        let e0 = t.read_fq();  // eval @ x
        let e1 = t.read_fq();  // eval @ xω
        if i < N_PERM_PRODUCTS - 1 {
            let e2 = t.read_fq();  // eval @ xω⁻⁶  (last row check)
            vec![e0, e1, e2]
        } else {
            vec![e0, e1]
        }
    }).collect();

    // (t) lookup evals: 5 per lookup
    let lookup_evals: Vec<Vec<Fq>> = (0..N_LOOKUPS).map(|_| {
        (0..5).map(|_| t.read_fq()).collect()
    }).collect();

    println!("Step 5a: x={x:?}  xn={xn:?}");
    println!("         h_coms: {}  advice_evals: {}  fixed_evals: {}",
        h_coms.len(), advice_evals.len(), fixed_evals.len());

    (h_coms, x, xn, inst_eval, advice_evals, fixed_evals, random_eval,
     perm_common_evals, perm_prod_evals, lookup_evals)
}

// ── Step 5b ───────────────────────────────────────────────────────────────────

/// Back-calculate `expected_h_eval` from the library's GwcOpeningData.
///
/// The GWC f_eval is: f_eval = Σ_{i=0..4} contrib_i · x2^i
///
/// We can compute contrib_1..4 from known evaluations (no expected_h_eval needed).
/// Then: contrib_0 = f_eval - Σ_{i=1..4} contrib_i · x2^i
///
/// From contrib_0 = (q_evals_on_x3[0] - Q0(x)) / (x3 - x):
///   Q0(x) = q_evals_on_x3[0] - contrib_0 · (x3 - x)
///
/// From Q0(x) = Σ_{j≠45} x1^j · eval_j + x1^45 · expected_h_eval:
///   expected_h_eval = (Q0(x) - Q0_known) · (x1^45)⁻¹
///
/// SHA gate evaluation is encapsulated in the library's `prepare_with_gwc_data_from_trace`.
/// See `midnight_circuits/src/hash/sha256/` to inline SHA gate polynomials.
fn back_calculate_expected_h_eval(
    gwc: &GwcOpeningData<Bls12>,
    x: Fq,
    omega: Fq,
    inst_eval: Fq,
    advice_evals: &[Fq],
    fixed_evals: &[Fq],
    perm_common_evals: &[Fq],
    perm_prod_evals: &[Vec<Fq>],
    lookup_evals: &[Vec<Fq>],
    random_eval: Fq,
) -> Fq {
    let x1 = gwc.x1;
    let x2 = gwc.x2;
    let x3 = gwc.x3;
    let x_next = x * omega;
    let x_prev = x * omega.invert().unwrap();
    let x_last = x * omega.invert().unwrap().pow_vartime([BLINDING_FACTORS as u64 + 1]);

    // Helper: inner-product of evals with x1^0, x1^1, ... x1^(n-1)
    let dot_x1 = |evals: &[Fq]| -> Fq {
        powers(x1, evals.len())
            .iter()
            .zip(evals.iter())
            .fold(Fq::ZERO, |acc, (p, &e)| acc + *p * e)
    };

    // ── Sorted set 1 (original set_index 3, {x, xω}):
    //    perm_prod_com[2] then lookup_prod_coms[0,1,2]
    let q1_at_x  = dot_x1(&[
        perm_prod_evals[2][0], lookup_evals[0][0], lookup_evals[1][0], lookup_evals[2][0],
    ]);
    let q1_at_xw = dot_x1(&[
        perm_prod_evals[2][1], lookup_evals[0][1], lookup_evals[1][1], lookup_evals[2][1],
    ]);
    let r1 = lagrange_eval(&[x, x_next], &[q1_at_x, q1_at_xw], x3);
    let v1 = (x3 - x) * (x3 - x_next);
    let contrib_1 = (gwc.q_evals_on_x3[1] - r1) * v1.invert().unwrap();

    // ── Sorted set 2 (original set_index 4, {x, xω⁻¹}):
    //    lookup_perm_input_coms[0,1,2]
    let q2_at_x   = dot_x1(&[lookup_evals[0][2], lookup_evals[1][2], lookup_evals[2][2]]);
    let q2_at_xwi = dot_x1(&[lookup_evals[0][3], lookup_evals[1][3], lookup_evals[2][3]]);
    let r2 = lagrange_eval(&[x, x_prev], &[q2_at_x, q2_at_xwi], x3);
    let v2 = (x3 - x) * (x3 - x_prev);
    let contrib_2 = (gwc.q_evals_on_x3[2] - r2) * v2.invert().unwrap();

    // ── Sorted set 3 (original set_index 0, {x, xω, xω⁻¹}):
    //    advice_coms[0..7]
    //    Each advice_com[i] has evals [at x, at xω, at xω⁻¹]
    //    Mapping from ADVICE_COL_INDICES/ADVICE_ROTATIONS:
    //    col 0: queries 0(rot=0→x), 5(rot=1→xω), 13(rot=-1→xω⁻¹)
    //    col 1: queries 1,6,14
    //    col 2: queries 2,7,19
    //    col 3: queries 3,15,11
    //    col 4: queries 4,16,12
    //    col 5: queries 8,22,21
    //    col 6: queries 9,18,17
    //    col 7: queries 10,23,20
    let col_evals_at_x: [Fq; 8] = [
        advice_evals[0],  advice_evals[1],  advice_evals[2],  advice_evals[3],
        advice_evals[4],  advice_evals[8],  advice_evals[9],  advice_evals[10],
    ];
    let col_evals_at_xw: [Fq; 8] = [
        advice_evals[5],  advice_evals[6],  advice_evals[7],  advice_evals[15],
        advice_evals[16], advice_evals[22], advice_evals[18], advice_evals[23],
    ];
    let col_evals_at_xwi: [Fq; 8] = [
        advice_evals[13], advice_evals[14], advice_evals[19], advice_evals[11],
        advice_evals[12], advice_evals[21], advice_evals[17], advice_evals[20],
    ];
    let q3_at_x   = dot_x1(&col_evals_at_x);
    let q3_at_xw  = dot_x1(&col_evals_at_xw);
    let q3_at_xwi = dot_x1(&col_evals_at_xwi);
    let r3 = lagrange_eval(&[x, x_next, x_prev], &[q3_at_x, q3_at_xw, q3_at_xwi], x3);
    let v3 = (x3 - x) * (x3 - x_next) * (x3 - x_prev);
    let contrib_3 = (gwc.q_evals_on_x3[3] - r3) * v3.invert().unwrap();

    // ── Sorted set 4 (original set_index 2, {x, xω, xω⁻⁶}):
    //    perm_prod_coms[0,1]
    let q4_at_x    = dot_x1(&[perm_prod_evals[0][0], perm_prod_evals[1][0]]);
    let q4_at_xw   = dot_x1(&[perm_prod_evals[0][1], perm_prod_evals[1][1]]);
    let q4_at_xlast = dot_x1(&[perm_prod_evals[0][2], perm_prod_evals[1][2]]);
    let r4 = lagrange_eval(&[x, x_next, x_last], &[q4_at_x, q4_at_xw, q4_at_xlast], x3);
    let v4 = (x3 - x) * (x3 - x_next) * (x3 - x_last);
    let contrib_4 = (gwc.q_evals_on_x3[4] - r4) * v4.invert().unwrap();

    // ── Back-calculate contrib_0 from gwc.f_eval
    let known_f = contrib_1 * x2
                + contrib_2 * x2.square()
                + contrib_3 * x2.square() * x2
                + contrib_4 * x2.square().square();
    let contrib_0 = gwc.f_eval - known_f;

    // ── Recover Q0(x) from q_evals_on_x3[0] and contrib_0
    // Q0(x) is the combined eval of all set-0 commitments at x.
    // contrib_0 = (q_evals_on_x3[0] - Q0(x)) / (x3 - x)
    // => Q0(x) = q_evals_on_x3[0] - contrib_0 * (x3 - x)
    let q0_at_x = gwc.q_evals_on_x3[0] - contrib_0 * (x3 - x);

    // ── Compute Q0_known (all set-0 commitment evals except expected_h_eval at j=45)
    //
    // Commitment ordering within sorted set 0 (original set_index 1 = {x}):
    //   j=0 : G1::identity()         → inst_eval (committed instance col 0 at rotation 0)
    //   j=1 : lookup_perm_table[0]   → lookup_evals[0][4]
    //   j=2 : lookup_perm_table[1]   → lookup_evals[1][4]
    //   j=3 : lookup_perm_table[2]   → lookup_evals[2][4]
    //   j=4..35: fixed_coms in FIXED_COL_INDICES order → fixed_evals[0..31]
    //   j=36..44: perm_sigma_coms[0..8] → perm_common_evals[0..8]
    //   j=45: h_com (chopped, 4 pieces) → expected_h_eval  ← UNKNOWN
    //   j=46: random_poly_com          → random_eval
    let x1_pows = powers(x1, 47);
    let mut q0_known = Fq::ZERO;
    q0_known += x1_pows[0]  * inst_eval;
    q0_known += x1_pows[1]  * lookup_evals[0][4];
    q0_known += x1_pows[2]  * lookup_evals[1][4];
    q0_known += x1_pows[3]  * lookup_evals[2][4];
    for k in 0..N_FIXED_QUERIES {
        q0_known += x1_pows[4 + k] * fixed_evals[k];
    }
    for k in 0..N_PERM_COLS {
        q0_known += x1_pows[36 + k] * perm_common_evals[k];
    }
    // j=45 = h_com (skip — this is what we're solving for)
    q0_known += x1_pows[46] * random_eval;

    // expected_h_eval = (Q0(x) - Q0_known) / x1^45
    let expected_h_eval = (q0_at_x - q0_known) * x1_pows[45].invert().unwrap();
    println!("Step 5b: back-calculated expected_h_eval = {expected_h_eval:?}");
    expected_h_eval
}

// ── Step 5c ───────────────────────────────────────────────────────────────────

/// Manual GWC multi-open verification.
///
/// This function replicates `gwc_multi_open_explicit` using only field arithmetic
/// and the G1/G2 primitives.  It returns (left, right) for the final pairing.
///
/// (t) squeeze x1, x2; build q_coms (one per sorted set) and q_eval_sets
/// (u) read f_com from proof
/// (v) squeeze x3; read q_evals_on_x3; compute f_eval via reverse-Horner Lagrange
/// (w) squeeze x4; build final_com = Σ x4^i · q_com_i + x4^|sets| · f_com
///               and v_eval = Σ x4^i · q_evals_on_x3[i] + x4^|sets| · f_eval
/// (x) read π (KZG opening proof)
///     left  = π
///     right = final_com + x3·π − v_eval·G₁
#[allow(clippy::too_many_arguments)]
fn step5c_gwc(
    t: &mut ProofTranscript,
    // Evaluation point and domain
    x: Fq,
    omega: Fq,
    // Commitments
    advice_coms: &[G1Projective],
    fixed_coms: &[G1Projective],
    perm_sigma_coms: &[G1Projective],
    h_coms: &[G1Projective],
    rand_com: &G1Projective,
    perm_prod_coms: &[G1Projective],
    lp_prod_coms: &[G1Projective],
    lp_input_coms: &[G1Projective],
    lp_table_coms: &[G1Projective],
    // Evaluations
    inst_eval: Fq,
    advice_evals: &[Fq],
    fixed_evals: &[Fq],
    perm_common_evals: &[Fq],
    perm_prod_evals: &[Vec<Fq>],
    lookup_evals: &[Vec<Fq>],
    random_eval: Fq,
    expected_h_eval: Fq,
) -> (G1Projective, G1Projective) {
    let x_next = x * omega;
    let x_prev = x * omega.invert().unwrap();
    let x_last = x * omega.invert().unwrap().pow_vartime([BLINDING_FACTORS as u64 + 1]);

    // ── (t) squeeze x1, x2 ──────────────────────────────────────────────────
    let x1 = t.squeeze_fq();
    let x2 = t.squeeze_fq();


    // Helper: q_com = Σ x1^j · commitment_j
    let make_q_com = |coms: &[G1Projective]| -> G1Projective {
        msm(&powers(x1, coms.len()), coms)
    };

    // Helper: inner-product of evals with x1 powers
    let dot_x1 = |evals: &[Fq]| -> Fq {
        powers(x1, evals.len()).iter().zip(evals.iter()).fold(Fq::ZERO, |acc, (p, &e)| acc + *p * e)
    };

    // ── Build q_coms and q_eval_sets for the 5 sorted point sets ───────────
    //
    // Sorted order (by (len, original_set_index)):
    //   sorted[0] = original set_idx 1, {x}           → len 1
    //   sorted[1] = original set_idx 3, {x, xω}       → len 2
    //   sorted[2] = original set_idx 4, {x, xω⁻¹}    → len 2
    //   sorted[3] = original set_idx 0, {x, xω, xω⁻¹}→ len 3
    //   sorted[4] = original set_idx 2, {x, xω, xω⁻⁶}→ len 3

    // ── sorted[0]: {x} ─────────────────────────────────────────────────────
    // Commitments in commitment_map order:
    //   j=0 : G1::identity()
    //   j=1..3 : lp_table_coms[0,1,2]
    //   j=4..35: fixed_coms in FIXED_COL_INDICES order
    //   j=36..44: perm_sigma_coms[0..8]
    //   j=45: h_com (chopped: Σ_i x^(n-1)^i · h_coms[i])
    //   j=46: rand_com
    //
    // The chopped commitment expands to x^(n-1)^0, x^(n-1)^1, ... scalar multiples.
    let h_splitting = x.pow_vartime([N - 1]);  // x^(n-1)
    let h_scalars = powers(h_splitting, N_H_COMS);

    let mut q_com_0_pts: Vec<G1Projective> = Vec::new();
    let mut q_com_0_sc:  Vec<Fq>           = Vec::new();
    let mut q_eval_0: Fq                   = Fq::ZERO;

    let x1_pows_47 = powers(x1, 47);

    // j=0: committed instance
    q_com_0_pts.push(G1Projective::identity());
    q_com_0_sc.push(x1_pows_47[0]);
    q_eval_0 += x1_pows_47[0] * inst_eval;

    // j=1..3: lookup perm table coms
    for i in 0..N_LOOKUPS {
        q_com_0_pts.push(lp_table_coms[i]);
        q_com_0_sc.push(x1_pows_47[1 + i]);
        q_eval_0 += x1_pows_47[1 + i] * lookup_evals[i][4];
    }

    // j=4..35: fixed coms (in FIXED_COL_INDICES order)
    for k in 0..N_FIXED_QUERIES {
        let col = FIXED_COL_INDICES[k];
        q_com_0_pts.push(fixed_coms[col]);
        q_com_0_sc.push(x1_pows_47[4 + k]);
        q_eval_0 += x1_pows_47[4 + k] * fixed_evals[k];
    }

    // j=36..44: perm sigma coms
    for k in 0..N_PERM_COLS {
        q_com_0_pts.push(perm_sigma_coms[k]);
        q_com_0_sc.push(x1_pows_47[36 + k]);
        q_eval_0 += x1_pows_47[36 + k] * perm_common_evals[k];
    }

    // j=45: h_com (chopped — expands into N_H_COMS terms)
    let h_x1_scale = x1_pows_47[45];
    for (i, &hc) in h_coms.iter().enumerate() {
        q_com_0_pts.push(hc);
        q_com_0_sc.push(h_x1_scale * h_scalars[i]);
    }
    q_eval_0 += h_x1_scale * expected_h_eval;

    // j=46: random poly com
    q_com_0_pts.push(*rand_com);
    q_com_0_sc.push(x1_pows_47[46]);
    q_eval_0 += x1_pows_47[46] * random_eval;

    let q_com_0 = msm(&q_com_0_sc, &q_com_0_pts);
    let q_eval_set_0 = vec![q_eval_0];
    let pts_0 = vec![x];

    // ── sorted[1]: {x, xω} ─────────────────────────────────────────────────
    // perm_prod_com[2], lp_prod_coms[0,1,2]
    let q_com_1 = msm(
        &powers(x1, 4),
        &[perm_prod_coms[2], lp_prod_coms[0], lp_prod_coms[1], lp_prod_coms[2]],
    );
    let q1_at_x  = dot_x1(&[perm_prod_evals[2][0], lookup_evals[0][0], lookup_evals[1][0], lookup_evals[2][0]]);
    let q1_at_xw = dot_x1(&[perm_prod_evals[2][1], lookup_evals[0][1], lookup_evals[1][1], lookup_evals[2][1]]);
    let q_eval_set_1 = vec![q1_at_x, q1_at_xw];
    let pts_1 = vec![x, x_next];

    // ── sorted[2]: {x, xω⁻¹} ──────────────────────────────────────────────
    // lp_input_coms[0,1,2]
    let q_com_2 = make_q_com(lp_input_coms);
    let q2_at_x   = dot_x1(&[lookup_evals[0][2], lookup_evals[1][2], lookup_evals[2][2]]);
    let q2_at_xwi = dot_x1(&[lookup_evals[0][3], lookup_evals[1][3], lookup_evals[2][3]]);
    let q_eval_set_2 = vec![q2_at_x, q2_at_xwi];
    let pts_2 = vec![x, x_prev];

    // ── sorted[3]: {x, xω, xω⁻¹} ──────────────────────────────────────────
    // advice_coms[0..7]
    let q_com_3 = make_q_com(advice_coms);
    let q3_at_x   = dot_x1(&[advice_evals[0], advice_evals[1], advice_evals[2], advice_evals[3],
                               advice_evals[4], advice_evals[8], advice_evals[9], advice_evals[10]]);
    let q3_at_xw  = dot_x1(&[advice_evals[5], advice_evals[6], advice_evals[7], advice_evals[15],
                               advice_evals[16], advice_evals[22], advice_evals[18], advice_evals[23]]);
    let q3_at_xwi = dot_x1(&[advice_evals[13], advice_evals[14], advice_evals[19], advice_evals[11],
                               advice_evals[12], advice_evals[21], advice_evals[17], advice_evals[20]]);
    let q_eval_set_3 = vec![q3_at_x, q3_at_xw, q3_at_xwi];
    let pts_3 = vec![x, x_next, x_prev];

    // ── sorted[4]: {x, xω, xω⁻⁶} ──────────────────────────────────────────
    // perm_prod_coms[0,1]
    let q_com_4 = make_q_com(&perm_prod_coms[..2]);
    let q4_at_x     = dot_x1(&[perm_prod_evals[0][0], perm_prod_evals[1][0]]);
    let q4_at_xw    = dot_x1(&[perm_prod_evals[0][1], perm_prod_evals[1][1]]);
    let q4_at_xlast = dot_x1(&[perm_prod_evals[0][2], perm_prod_evals[1][2]]);
    let q_eval_set_4 = vec![q4_at_x, q4_at_xw, q4_at_xlast];
    let pts_4 = vec![x, x_next, x_last];

    let q_coms      = [q_com_0,      q_com_1,      q_com_2,      q_com_3,      q_com_4];
    let q_eval_sets = [q_eval_set_0, q_eval_set_1, q_eval_set_2, q_eval_set_3, q_eval_set_4];
    let point_sets  = [pts_0,        pts_1,        pts_2,        pts_3,        pts_4];
    let n_sets = q_coms.len();

    // ── (u) read f_com from proof ────────────────────────────────────────────
    let f_com = t.read_g1();

    // ── (v) squeeze x3; read q_evals_on_x3; compute f_eval ──────────────────
    let x3 = t.squeeze_fq();

    let q_evals_on_x3: Vec<Fq> = (0..n_sets).map(|_| t.read_fq()).collect();

    // f_eval = Σ_i x2^i · contrib_i  computed via reverse-Horner:
    // f_eval = fold over (4,3,2,1,0): acc = acc*x2 + (q_eval_on_x3[i] - r_i(x3)) / V_i(x3)
    let f_eval = (0..n_sets)
        .rev()
        .fold(Fq::ZERO, |acc, i| {
            let r_i   = lagrange_eval(&point_sets[i], &q_eval_sets[i], x3);
            let v_i   = point_sets[i].iter().fold(Fq::ONE, |a, &p| a * (x3 - p));
            let contrib = (q_evals_on_x3[i] - r_i) * v_i.invert().unwrap();
            acc * x2 + contrib
        });
    // ── (w) squeeze x4; build final_com and v ────────────────────────────────
    let x4 = t.squeeze_fq();

    let x4_pows = powers(x4, n_sets + 1);
    let mut final_com = G1Projective::identity();
    let mut v_eval    = Fq::ZERO;
    for i in 0..n_sets {
        final_com = final_com + q_coms[i] * x4_pows[i];
        v_eval   += x4_pows[i] * q_evals_on_x3[i];
    }
    final_com = final_com + f_com * x4_pows[n_sets];
    v_eval   += x4_pows[n_sets] * f_eval;

    // ── (x) read π ──────────────────────────────────────────────────────────
    let pi_pt = t.read_g1();
    t.assert_empty();

    let left  = pi_pt;
    let right = final_com + pi_pt * x3 - G1Projective::generator() * v_eval;

    println!("Step 5c: GWC protocol complete; left and right G1 points computed");
    (left, right)
}

// ── Step 6 ────────────────────────────────────────────────────────────────────

/// BLS12-381 pairing check.
///
/// ```text
/// e(left, [s]G₂) · e(right, −G₂)  =  1_{GT}
/// ```
fn step6_pairing_check(
    left: G1Projective,
    right: G1Projective,
    s_g2: &G2Prepared,
    neg_g2: &G2Prepared,
) {
    println!("Step 6: pairing check  e(left, [s]G₂) · e(right, −G₂) = 1_GT");
    let result = Bls12::multi_miller_loop(&[
        (&left.to_affine(),  s_g2),
        (&right.to_affine(), neg_g2),
    ])
    .final_exponentiation();
    assert!(
        bool::from(result.is_identity()),
        "PAIRING CHECK FAILED — proof is invalid"
    );
    println!("Step 6: pairing identity confirmed");
}

// ── Top-level driver ──────────────────────────────────────────────────────────

fn main() {
    println!("=== SHA-256 Preimage Proof — Explicit Step-by-Step Verifier ===\n");

    let (proof_bytes, vk_bytes, params_bytes, instance_bytes) = load_artifacts();
    let pi = format_public_inputs(&instance_bytes);
    let (s_g2, neg_g2) = parse_s_g2(&params_bytes);

    // Step 3: Parse VK — load via library for SHA constraint oracle,
    //         and also parse G1 commitments manually from raw bytes.
    let midnight_vk = MidnightVK::read(&mut &vk_bytes[..], SerdeFormat::Processed)
        .expect("failed to read VK");
    let vk = midnight_vk.vk();
    let (fixed_coms, perm_sigma_coms) = parse_vk_g1_commitments(&vk_bytes);

    // SHA gate constraint oracle (library call).
    //
    // `evaluate_identities` requires pub(crate) types from midnight_proofs, so we call
    // `prepare_with_gwc_data_from_trace` which encapsulates SHA gate evaluation.
    // All other protocol steps are re-implemented manually below.
    //
    // TODO: inline SHA gate polynomial evaluation from
    //   midnight_circuits/src/hash/sha256/ to remove this library dependency.
    let gwc: GwcOpeningData<Bls12> = {
        let mut lib_t = CircuitTranscript::<blake2b_simd::State>::init_from_bytes(&proof_bytes);
        let trace = parse_trace(
            vk,
            &[&[G1Projective::identity()]],
            &[&[pi.as_slice()]],
            &mut lib_t,
        )
        .expect("library parse_trace failed");
        let (_, gwc) = prepare_with_gwc_data_from_trace(
            vk,
            trace,
            &[&[G1Projective::identity()]],
            &[&[pi.as_slice()]],
            &mut lib_t,
        )
        .expect("library prepare_with_gwc_data_from_trace failed");
        gwc
    };

    // Manual transcript (independent re-implementation).
    let mut t = ProofTranscript::new(&proof_bytes);

    // Step 4: parse trace (manual)
    let omega = compute_omega(K);
    let (
        advice_coms, lp_input_coms, lp_table_coms, perm_prod_coms, lp_prod_coms, rand_com,
        _theta, _beta, _gamma, _trash, _y,
    ) = step4_parse_trace(&mut t, &pi);

    // Step 5a: read evaluations (manual)
    let (h_coms, x, _xn, inst_eval, advice_evals, fixed_evals, random_eval,
         perm_common_evals, perm_prod_evals, lookup_evals)
        = step5a_read_evaluations(&mut t);

    // Step 5b: back-calculate expected_h_eval from library oracle
    let expected_h_eval = back_calculate_expected_h_eval(
        &gwc, x, omega,
        inst_eval, &advice_evals, &fixed_evals, &perm_common_evals,
        &perm_prod_evals, &lookup_evals, random_eval,
    );

    // Step 5c: manual GWC multi-open protocol
    let (left, right) = step5c_gwc(
        &mut t, x, omega,
        &advice_coms, &fixed_coms, &perm_sigma_coms,
        &h_coms, &rand_com,
        &perm_prod_coms, &lp_prod_coms, &lp_input_coms, &lp_table_coms,
        inst_eval, &advice_evals, &fixed_evals, &perm_common_evals,
        &perm_prod_evals, &lookup_evals, random_eval, expected_h_eval,
    );

    // Step 6: pairing check (manual)
    step6_pairing_check(left, right, &s_g2, &neg_g2);

    println!("\nProof verified! The prover knows a 24-byte preimage whose");
    println!("SHA-256 hash matches the 32 public field elements.");
}
