//! Decode the four SHA-256 preimage proof artifacts into a single JSON file.
//!
//! Run `cargo run --example sha_preimage` first to generate the artifacts, then:
//!
//! ```
//! cargo run --example sha_preimage_dump_json
//! ```
//!
//! Output: `examples/assets/sha_preimage_decoded.json`
//!
//! Every G1 commitment is a 48-byte compressed point (hex).
//! Every G2 point is a 96-byte compressed point (hex).
//! Every field element is a 32-byte little-endian canonical scalar (hex).

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{Group, GroupEncoding};
use midnight_curves::{Fq, G1Projective};
use serde_json::{json, Value};
use std::fs;

// ── Circuit constants (same as sha_preimage_verify_manual.rs) ────────────────

const TRANSCRIPT_REPR: [u8; 32] = [
    183, 133, 103, 247, 105, 79, 107, 44, 128, 90, 72, 37, 41, 189, 60, 185,
    222, 30, 4, 122, 238, 112, 81, 155, 173, 169, 251, 185, 43, 87, 118, 32,
];

const K: u32 = 13;
const N: u64 = 1 << K;
const N_ADVICE_COLS: usize = 8;
const N_LOOKUPS: usize = 3;
const N_PERM_COLS: usize = 9;
const N_PERM_PRODUCTS: usize = 3;
const N_H_COMS: usize = 4;
const N_ADVICE_QUERIES: usize = 24;
const N_FIXED_QUERIES: usize = 32;
const N_FIXED_COLS: usize = 32;
const BLINDING_FACTORS: usize = 5;
const ZKSTD_ARCH_BYTES: usize = 16;

// ── Formatting helpers ────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn fq_hex(x: &Fq) -> String {
    hex(x.to_repr().as_ref())
}

fn g1_hex(pt: &G1Projective) -> String {
    hex(GroupEncoding::to_bytes(pt).as_ref())
}

// ── Transcript (Blake2b-512 Fiat-Shamir sponge) ───────────────────────────────

struct T {
    state: blake2b_simd::State,
    proof: Vec<u8>,
    pos: usize,
}

impl T {
    fn new(proof: &[u8]) -> Self {
        let state = Blake2bParams::new()
            .hash_length(64)
            .key(b"Domain separator for transcript")
            .to_state();
        T { state, proof: proof.to_vec(), pos: 0 }
    }

    fn absorb(&mut self, data: &[u8]) {
        self.state.update(&[0x01]);
        self.state.update(data);
    }

    fn absorb_fq(&mut self, x: &Fq) { self.absorb(x.to_repr().as_ref()); }
    fn absorb_g1(&mut self, pt: &G1Projective) { self.absorb(GroupEncoding::to_bytes(pt).as_ref()); }

    fn squeeze_fq(&mut self) -> Fq {
        self.state.update(&[0x00]);
        let out = self.state.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(out.as_bytes());
        Fq::from_uniform_bytes(&bytes)
    }

    fn read_g1(&mut self) -> G1Projective {
        let mut buf = [0u8; 48];
        buf.copy_from_slice(&self.proof[self.pos..self.pos + 48]);
        self.pos += 48;
        self.absorb(&buf);
        let mut repr = <G1Projective as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&buf);
        Option::from(G1Projective::from_bytes(&repr)).expect("invalid G1 in proof")
    }

    fn read_fq(&mut self) -> Fq {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.proof[self.pos..self.pos + 32]);
        self.pos += 32;
        self.absorb(&buf);
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&buf);
        Option::from(Fq::from_repr(repr)).expect("invalid Fq in proof")
    }
}

// ── Root-of-unity helper ──────────────────────────────────────────────────────

fn compute_omega(k: u32) -> Fq {
    Fq::ROOT_OF_UNITY.pow_vartime([1u64 << (Fq::S - k)])
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let dir = "examples/assets";
    let proof_bytes  = fs::read(format!("{dir}/sha_preimage_proof.bin")).expect("run sha_preimage first");
    let vk_bytes     = fs::read(format!("{dir}/sha_preimage_vk.bin")).expect("run sha_preimage first");
    let params_bytes = fs::read(format!("{dir}/sha_preimage_verifier_params.bin")).expect("run sha_preimage first");
    let instance_bytes = fs::read(format!("{dir}/sha_preimage_instance.bin")).expect("run sha_preimage first");

    // ── Instance ─────────────────────────────────────────────────────────────

    let pi_fq: Vec<Fq> = instance_bytes.iter().map(|&b| Fq::from(b as u64)).collect();
    let instance_json = json!({
        "raw_hex": hex(&instance_bytes),
        "public_inputs_fq": pi_fq.iter().map(|x| fq_hex(x)).collect::<Vec<_>>(),
    });

    // ── Verifier params ([s]G₂) ───────────────────────────────────────────────

    assert_eq!(params_bytes.len(), 96);
    let params_json = json!({
        "s_g2_compressed_hex": hex(&params_bytes),
    });

    // ── VK ───────────────────────────────────────────────────────────────────

    let fixed_start = ZKSTD_ARCH_BYTES + 1 + 4 + 1 + 1 + 4;  // byte 27
    let perm_start  = fixed_start + N_FIXED_COLS * 48;         // byte 1563

    let vk_fixed_coms: Vec<Value> = (0..N_FIXED_COLS).map(|i| {
        let off = fixed_start + i * 48;
        json!(hex(&vk_bytes[off..off + 48]))
    }).collect();

    let vk_perm_coms: Vec<Value> = (0..N_PERM_COLS).map(|i| {
        let off = perm_start + i * 48;
        json!(hex(&vk_bytes[off..off + 48]))
    }).collect();

    let vk_json = json!({
        "transcript_repr_hex": hex(&TRANSCRIPT_REPR),
        "fixed_commitments_g1": vk_fixed_coms,
        "perm_sigma_commitments_g1": vk_perm_coms,
    });

    // ── Proof — parse + run transcript ───────────────────────────────────────

    let omega = compute_omega(K);
    let mut t = T::new(&proof_bytes);

    // Absorb VK transcript repr
    let tr_fq = {
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&TRANSCRIPT_REPR);
        Fq::from_repr(repr).unwrap()
    };
    t.absorb_fq(&tr_fq);

    // Absorb committed instance = G1::identity()
    t.absorb_g1(&G1Projective::identity());

    // Absorb PI length + each PI element
    t.absorb_fq(&Fq::from_u128(pi_fq.len() as u128));
    for p in &pi_fq { t.absorb_fq(p); }

    // 8 advice commitments
    let advice_coms: Vec<G1Projective> = (0..N_ADVICE_COLS).map(|_| t.read_g1()).collect();
    let theta = t.squeeze_fq();

    // 3 × (lookup_perm_input, lookup_perm_table) — interleaved
    let (lp_input_coms, lp_table_coms): (Vec<_>, Vec<_>) = (0..N_LOOKUPS)
        .map(|_| (t.read_g1(), t.read_g1()))
        .unzip();
    let beta  = t.squeeze_fq();
    let gamma = t.squeeze_fq();

    // 3 perm-product commitments
    let perm_prod_coms: Vec<G1Projective> = (0..N_PERM_PRODUCTS).map(|_| t.read_g1()).collect();

    // 3 lookup-product commitments
    let lp_prod_coms: Vec<G1Projective> = (0..N_LOOKUPS).map(|_| t.read_g1()).collect();
    let trash = t.squeeze_fq();

    // 1 random-poly commitment
    let rand_com = t.read_g1();
    let y = t.squeeze_fq();

    // 4 h_com pieces (vanishing quotient)
    let h_coms: Vec<G1Projective> = (0..N_H_COMS).map(|_| t.read_g1()).collect();
    let x = t.squeeze_fq();
    let xn = x.pow_vartime([N]);
    let x_next = x * omega;
    let x_prev = x * omega.invert().unwrap();
    let x_last = x * omega.invert().unwrap().pow_vartime([BLINDING_FACTORS as u64 + 1]);

    // Evaluations
    let inst_eval  = t.read_fq();
    let advice_evals:       Vec<Fq> = (0..N_ADVICE_QUERIES) .map(|_| t.read_fq()).collect();
    let fixed_evals:        Vec<Fq> = (0..N_FIXED_QUERIES)  .map(|_| t.read_fq()).collect();
    let random_eval = t.read_fq();
    let perm_common_evals:  Vec<Fq> = (0..N_PERM_COLS)      .map(|_| t.read_fq()).collect();

    // Perm-product evals: products 0,1 → 3 evals; product 2 → 2 evals
    let perm_prod_evals: Vec<Vec<Fq>> = (0..N_PERM_PRODUCTS).map(|i| {
        let e0 = t.read_fq();
        let e1 = t.read_fq();
        if i < N_PERM_PRODUCTS - 1 { vec![e0, e1, t.read_fq()] } else { vec![e0, e1] }
    }).collect();

    // Lookup evals: 5 per lookup [product, product_next, perm_input, perm_input_inv, perm_table]
    let lookup_evals: Vec<Vec<Fq>> = (0..N_LOOKUPS).map(|_| {
        (0..5).map(|_| t.read_fq()).collect()
    }).collect();

    // GWC: f_com
    let f_com = t.read_g1();
    let x1 = t.squeeze_fq();
    let x2 = t.squeeze_fq();
    let x3 = t.squeeze_fq();

    // q_evals_on_x3 (5 values, one per sorted point set)
    let q_evals_on_x3: Vec<Fq> = (0..5).map(|_| t.read_fq()).collect();
    let x4 = t.squeeze_fq();

    // KZG opening witness π
    let pi_pt = t.read_g1();

    assert_eq!(t.pos, proof_bytes.len(), "proof has trailing bytes");

    // ── Build JSON ────────────────────────────────────────────────────────────

    let lookup_permuted: Vec<Value> = (0..N_LOOKUPS).map(|i| json!({
        "input_g1": g1_hex(&lp_input_coms[i]),
        "table_g1": g1_hex(&lp_table_coms[i]),
    })).collect();

    let perm_prod_eval_json: Vec<Value> = perm_prod_evals.iter().enumerate().map(|(i, ev)| {
        if i < N_PERM_PRODUCTS - 1 {
            json!({ "at_x": fq_hex(&ev[0]), "at_xw": fq_hex(&ev[1]), "at_xlast": fq_hex(&ev[2]) })
        } else {
            json!({ "at_x": fq_hex(&ev[0]), "at_xw": fq_hex(&ev[1]) })
        }
    }).collect();

    let lookup_eval_json: Vec<Value> = lookup_evals.iter().map(|ev| json!({
        "product_at_x":      fq_hex(&ev[0]),
        "product_at_xw":     fq_hex(&ev[1]),
        "perm_input_at_x":   fq_hex(&ev[2]),
        "perm_input_at_xwi": fq_hex(&ev[3]),
        "perm_table_at_x":   fq_hex(&ev[4]),
    })).collect();

    let challenges_json = json!({
        "theta": fq_hex(&theta),
        "beta":  fq_hex(&beta),
        "gamma": fq_hex(&gamma),
        "trash": fq_hex(&trash),
        "y":     fq_hex(&y),
        "x":     fq_hex(&x),
        "xn":    fq_hex(&xn),
        "x_next":  fq_hex(&x_next),
        "x_prev":  fq_hex(&x_prev),
        "x_last":  fq_hex(&x_last),
        "x1":    fq_hex(&x1),
        "x2":    fq_hex(&x2),
        "x3":    fq_hex(&x3),
        "x4":    fq_hex(&x4),
    });

    let proof_json = json!({
        "advice_commitments_g1":          advice_coms.iter().map(g1_hex).collect::<Vec<_>>(),
        "lookup_permuted_commitments":     lookup_permuted,
        "perm_product_commitments_g1":     perm_prod_coms.iter().map(g1_hex).collect::<Vec<_>>(),
        "lookup_product_commitments_g1":   lp_prod_coms.iter().map(g1_hex).collect::<Vec<_>>(),
        "random_poly_commitment_g1":       g1_hex(&rand_com),
        "h_commitments_g1":                h_coms.iter().map(g1_hex).collect::<Vec<_>>(),
        "instance_eval":                   fq_hex(&inst_eval),
        "advice_evals":                    advice_evals.iter().map(fq_hex).collect::<Vec<_>>(),
        "fixed_evals":                     fixed_evals.iter().map(fq_hex).collect::<Vec<_>>(),
        "random_poly_eval":                fq_hex(&random_eval),
        "perm_sigma_evals":                perm_common_evals.iter().map(fq_hex).collect::<Vec<_>>(),
        "perm_product_evals":              perm_prod_eval_json,
        "lookup_evals":                    lookup_eval_json,
        "gwc": {
            "f_com_g1":         g1_hex(&f_com),
            "q_evals_on_x3":    q_evals_on_x3.iter().map(fq_hex).collect::<Vec<_>>(),
            "pi_g1":            g1_hex(&pi_pt),
        },
    });

    let out = json!({
        "description": "SHA-256 preimage proof artifacts decoded for the PLONK+GWC verifier",
        "circuit": {
            "k": K,
            "n": N,
            "n_advice_cols": N_ADVICE_COLS,
            "n_lookups": N_LOOKUPS,
            "n_perm_cols": N_PERM_COLS,
            "n_perm_products": N_PERM_PRODUCTS,
            "n_h_coms": N_H_COMS,
            "n_advice_queries": N_ADVICE_QUERIES,
            "n_fixed_queries": N_FIXED_QUERIES,
            "blinding_factors": BLINDING_FACTORS,
        },
        "instance":         instance_json,
        "verifier_params":  params_json,
        "vk":               vk_json,
        "proof":            proof_json,
        "challenges":       challenges_json,
    });

    let out_path = format!("{dir}/sha_preimage_decoded.json");
    let json_str = serde_json::to_string_pretty(&out).expect("json serialization failed");
    fs::write(&out_path, &json_str).expect("failed to write JSON");
    println!("Written {} bytes to {out_path}", json_str.len());
    println!("Fields: instance, verifier_params, vk, proof (commitments + evals + gwc), challenges");
}
