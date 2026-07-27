//! End-to-end tests for selector compression: keygen with
//! `keygen_vk_with_k_and_compression` must produce fewer fixed commitments
//! than the direct selector conversion, and proofs must verify in both modes.

use blake2b_simd::State;
use ff::Field;
use midnight_curves::{Bls12, Fq as Scalar};
use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk_with_k, keygen_vk_with_k_and_compression, prepare,
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, ProvingKey, Selector,
        TableColumn, VerifyingKey,
    },
    poly::{
        commitment::Guard,
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
        Rotation,
    },
    transcript::{CircuitTranscript, Transcript},
    utils::SerdeFormat,
};
use rand_core::OsRng;

type Scheme = KZGCommitmentScheme<Bls12>;
type TranscriptType = CircuitTranscript<State>;

const K: u32 = 7;
const NUM_SMALL_SELECTORS: usize = 9;

/// A selector-heavy circuit: `NUM_SMALL_SELECTORS` simple selectors each gate
/// a low-degree gate on their own region (so they are mutually exclusive and
/// compressible), one selector gates a gate at the constraint-system degree
/// bound (no headroom, so it cannot share), and a complex selector activates
/// a lookup.
#[derive(Clone)]
struct CompressCircuit<F: Field> {
    x: Value<F>,
}

#[derive(Clone)]
struct CompressConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    small_selectors: Vec<Selector>,
    s_big: Selector,
    s_lookup: Selector,
    table: TableColumn,
}

impl<F: ff::FromUniformBytes<64> + Ord> Circuit<F> for CompressCircuit<F> {
    type Config = CompressConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        CompressCircuit { x: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        meta.enable_equality(a);

        // A gate of degree 5 (including its virtual selector), which pins the
        // constraint-system degree that compression must respect.
        let s_big = meta.selector();
        meta.create_gate("big", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            Constraints::with_selector(
                s_big,
                vec![("a^2 * b^2 = c", a.clone() * a * b.clone() * b - c)],
            )
        });

        // Many low-degree gates, one selector each. Regions are laid out
        // sequentially, so these selectors are mutually exclusive and can
        // share fixed columns.
        let small_selectors: Vec<Selector> = (0..NUM_SMALL_SELECTORS)
            .map(|i| {
                let s = meta.selector();
                meta.create_gate("small", |meta| {
                    let a = meta.query_advice(a, Rotation::cur());
                    let b = meta.query_advice(b, Rotation::cur());
                    let c = meta.query_advice(c, Rotation::cur());
                    let poly = if i % 2 == 0 {
                        a * b - c
                    } else {
                        a + b - c
                    };
                    Constraints::with_selector(s, vec![("small gate", poly)])
                });
                s
            })
            .collect();

        // A lookup gated by a complex selector, exercising selector
        // replacement in non-gate expressions.
        let s_lookup = meta.complex_selector();
        let table = meta.lookup_table_column();
        meta.lookup("range", Some(s_lookup), |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            vec![(a, table)]
        });

        CompressConfig {
            a,
            b,
            c,
            small_selectors,
            s_big,
            s_lookup,
            table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "table",
            |mut table| {
                for i in 0..16 {
                    table.assign_cell(
                        || "table",
                        config.table,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        for (i, s) in config.small_selectors.iter().enumerate() {
            layouter.assign_region(
                || "small",
                |mut region| {
                    s.enable(&mut region, 0)?;
                    let x = self.x + Value::known(F::from(i as u64));
                    let y = Value::known(F::from(2u64));
                    let z = if i % 2 == 0 { x * y } else { x + y };
                    region.assign_advice(|| "a", config.a, 0, || x)?;
                    region.assign_advice(|| "b", config.b, 0, || y)?;
                    region.assign_advice(|| "c", config.c, 0, || z)?;
                    Ok(())
                },
            )?;
        }

        layouter.assign_region(
            || "big",
            |mut region| {
                config.s_big.enable(&mut region, 0)?;
                let x = self.x;
                region.assign_advice(|| "a", config.a, 0, || x)?;
                region.assign_advice(|| "b", config.b, 0, || x)?;
                region.assign_advice(|| "c", config.c, 0, || x * x * x * x)?;
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "lookup",
            |mut region| {
                config.s_lookup.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.a, 0, || Value::known(F::from(7u64)))?;
                region.assign_advice(|| "b", config.b, 0, || Value::known(F::ZERO))?;
                region.assign_advice(|| "c", config.c, 0, || Value::known(F::ZERO))?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// SHA-256 over the zk-stdlib: a realistic, selector-heavy circuit, close to
/// the ones verified on-chain. Measures the fixed-commitment count with and
/// without compression and checks a proof verifies in compressed mode.
#[test]
fn compress_selectors_stdlib_sha256() {
    use midnight_circuits::instructions::AssignmentInstructions;
    use midnight_proofs::plonk::k_from_circuit;
    use midnight_zk_stdlib::{MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch};

    #[derive(Clone)]
    struct Sha256Relation;

    impl Relation for Sha256Relation {
        type Instance = ();
        type Witness = ();
        type Error = Error;

        fn format_instance(_instance: &Self::Instance) -> Result<Vec<Scalar>, Error> {
            Ok(vec![])
        }

        fn circuit(
            &self,
            std_lib: &ZkStdLib,
            layouter: &mut impl Layouter<Scalar>,
            _instance: Value<Self::Instance>,
            _witness: Value<Self::Witness>,
        ) -> Result<(), Error> {
            let input = std_lib.assign_many(
                layouter,
                &[
                    Value::known(13u8),
                    Value::known(226u8),
                    Value::known(119u8),
                    Value::known(5u8),
                ],
            )?;
            let _hash = std_lib.sha2_256(layouter, &input)?;
            Ok(())
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
            Ok(Sha256Relation)
        }
    }

    let circuit = MidnightCircuit::from_relation(&Sha256Relation, None);
    let k = k_from_circuit(&circuit);
    let params = ParamsKZG::<Bls12>::unsafe_setup(k, OsRng);

    let vk_direct: VerifyingKey<Scalar, Scheme> =
        keygen_vk_with_k(&params, &circuit, k).expect("keygen_vk should not fail");
    let vk_compressed: VerifyingKey<Scalar, Scheme> =
        keygen_vk_with_k_and_compression(&params, &circuit, k)
            .expect("keygen_vk with compression should not fail");

    let direct_count = vk_direct.fixed_commitments().len();
    let compressed_count = vk_compressed.fixed_commitments().len();
    println!("stdlib sha256 fixed commitments without compression: {direct_count}");
    println!("stdlib sha256 fixed commitments with compression:    {compressed_count}");
    assert!(compressed_count < direct_count);

    let pk = keygen_pk(vk_compressed, &circuit).expect("keygen_pk should not fail");

    let mut transcript = TranscriptType::init();
    create_proof::<Scalar, Scheme, _, _>(
        &params,
        &pk,
        &circuit,
        #[cfg(feature = "committed-instances")]
        0,
        &[&[], &[]],
        &mut transcript,
        OsRng,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let mut transcript = TranscriptType::init_from_bytes(&proof);
    let verifier = prepare::<Scalar, Scheme, _>(
        pk.get_vk(),
        #[cfg(feature = "committed-instances")]
        &[],
        &[&[], &[]],
        &mut transcript,
    )
    .expect("proof preparation should not fail");
    verifier.verify(&params.verifier_params()).expect("proof verification should not fail");
}

fn prove_and_verify(params: &ParamsKZG<Bls12>, pk: &ProvingKey<Scalar, Scheme>) {
    let circuit = CompressCircuit {
        x: Value::known(Scalar::from(5u64)),
    };

    let mut transcript = TranscriptType::init();
    create_proof::<Scalar, Scheme, _, _>(
        params,
        pk,
        &circuit,
        #[cfg(feature = "committed-instances")]
        0,
        &[] as &[&[Scalar]],
        &mut transcript,
        OsRng,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let mut transcript = TranscriptType::init_from_bytes(&proof);
    let verifier = prepare::<Scalar, Scheme, _>(
        pk.get_vk(),
        #[cfg(feature = "committed-instances")]
        &[],
        &[] as &[&[Scalar]],
        &mut transcript,
    )
    .expect("proof preparation should not fail");
    verifier.verify(&params.verifier_params()).expect("proof verification should not fail");
}

#[test]
fn compress_selectors_end_to_end() {
    let circuit = CompressCircuit::<Scalar> {
        x: Value::known(Scalar::from(5u64)),
    };
    let prover = MockProver::run(&circuit, vec![]).expect("MockProver::run should not fail");
    prover.assert_satisfied();

    let params = ParamsKZG::<Bls12>::unsafe_setup(K, OsRng);
    let empty_circuit = CompressCircuit::<Scalar> { x: Value::unknown() };

    let vk_direct: VerifyingKey<Scalar, Scheme> =
        keygen_vk_with_k(&params, &empty_circuit, K).expect("keygen_vk should not fail");
    let vk_compressed: VerifyingKey<Scalar, Scheme> =
        keygen_vk_with_k_and_compression(&params, &empty_circuit, K)
            .expect("keygen_vk with compression should not fail");

    let direct_count = vk_direct.fixed_commitments().len();
    let compressed_count = vk_compressed.fixed_commitments().len();
    println!("fixed commitments without compression: {direct_count}");
    println!("fixed commitments with compression:    {compressed_count}");

    // 9 mutually-exclusive degree-3 selectors pack 3 per column (degree
    // headroom 5 - 2 = 3), the degree-5 gate's selector and the complex
    // lookup selector each keep their own column: 11 selector columns
    // become 5 (the 12th fixed column is the lookup table).
    assert!(
        direct_count - compressed_count >= 6,
        "expected a substantial drop in fixed commitments: {compressed_count} vs {direct_count}"
    );

    // Compression is a different circuit encoding, so the transcript
    // representation must differ.
    assert_ne!(vk_direct.transcript_repr(), vk_compressed.transcript_repr());

    // Proofs verify in both modes.
    let pk_direct =
        keygen_pk(vk_direct, &empty_circuit).expect("keygen_pk should not fail");
    prove_and_verify(&params, &pk_direct);

    let pk_compressed =
        keygen_pk(vk_compressed, &empty_circuit).expect("keygen_pk should not fail");
    prove_and_verify(&params, &pk_compressed);
}

#[test]
fn compress_selectors_vk_serialization_roundtrip() {
    let params = ParamsKZG::<Bls12>::unsafe_setup(K, OsRng);
    let empty_circuit = CompressCircuit::<Scalar> { x: Value::unknown() };

    for compress in [false, true] {
        let vk: VerifyingKey<Scalar, Scheme> = if compress {
            keygen_vk_with_k_and_compression(&params, &empty_circuit, K).unwrap()
        } else {
            keygen_vk_with_k(&params, &empty_circuit, K).unwrap()
        };

        let bytes = vk.to_bytes(SerdeFormat::RawBytes);
        assert_eq!(bytes.len(), vk.bytes_length(SerdeFormat::RawBytes));
        let vk_read: VerifyingKey<Scalar, Scheme> =
            VerifyingKey::from_bytes::<CompressCircuit<Scalar>>(
                &bytes,
                SerdeFormat::RawBytes,
                #[cfg(feature = "circuit-params")]
                (),
            )
            .expect("VK deserialization should not fail");

        // The deserialized VK must replay the same selector conversion:
        // same columns, same gate expressions, same transcript representative.
        assert_eq!(vk.transcript_repr(), vk_read.transcript_repr());
        assert_eq!(
            vk.fixed_commitments().len(),
            vk_read.fixed_commitments().len()
        );

        // A proof generated under the original key verifies with the
        // deserialized one.
        let pk = keygen_pk(vk, &empty_circuit).unwrap();
        let circuit = CompressCircuit {
            x: Value::known(Scalar::from(5u64)),
        };
        let mut transcript = TranscriptType::init();
        create_proof::<Scalar, Scheme, _, _>(
            &params,
            &pk,
            &circuit,
            #[cfg(feature = "committed-instances")]
            0,
            &[] as &[&[Scalar]],
            &mut transcript,
            OsRng,
        )
        .unwrap();
        let proof = transcript.finalize();

        let mut transcript = TranscriptType::init_from_bytes(&proof);
        let verifier = prepare::<Scalar, Scheme, _>(
            &vk_read,
            #[cfg(feature = "committed-instances")]
            &[],
            &[] as &[&[Scalar]],
            &mut transcript,
        )
        .unwrap();
        verifier
            .verify(&params.verifier_params())
            .expect("proof must verify under the deserialized VK");
    }
}
