//! Representation of a Trace for a batch of proofs that are being generated
//! simultaneously.

use ff::PrimeField;

use crate::{
    plonk::{lookup, permutation, trash, vanishing},
    poly::{commitment::PolynomialCommitmentScheme, Coeff, LagrangeCoeff, Polynomial},
};

/// Prover's trace of a set of proofs. This type guarantees that the size of the
/// outer vector of its fields has the same size.
#[derive(Debug)]
pub struct ProverTrace<F: PrimeField> {
    pub(crate) advice_polys: Vec<Vec<Polynomial<F, Coeff>>>,
    pub(crate) instance_polys: Vec<Vec<Polynomial<F, Coeff>>>,
    #[allow(dead_code)]
    // This field will be useful for split accumulation
    pub(crate) instance_values: Vec<Vec<Polynomial<F, LagrangeCoeff>>>,
    pub(crate) vanishing: vanishing::prover::Committed<F>,
    pub(crate) lookups: Vec<Vec<lookup::prover::Committed<F>>>,
    pub(crate) trashcans: Vec<Vec<trash::prover::Committed<F>>>,
    pub(crate) permutations: Vec<permutation::prover::Committed<F>>,
    pub(crate) challenges: Vec<F>,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) theta: F,
    pub(crate) trash_challenge: F,
    pub(crate) y: F,
}

/// Verifier's trace of a set of proofs. This type guarantees that the size of
/// the outer vector of its fields has the same size.
#[derive(Debug)]
pub struct VerifierTrace<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> {
    pub(crate) advice_commitments: Vec<Vec<PCS::Commitment>>,
    pub(crate) vanishing: vanishing::verifier::Committed<F, PCS>,
    pub(crate) lookups: Vec<Vec<lookup::verifier::Committed<F, PCS>>>,
    pub(crate) trashcans: Vec<Vec<trash::verifier::Committed<F, PCS>>>,
    pub(crate) permutations: Vec<permutation::verifier::Committed<F, PCS>>,
    pub(crate) challenges: Vec<F>,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) theta: F,
    pub(crate) trash_challenge: F,
    pub(crate) y: F,
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> VerifierTrace<F, PCS> {
    /// Fiat-Shamir challenge for lookup column independence.
    pub fn theta(&self) -> F { self.theta }
    /// Fiat-Shamir challenge for permutation/lookup product arguments (first).
    pub fn beta(&self) -> F { self.beta }
    /// Fiat-Shamir challenge for permutation/lookup product arguments (second).
    pub fn gamma(&self) -> F { self.gamma }
    /// Fiat-Shamir challenge that keeps custom gates linearly independent.
    pub fn y(&self) -> F { self.y }
    /// Fiat-Shamir challenge for the trashcan argument.
    pub fn trash_challenge(&self) -> F { self.trash_challenge }
    /// Phase-based user-defined challenges squeezed during advice absorption.
    pub fn challenges(&self) -> &[F] { &self.challenges }
    /// Advice polynomial commitments read from the proof, grouped by proof index.
    pub fn advice_commitments(&self) -> &[Vec<PCS::Commitment>] { &self.advice_commitments }
}
