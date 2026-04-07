# PLONK + KZG Verification Protocol — Mathematical Reference

This document explains the mathematics behind every step in
`sha_preimage_verify_manual.rs`.  It is written as a self-contained
reference so the protocol can be understood and re-implemented without
reading Rust code.

---

## Prerequisites

| Symbol | Meaning |
|--------|---------|
| `𝔽` | BLS12-381 scalar field (`Fq`, order ≈ 2²⁵⁵) |
| `𝔾₁`, `𝔾₂` | Elliptic-curve groups of prime order |
| `e : 𝔾₁ × 𝔾₂ → 𝔾ₜ` | Optimal Ate pairing |
| `G₁`, `G₂` | Fixed generators of 𝔾₁ and 𝔾₂ |
| `[x]G` | Scalar multiplication `x · G` |
| `n = 2ᵏ` | Domain size (here `k = 13`, `n = 8192`) |
| `ω` | Primitive `n`-th root of unity in `𝔽` |
| `Z_H(X) = Xⁿ − 1` | Vanishing polynomial of the multiplicative group `H = {1, ω, …, ωⁿ⁻¹}` |
| `τ` | Toxic waste from the KZG trusted setup; never revealed |

The KZG trusted setup provides `[τ]G₁, [τ²]G₁, …` and `[τ]G₂`.
A commitment to a polynomial `f(X)` is `[f(τ)]G₁`.

---

## Step 0 — Load artifacts

No mathematics.  Four binary files are read from disk:
- `sha_preimage_proof.bin` — the proof transcript (4336 bytes)
- `sha_preimage_vk.bin` — the verifying key (1995 bytes)
- `sha_preimage_verifier_params.bin` — KZG verifier params (96 bytes; one
  compressed G₂ point: `[τ]G₂`)
- `sha_preimage_instance.bin` — 32 raw bytes (the SHA-256 output)

---

## Step 1 — Format public inputs

The SHA-256 circuit exposes each output byte `bᵢ ∈ {0,…,255}` as a field
element.  The mapping is simply the natural injection:

```
πᵢ = bᵢ  (as an element of 𝔽,  i = 0,…,31)
```

The resulting vector **π** = (π₀,…,π₃₁) ∈ 𝔽³² is the statement that the
verifier wants to check: "I know a preimage whose SHA-256 hash is **π**."

---

## Step 2 — Reconstruct G2Prepared objects

The KZG verifier parameters contain a single G₂ point:

```
s_g2 = [τ]G₂
```

Two precomputed values are built for the pairing:

```
s_g2_prepared  = Miller-loop precomputation of  [τ]G₂
neg_g2_prepared= Miller-loop precomputation of  −G₂
```

These are the two G₂ inputs to the final pairing equation (Step 6).

---

## Step 3 — Load the verifying key

The verifying key encodes the *circuit description* as KZG commitments:

```
vk.fixed_commitments[i]       = [q_i(τ)]G₁   (selector / fixed polynomials)
vk.permutation.commitments[i] = [σ_i(τ)]G₁   (copy-constraint permutation)
```

It also stores:

```
vk.transcript_repr ∈ 𝔽
```

This is a Blake2b hash of the entire circuit description (fixed commitments,
permutation commitments, domain parameters, and constraint-system structure).
It is the first value absorbed into the proof transcript, binding the proof
to this exact circuit.

---

## Step 4 — Parse PLONK trace (`parse_trace`)

`parse_trace` runs the Fiat-Shamir sponge, interleaving reads from the
proof with challenge squeezes.  The transcript is a Blake2b-512 state with
key `"Domain separator for transcript"`.

```
Absorb(data)  : state ← state.update([0x01] || data)
Squeeze()     : state ← state.update([0x00]);
                output ← state.finalize()   (64 bytes)
                challenge ← 𝔽::from_uniform_bytes(output[..64])
```

The sequence is:

| # | Operation | Object |
|---|-----------|--------|
| (a) | Absorb | `vk.transcript_repr` (32 bytes) |
| (b) | Absorb | committed-instance commitment (48-byte compressed G₁, `G₁::identity()` for SHA circuit) |
| (c) | Absorb | `|instance|` (32 bytes) + each of 32 public inputs (32 bytes each) |
| (d) | Read + Absorb | 8 advice commitments `Aᵢ = [aᵢ(τ)]G₁` (48 bytes each) |
| — | **Squeeze** | **θ** (theta) |
| (e) | Read + Absorb | permuted lookup commitments (2 × 48 bytes per lookup argument) |
| — | **Squeeze** | **β** |
| — | **Squeeze** | **γ** |
| (f) | Read + Absorb | permutation product commitments `Zσ = [zσ(τ)]G₁` |
| (g) | Read + Absorb | lookup product commitments |
| — | **Squeeze** | **trash\_challenge** |
| (h) | Read + Absorb | trashcan commitments (none in SHA circuit; 0 reads) |
| (i) | Read + Absorb | vanishing random poly commitment `R = [r(τ)]G₁` |
| — | **Squeeze** | **y** |

### What each challenge does

**θ (theta)** — Lookup column-independence challenge.

The lookup argument checks that the vector `f ⊂ t` (every element of `f`
appears in `t`).  When the table has multiple columns, they are compressed
into one using powers of `θ`:

```
f_compressed(X) = f₁(X) + θ·f₂(X) + θ²·f₃(X) + …
t_compressed(X) = t₁(X) + θ·t₂(X) + θ²·t₃(X) + …
```

A random `θ` ensures these linear combinations are independent with high
probability.

**β, γ** — Permutation (copy-constraint) argument challenges.

The copy-constraint argument uses a grand-product polynomial `Zσ(X)`.  It
encodes the constraint "the evaluations of two cells are equal" via:

```
Zσ(ωX) · ∏ᵢ (aᵢ(X) + β·σᵢ(X) + γ)  =  Zσ(X) · ∏ᵢ (aᵢ(X) + β·idᵢ(X) + γ)
```

where `σᵢ` is the permutation polynomial and `idᵢ(X) = X·δⁱ` is an identity
polynomial (`δ` is a coset shift).  β and γ make the products non-degenerate
with overwhelming probability.

The same pair (β, γ) also appears in the lookup product argument (Plookup):

```
Zl(ωX) · (1+β) · (f'(X) + β·t(X) + γ)  =  Zl(X) · (f'(X) + β·f'(ωX) + γ(1+β)) · (t(X) + β·t(ωX) + γ(1+β))
```

**y** — Gate-linearity challenge.

All custom gate constraints and argument constraints are combined into a single
polynomial via powers of `y`:

```
P(X) = ∑ᵢ yⁱ · constraintᵢ(X)
```

The vanishing polynomial `h(X)` satisfies `P(X) = h(X) · Z_H(X)`.

---

## Step 5a — Verify algebraic constraints

After `parse_trace`, the transcript continues.

### (m) Read quotient polynomial pieces

The quotient polynomial `h(X)` has degree `(cs_degree − 1) · n` and is split
into `cs_degree` pieces `h₀(X), …, h_{d-1}(X)` of degree `< n` such that:

```
h(X) = h₀(X) + Xⁿ·h₁(X) + X²ⁿ·h₂(X) + …
```

The prover sends commitments `Hᵢ = [hᵢ(τ)]G₁`.

### (n) Squeeze x; compute xⁿ

```
x ← Squeeze()
xⁿ = x raised to the n-th power
```

`x` is the random evaluation point at which the verifier checks all
polynomial identities.

### (o) Instance evaluation via Lagrange interpolation

The instance polynomial `L(X)` encodes the public inputs:

```
L(ωⁱ) = πᵢ   for i = 0, …, 31
```

The Lagrange basis polynomials are:

```
lᵢ(x) = (xⁿ − 1) / (n · (x − ωⁱ))
```

The evaluation `L(x)` is computed without knowing `L` explicitly:

```
L(x) = ∑ᵢ πᵢ · lᵢ(x)
```

### (p–q) Read evaluations

The prover sends:
- `a_eval[j]  = aⱼ(x·ωʳ)` for each advice query `(j, rotation r)`
- `q_eval[j]  = qⱼ(x·ωʳ)` for each fixed query `(j, rotation r)`
- `r_eval      = r(x)`       for the vanishing random polynomial
- `σ_eval[i]  = σᵢ(x)`       for each permutation column
- `Zσ_evals   = {Zσ(x), Zσ(ωx), Zσ(ω⁻¹x)}`  for permutation products
- lookup evaluations (5 values per lookup argument)

### (r) evaluate_identities — the core constraint check

This is the verifier's algebraic check.  It asserts:

```
h(x) · Z_H(x) = P(x)
```

where the right-hand side `P(x)` is computed from the claimed evaluations
and where:

```
h(x) = h₀(x) + xⁿ·h₁(x) + x²ⁿ·h₂(x) + …
Z_H(x) = xⁿ − 1
```

Specifically, it verifies that the claimed `h(x)` satisfies:

```
h(x) · (xⁿ − 1)  =  ∑ᵢ yⁱ · gateᵢ(x, advice, fixed, instance)
                   + ∑ permutation_constraints(x, …)
                   + ∑ lookup_constraints(x, …)
```

If this equation does not hold, the verifier rejects immediately.  If it
holds, we are convinced the circuit is satisfied *modulo* the polynomial
commitments opening to the correct values — which is what the GWC step checks.

### (s) Build the VerifierQuery list

The verifier constructs a list of tuples `(commitment Cⱼ, point pⱼ, claimed value vⱼ)`.
Each tuple asserts `polyⱼ(pⱼ) = vⱼ`.  The full list covers:

- Advice polynomial commitments `Aᵢ` at rotations of `x`
- Fixed polynomial commitments (from VK) at rotations of `x`
- Permutation σ commitments at `x`
- Permutation product commitments `Zσ` at `x`, `ωx`, `ω⁻ᵇˡⁱⁿᵈ·x`
- Lookup permuted + product commitments at appropriate rotations
- Vanishing polynomial pieces `Hᵢ` at `x`
- Vanishing random polynomial `R` at `x`

---

## Step 5b — GWC multi-open (`gwc_multi_open_explicit`)

The GWC (Generalized/Boneh-type Kate commitment scheme for multiple openings)
from the Halo 2 design reduces all of the above opening claims to a *single*
KZG opening.

Reference:
[Halo 2 Book — Multipoint Opening](https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html)

### Group queries by evaluation-point set

The query list has polynomials queried at different subsets of `{x, ωx, ω⁻¹x, …}`.
Group them by their *set* of evaluation points:

```
Set 0: polynomials queried only at {x}             (fixed, vanishing pieces, …)
Set 1: polynomials queried at {x, ωx}              (lookup permuted, …)
Set 2: polynomials queried at {x, ωx, ω⁻¹x}       (permutation products, …)
…  (5 sets total for the SHA-256 circuit)
```

### (t) Squeeze x1, x2

**x1** batches commitments *within* each set (different polynomials evaluated
at the same point set).  For set `i` containing polynomials `Cᵢ₀, Cᵢ₁, …`:

```
q_com_i = ∑ⱼ x1ʲ · Cᵢⱼ   ∈ 𝔾₁
```

The combined polynomial `Q_i(X)` satisfies:

```
Q_i(p) = ∑ⱼ x1ʲ · polyᵢⱼ(p)   for every evaluation point p in Set i
```

**x2** batches the *sets* into one.  The prover builds an auxiliary polynomial:

```
f(X) = ∑ᵢ x2ⁱ · [Q_i(X) − R_i(X)] / V_i(X)
```

where:
- `R_i(X)` is the unique polynomial of degree `< |Set i|` satisfying
  `R_i(pᵢⱼ) = q_com_i evaluated at pᵢⱼ` (the Lagrange interpolant through
  the claimed evaluation pairs)
- `V_i(X) = ∏ⱼ (X − pᵢⱼ)` is the vanishing polynomial of Set i

`f(X)` encodes the entire multi-opening claim in one polynomial.

### (u) Read f_com

```
f_com = [f(τ)]G₁   (read 48 bytes from proof, absorb into transcript)
```

### (v) Squeeze x3; read q_evals_on_x3; compute f_eval

```
x3 ← Squeeze()
q_eval_i = Q_i(x3)   for i = 0, …, |sets|−1   (read from proof)
```

The verifier recomputes `f(x3)` from the claimed evaluations:

```
for each set i (iterating in reverse for the folding to work):
  R_i(x3)  = lagrange_interpolate({pᵢⱼ}, {claimed evals at pᵢⱼ})(x3)
  eval_i   = (q_eval_i − R_i(x3)) / ∏ⱼ (x3 − pᵢⱼ)

f_eval = ∑ᵢ x2ⁱ · eval_i
```

This is the value `f(x3)` that the prover *should* have if all claimed
evaluations are correct.

### (w) Squeeze x4; combine into final_com and v

**x4** batches the `Q_i` polynomials and `f` into one final polynomial:

```
final_poly(X) = ∑ᵢ x4ⁱ · Q_i(X) + x4^|sets| · f(X)
final_com     = ∑ᵢ x4ⁱ · q_com_i + x4^|sets| · f_com   ∈ 𝔾₁
v             = ∑ᵢ x4ⁱ · q_eval_i + x4^|sets| · f_eval  ∈ 𝔽
```

`final_com = [final_poly(τ)]G₁` and `v = final_poly(x3)` (if everything is
honest).  The whole multi-opening has now been compressed into the single
claim `final_poly(x3) = v`.

### (x) Read π; build pairing inputs

The prover sends the KZG witness for `final_poly(x3) = v`:

```
π = [(final_poly(τ) − v) / (τ − x3)] G₁   (read 48 bytes from proof)
```

The pairing inputs are:

```
left  = π
right = final_com + x3·π − v·G₁
      = [final_poly(τ)]G₁ + x3·π − v·G₁
```

---

## Step 6 — Pairing check

The verifier evaluates:

```
e(left, [τ]G₂) · e(right, −G₂)  =?  1_{GT}
```

### Why this works

Start from the KZG relation:

```
π = [(final_poly(τ) − v) / (τ − x3)] G₁
⟹  (τ − x3) · π = (final_poly(τ) − v) · G₁
⟹  [τ]G₁ · π / G₁ − x3·π = final_poly(τ)·G₁ − v·G₁      (heuristically)
```

More precisely, using bilinearity:

```
e(π, [τ]G₂)
= e([(final_poly(τ)−v)/(τ−x3)]G₁, [τ]G₂)
= e([(final_poly(τ)−v)/(τ−x3)]G₁, τ·G₂)
```

We want to check that `right = final_com − v·G₁ + x3·π`:

```
e(π, [τ]G₂) · e(right, −G₂)
= e(π, [τ]G₂) · e(final_com − v·G₁ + x3·π, −G₂)
```

Expand using bilinearity (`e(A+B, C) = e(A,C)·e(B,C)`):

```
= e(π, [τ]G₂) · e([final_poly(τ)]G₁, −G₂) · e(−v·G₁, −G₂) · e(x3·π, −G₂)
= e(π, [τ]G₂) · e(π, −x3·G₂) · e([final_poly(τ)−v]G₁, −G₂)
= e(π, ([τ]−x3)·G₂) · e([final_poly(τ)−v]G₁, −G₂)
```

If `π` is honest then `(τ−x3)·π = (final_poly(τ)−v)·G₁`, so:

```
= e((final_poly(τ)−v)·G₁/(τ−x3), (τ−x3)·G₂) · e([final_poly(τ)−v]G₁, −G₂)
= e([final_poly(τ)−v]G₁, G₂) · e([final_poly(τ)−v]G₁, −G₂)
= e([final_poly(τ)−v]G₁, G₂ − G₂)
= e(…, 0)
= 1_{GT}  ✓
```

An adversarial prover who does not know a valid witness cannot produce a `π`
that passes this check without breaking the discrete-log hardness of 𝔾₁ or
the `d-Strong Diffie-Hellman` assumption in the KZG setup.

---

## Complete verification flow

```
Proof bytes ──────────────────────────────────────────────────────────┐
                                                                       │
Step 1:  π₀,…,π₃₁ = hash_bytes_as_Fq                                 │
Step 2:  s_g2_prepared, neg_g2_prepared                                │
Step 3:  vk (fixed + permutation commitments, transcript_repr)         │
                                                                       │
Step 4 [parse_trace]:                                                  │
  Absorb vk.transcript_repr, committed_pi, instance                   │
  Read advice coms A₀,…,A₇; squeeze θ                                 │
  Read lookup-permuted coms; squeeze β, γ                              │
  Read permutation product coms; squeeze trash_challenge               │
  Read vanishing random poly com R; squeeze y                          │
  → VerifierTrace{θ, β, γ, y, trash, A₀,…,A₇, …}                     │
                                                                       │
Step 5a [verify_algebraic_constraints]:                                │
  Read h_com pieces H₀,…,Hd₋₁; squeeze x; compute xⁿ                 │
  Compute instance_eval = Σᵢ πᵢ·lᵢ(x) via Lagrange                   │
  Read advice_evals, fixed_evals, permutation_evals, lookup_evals      │
  Verify: h(x)·(xⁿ−1) = Σᵢ yⁱ·gateᵢ(x) + perm(x) + lookup(x)       │
  Build VerifierQuery list                                             │
                                                                       │
Step 5b [gwc_multi_open_explicit]:                                     │
  squeeze x1, x2                                                       │
  Group queries by eval-point set; combine with x1 → q_com_i          │
  Read f_com; squeeze x3                                               │
  Read q_eval_i(x3); compute f_eval via Lagrange                       │
  squeeze x4                                                           │
  final_com = Σᵢ x4ⁱ·q_com_i + x4^|sets|·f_com                       │
  v         = Σᵢ x4ⁱ·q_eval_i + x4^|sets|·f_eval                     │
  Read π                                                               │
  left  = π                                                            │
  right = final_com + x3·π − v·G₁                                     │
                                                                       │
Step 6 [pairing]:                                                      │
  e(left, [τ]G₂) · e(right, −G₂) = 1_{GT}  ?                         │
```
