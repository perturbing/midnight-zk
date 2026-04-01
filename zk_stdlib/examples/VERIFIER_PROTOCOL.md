# PLONK + GWC Verifier Protocol — SHA-256 Preimage Circuit

This document describes the verification protocol implemented in
`sha_preimage_verify_manual.rs`.  All arithmetic is in the BLS12-381 scalar
field **𝔽** (≈ 2²⁵⁵).  **G₁**, **G₂** are the two elliptic-curve groups;
𝑒 : G₁ × G₂ → G_T is the pairing.

---

## Notation

| Symbol | Meaning |
|--------|---------|
| N = 2¹³ | Domain size |
| ω | Primitive N-th root of unity in 𝔽 |
| H | Multiplicative subgroup ⟨ω⟩ of order N |
| [a]G | Scalar multiplication a·G |
| com(f) | KZG commitment to polynomial f |
| 𝒯 | Fiat-Shamir transcript (Blake2b-512 sponge) |
| absorb(d) | `state.update([0x01] ‖ d)` |
| squeeze() | `state.update([0x00]); Fq::from_uniform_bytes(state.finalize())` |

### Circuit dimensions (SHA-256, K = 13)

| Constant | Value |
|----------|-------|
| N_ADVICE_COLS | 8 |
| N_FIXED_COLS | 32 |
| N_PERM_COLS (σ columns) | 9 |
| N_PERM_PRODUCTS | 3 |
| N_LOOKUPS | 3 |
| N_H_COMS (quotient pieces) | 4 |
| CS_DEGREE | 5 |
| BLINDING_FACTORS | 5 |

---

## Binary inputs

| File | Contents |
|------|----------|
| `sha_preimage_proof.bin` | 4336-byte proof |
| `sha_preimage_vk.bin` | Verifying key (fixed and σ commitments) |
| `sha_preimage_verifier_params.bin` | [τ]G₂ — 96-byte compressed G₂ |
| `sha_preimage_instance.bin` | 32-byte SHA-256 digest (public input) |

---

## Step 1 — Public inputs

The 32-byte SHA-256 digest is mapped to field elements:

$$\mathsf{pi}_i = \mathbb{F}(\mathsf{digest}[i]) \in \mathbb{F}, \quad i = 0,\ldots,31$$

---

## Step 2 — Verifier parameters

Parse the 96-byte file as a compressed G₂ point:

$$[s]G_2 \in G_2$$

Also fix $-G_2$ (the negation of the generator).

---

## Step 3 — Verifying key

From the VK binary (layout: 16-byte arch header, 1-byte k, 4-byte
nb_public_inputs, 1-byte version = 0x03, 1-byte k, 4-byte n_fixed):

$$\mathsf{fixed\_coms}[0..31] \in G_1, \quad \sigma\_\mathsf{coms}[0..8] \in G_1$$

The transcript seed is a hardcoded 32-byte value derived at key-generation time:

$$\tau_{\mathsf{repr}} = \mathsf{Blake2b\text{-}512}(\text{circuit description}) \in \mathbb{F}$$

---

## Step 4 — Fiat-Shamir trace

Initialise 𝒯 with key `b"Domain separator for transcript"`.

**(a)** absorb $\tau_{\mathsf{repr}}$ (32 bytes LE)

**(b)** absorb $\mathbf{0}_{G_1}$ — the committed-instance commitment (48 bytes compressed)

**(c)** absorb $|\mathsf{pi}|$ as 32-byte LE u128, then absorb each $\mathsf{pi}_i$

**(d)** Read 8 advice commitments $A_0,\ldots,A_7 \in G_1$.
Squeeze: $\theta \leftarrow 𝒯$

**(e)** For each lookup $\ell = 0,1,2$, read interleaved pairs:
$$(\mathsf{lp\_input\_com}[\ell],\; \mathsf{lp\_table\_com}[\ell]) \in G_1^2$$
Squeeze: $\beta \leftarrow 𝒯$, $\gamma \leftarrow 𝒯$

**(f)** Read 3 permutation-product commitments $Z_0, Z_1, Z_2 \in G_1$

**(g)** Read 3 lookup-product commitments $\mathsf{lp\_prod\_com}[\ell] \in G_1$
Squeeze: $\mathsf{trash} \leftarrow 𝒯$

**(h)** Read random-poly commitment $R \in G_1$
Squeeze: $y \leftarrow 𝒯$

---

## Step 5a — Read evaluations

**(m)** Read 4 vanishing-quotient commitments $H_0, H_1, H_2, H_3 \in G_1$
Squeeze: $x \leftarrow 𝒯$
Compute: $x^N$, $x_{\text{next}} = x\omega$, $x_{\text{prev}} = x\omega^{-1}$,
$x_{\text{last}} = x\omega^{-6}$

**(n)** Read $\hat{u} \in \mathbb{F}$ — committed-instance polynomial evaluation at $x$

**(o)** Read 24 advice evaluations $\hat{a}_0,\ldots,\hat{a}_{23} \in \mathbb{F}$

**(p)** Read 32 fixed evaluations $\hat{f}_0,\ldots,\hat{f}_{31} \in \mathbb{F}$

**(q)** Read random-poly evaluation $\hat{r} \in \mathbb{F}$

**(r)** Read 9 permutation-σ evaluations $\hat{\sigma}_0,\ldots,\hat{\sigma}_8 \in \mathbb{F}$

**(s)** Read permutation-product evaluations (all at $x$, then $x_{\text{next}}$,
then $x_{\text{last}}$ for non-final products):

$$\hat{z}^{(i)}_x,\; \hat{z}^{(i)}_{x\omega},\; [\hat{z}^{(i)}_{x_{\text{last}}}] \quad i=0,1,2$$

Products 0 and 1 supply 3 values; product 2 (the last chunk) supplies 2.

**(t)** Read per-lookup evaluations (5 per lookup):

$$(\hat{p}^{(\ell)},\; \hat{p}^{(\ell)}_{x\omega},\; \hat{s}^{(\ell)},\; \hat{s}^{(\ell)}_{x\omega^{-1}},\; \hat{t}^{(\ell)}) \quad \ell = 0,1,2$$

where $\hat{p}$ = product, $\hat{s}$ = permuted input, $\hat{t}$ = permuted table.

---

## Step 5b — SHA gate constraint (oracle)

The vanishing polynomial evaluates as

$$H(x) = \frac{\text{gate\_poly}(x)}{x^N - 1}$$

where `gate_poly` encodes all PLONK custom gates for the SHA-256 circuit.
Computing this directly requires inlining the SHA gate polynomials (deferred).

**Current approach** (back-calculation via the GWC f_eval oracle):

Given the GWC challenges $x_1, x_2, x_3$ and the proof-supplied
$Q_i(x_3)$ values (see Step 5c), one can recover $H(x)$:

1. Compute contributions $c_i = \dfrac{Q_i(x_3) - R_i(x_3)}{V_i(x_3)}$ for $i = 1,2,3,4$

2. $c_0 = f_{\text{eval}} - \sum_{i=1}^{4} c_i \cdot x_2^i$

3. $Q_0(x) = Q_0(x_3) - c_0 \cdot (x_3 - x)$

4. $H(x) = \dfrac{Q_0(x) - Q_0^{\text{known}}(x)}{x_1^{45}}$

where $Q_0^{\text{known}}(x)$ is the weighted sum of all set-0 evaluations
*except* the $H$-term (see the sorted-set-0 table in Step 5c).

---

## Step 5c — GWC multi-open

### Evaluation points

$$x_{\text{next}} = x\omega, \quad x_{\text{prev}} = x\omega^{-1}, \quad x_{\text{last}} = x\omega^{-6}$$

### Sorted point sets (5 sets, ordered by |set|, then set_index)

| sorted idx | point set | # coms | commitments |
|------------|-----------|--------|-------------|
| 0 | {x} | 47 | $\mathbf{0}$, lp\_table[0..2], fixed[FIXED\_COL\_INDICES[0..31]], σ[0..8], $H$ (chopped), $R$ |
| 1 | {x, xω} | 4 | $Z_2$, lp\_prod[0..2] |
| 2 | {x, xω⁻¹} | 3 | lp\_input[0..2] |
| 3 | {x, xω, xω⁻¹} | 8 | $A_0,\ldots,A_7$ |
| 4 | {x, xω, xω⁻⁶} | 2 | $Z_0, Z_1$ |

The **chopped** commitment $H$ expands into 4 scalar–point pairs with
splitting factor $\delta = x^{N-1}$:

$$H \mapsto \sum_{i=0}^{3} \delta^i \cdot H_i$$

### Squeeze $x_1, x_2$

For each sorted set $s$, form the combined commitment and evaluation:

$$Q_s = \sum_{j=0}^{|\mathsf{coms}_s|-1} x_1^j \cdot \mathsf{com}_{s,j} \in G_1$$

$$Q_s(p) = \sum_{j=0}^{|\mathsf{coms}_s|-1} x_1^j \cdot \mathsf{eval}_{s,j}(p) \in \mathbb{F} \quad \text{for each } p \in \mathsf{pts}_s$$

### Read $F \in G_1$ from proof

### Squeeze $x_3$

### Read $Q_s(x_3) \in \mathbb{F}$ from proof for each $s$

### Compute f_eval (reverse-Horner)

For each set $s$ let $R_s$ be the polynomial interpolating
$(p, Q_s(p))_{p \in \mathsf{pts}_s}$, and $V_s(X) = \prod_{p \in \mathsf{pts}_s}(X - p)$.

$$c_s = \frac{Q_s(x_3) - R_s(x_3)}{V_s(x_3)}$$

$$f_{\text{eval}} = \sum_{s=0}^{4} c_s \cdot x_2^s \quad \text{(accumulated via reverse-Horner)}$$

### Squeeze $x_4$

$$\mathsf{final\_com} = \sum_{s=0}^{4} x_4^s \cdot Q_s \;+\; x_4^5 \cdot F \in G_1$$

$$v = \sum_{s=0}^{4} x_4^s \cdot Q_s(x_3) \;+\; x_4^5 \cdot f_{\text{eval}} \in \mathbb{F}$$

### Read $\pi \in G_1$ from proof (KZG opening witness)

$$\mathsf{left} = \pi, \qquad \mathsf{right} = \mathsf{final\_com} + x_3 \cdot \pi - v \cdot G_1$$

---

## Step 6 — Pairing check

$$e(\mathsf{left},\; [s]G_2) \cdot e(\mathsf{right},\; -G_2) \stackrel{?}{=} 1_{G_T}$$

This is the standard KZG opening check:
$e(\pi, [\tau - x_3]G_2) = e(\mathsf{final\_com} - [v]G_1, G_2)$.

---

## Proof byte layout (4336 bytes total)

| Byte range | Length | Content |
|------------|--------|---------|
| 0 – 383 | 384 | 8 advice commitments (8 × 48) |
| 384 – 671 | 288 | 6 lookup permuted commitments, interleaved: (input₀, table₀, input₁, table₁, input₂, table₂), 6 × 48 |
| 672 – 815 | 144 | 3 permutation-product commitments (3 × 48) |
| 816 – 959 | 144 | 3 lookup-product commitments (3 × 48) |
| 960 – 1007 | 48 | 1 random-poly commitment |
| 1008 – 1199 | 192 | 4 vanishing-quotient commitments H₀…H₃ (4 × 48) |
| 1200 – 1231 | 32 | 1 committed-instance evaluation (column 0 at x) |
| 1232 – 1999 | 768 | 24 advice evaluations (24 × 32) |
| 2000 – 3023 | 1024 | 32 fixed evaluations (32 × 32) |
| 3024 – 3055 | 32 | 1 random-poly evaluation |
| 3056 – 3343 | 288 | 9 permutation-σ evaluations (9 × 32) |
| 3344 – 3599 | 256 | 8 permutation-product evaluations (8 × 32): products 0,1 give 3 evals each; product 2 gives 2 |
| 3600 – 4079 | 480 | 15 lookup evaluations (3 lookups × 5 × 32) |
| 4080 – 4127 | 48 | f_com — GWC auxiliary commitment F |
| 4128 – 4287 | 160 | 5 combined evaluations Q_s(x₃) (5 × 32) |
| 4288 – 4335 | 48 | π — KZG opening witness |

> The read sequence in Steps 4 and 5 is the authoritative layout definition.
