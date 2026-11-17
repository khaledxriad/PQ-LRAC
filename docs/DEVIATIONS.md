# How this prototype relates to the paper

This repository is a **Python reference prototype** of the construction in the manuscript. It was written
as a self-contained, testable implementation of the paper's algorithms (Setup, KeyGen, Encrypt,
outsourced Transform, final Decrypt with LSSS reconstruction and the Fujisaki-Okamoto-style re-encryption
check). It is **not** the C / ARM Cortex-M code that produced the timings in Tables 1-5, and its timings
and ciphertext sizes must not be read as those results.

## Instantiation choices (where the paper's algebra is not fully specified)

| Item | Paper | Prototype |
|---|---|---|
| Ring / parameters | R_q = Z_q[X]/(X^256+1), q ~ 2^13 prime | q = 7681, n = 256, module rank K = 2, centred-binomial (eta = 2) errors and secrets |
| Attribute keys | `SK_i = SamplePre(T, A, H(i), sigma)`, `A*SK_i = H(i)` | No trapdoor. The authority samples short `s_i` and publishes an MLWE public key `p_i = A s_i + e_i` per attribute in the public parameters. `H(i)` is therefore not a random oracle on attribute names. |
| Encryption | Regev-style with policy basis `B_A` | Module-Regev: `u = A^T r + e1`, one `v_j = p_rho(j)^T r + e2_j + floor(q/2)*share_j` per LSSS row |
| LSSS | LSSS matrix over a field | Matrix over GF(2) (bit shares), built from AND/OR/threshold formulas; reconstruction coefficients in {0,1} |
| Transformation key | `TK = (P = AR+E, Q = (sum SK_i)G + R) + eta`, MSB/LSB split | Rank-one blinding: `TK_i = s_i + c_i*y` (cloud) with `(y, c_i)` kept by the user; the user's cost is one inner product `y^T u` plus one scalar multiplication per used row |
| CCA2 transform | seed `M`, coins `G(M, policy)`, AEAD under `KDF(M)`, re-encryption check | Same; SHAKE-256 for `G`/`KDF`, ChaCha20-Poly1305 for the AEAD |
| Compression | lossless bit-packing + run-length encoding | 13-bit packing only (no run-length coding) |
| NTT | optimised butterflies, ARM assembly | dense-matrix negacyclic NTT in NumPy (correct, O(n^2)) |

## Not implemented

* Gaussian trapdoor sampling (`TrapGen`, `SamplePre`) and the hash-to-syndrome oracle `H`.
* The noise-flooding term `eta` in the transformation key and the key splitting into MSB/LSB parts.
  Leakage resilience is a property proven in Section 5.3 of the paper; this code does not demonstrate it.
* The optional zero-knowledge proof of correct cloud computation.
* The majority vote over several authorized subsets (the prototype uses the single subset found by the
  GF(2) solver, i.e. r = 1).
* Collusion resistance: attribute secrets `s_i` are shared by all users holding attribute i, so two users
  with different attributes can pool them. The blinding of the transformation key has no security proof.

## Consequences

* Ciphertext size here is about 0.42 KB per policy row (one ring element of 256 x 13 bits), plus a fixed
  0.83 KB for `u`. This is a property of the module-Regev instantiation above, not of the paper's
  measurements.
* **Do not use this code to protect real data.** It is research code and has not been audited.
