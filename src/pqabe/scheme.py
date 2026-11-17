"""Prototype of the outsourced-decryption lattice ABE described in the paper.

Structure (see docs/DEVIATIONS.md for what differs from the paper):
  setup        qAA: public matrix A in R_q^{KxK}, one MLWE public key p_i = A s_i + e_i per attribute
  keygen       qAA: user secret key SK = {s_i : i in S}
  make_transform_key   user: blind SK into a transformation key TK_i = s_i + c_i*y for the cloud
  encrypt      FO-style hybrid: random 256-bit seed M, coins = G(M || policy), LSSS shares of M
               encrypted per row (module-Regev), payload under AEAD with key KDF(M)
  cloud_transform      cloud: partial decryption with TK (no access to s_i or M)
  user_finalize        user: unblind, round, LSSS-reconstruct, re-encryption check, AEAD decrypt
"""
import hashlib
import os
from dataclasses import dataclass

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .lsss import build_lsss, policy_bytes, reconstruction_coeffs
from .ring import N, Q, intt, ntt

K = 2        # module rank
ETA = 2      # centred binomial parameter for secrets and errors
HALF = Q // 2


# ---------------------------------------------------------------- sampling
def _xof(*parts, length):
    h = hashlib.shake_256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest(length)


def _uniform(seed, count):
    buf = np.frombuffer(_xof(seed, b"A", length=count * 8), dtype="<u2")
    buf = buf[buf < (65536 // Q) * Q] % Q
    if len(buf) < count:
        raise RuntimeError("rejection sampling ran out of bytes")
    return buf[:count].astype(np.int64)


def _cbd(buf, count):
    """`count` centred-binomial(ETA=2) samples from count/2 bytes."""
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8))[: 4 * count].reshape(count, 4).astype(np.int64)
    return bits[:, 0] + bits[:, 1] - bits[:, 2] - bits[:, 3]


def _cbd_random(shape):
    count = int(np.prod(shape))
    return _cbd(os.urandom((count + 1) // 2), count).reshape(shape)


# ---------------------------------------------------------------- bit packing (lossless, 13 bits)
def _pack(vals):
    v = np.asarray(vals, dtype=np.int64).reshape(-1) % Q
    bits = ((v[:, None] >> np.arange(12, -1, -1)) & 1).astype(np.uint8).reshape(-1)
    return np.packbits(bits).tobytes()


# ---------------------------------------------------------------- data classes
@dataclass
class PublicParams:
    seed: bytes
    A_hat: np.ndarray     # (K, K, N) NTT domain
    P_hat: dict           # attribute -> (K, N) NTT domain


@dataclass
class Ciphertext:
    policy: object
    u: np.ndarray         # (K, N)
    v: np.ndarray         # (L, N)
    nonce: bytes
    body: bytes

    def to_bytes(self):
        pol = policy_bytes(self.policy)
        return len(pol).to_bytes(4, "big") + pol + _pack(self.u) + _pack(self.v) + self.nonce + self.body


# ---------------------------------------------------------------- setup / keygen
def setup(universe):
    """qAA initialisation. Returns (PP, MSK). MSK holds the per-attribute secrets s_i."""
    seed = os.urandom(32)
    A_hat = ntt(_uniform(seed, K * K * N).reshape(K, K, N))
    P_hat, msk = {}, {}
    for attr in universe:
        s = _cbd_random((K, N))
        e = _cbd_random((K, N))
        s_hat = ntt(s)
        p_hat = ((A_hat * s_hat[None]).sum(axis=1) + ntt(e)) % Q       # p = A s + e
        P_hat[attr] = p_hat
        msk[attr] = s
    return PublicParams(seed, A_hat, P_hat), msk


def keygen(msk, attrs):
    """qAA issues SK = {s_i} for the user's attribute set."""
    return {a: msk[a].copy() for a in attrs}


def make_transform_key(sk):
    """User-side: TK_i = s_i + c_i*y (cloud part) and the local blinding (y, {c_i})."""
    y_hat = (np.frombuffer(os.urandom(K * N * 4), dtype="<u4") % Q).astype(np.int64).reshape(K, N)
    tk, c = {}, {}
    for a, s in sk.items():
        ci = int.from_bytes(os.urandom(4), "big") % (Q - 1) + 1
        tk[a] = (ntt(s) + ci * y_hat) % Q
        c[a] = ci
    return tk, (y_hat, c)


# ---------------------------------------------------------------- encryption
def _lattice_encrypt(pp, policy, M, lsss):
    """Deterministic given (M, policy): all randomness is G(M || policy)."""
    Mat, rho = lsss
    L, c = Mat.shape
    pol = policy_bytes(policy)
    r = _cbd(_xof(M, pol, b"r", length=K * N // 2), K * N).reshape(K, N)
    e1 = _cbd(_xof(M, pol, b"e1", length=K * N // 2), K * N).reshape(K, N)
    e2 = _cbd(_xof(M, pol, b"e2", length=(L * N + 1) // 2), L * N).reshape(L, N)
    rnd = np.unpackbits(np.frombuffer(_xof(M, pol, b"shares", length=(max(c - 1, 0) * N + 7) // 8 + 1),
                                      dtype=np.uint8))[: max(c - 1, 0) * N].reshape(max(c - 1, 0), N)
    V = np.concatenate([np.unpackbits(np.frombuffer(M, dtype=np.uint8))[None, :], rnd], axis=0).astype(np.int64)
    lam = (Mat.astype(np.int64) @ V) % 2                                  # (L, N) bit shares

    r_hat = ntt(r)
    u = (intt((pp.A_hat * r_hat[:, None]).sum(axis=0)) + e1) % Q          # u = A^T r + e1
    P = np.stack([pp.P_hat[a] for a in rho])                              # (L, K, N)
    v = (intt((P * r_hat[None]).sum(axis=1)) + e2 + HALF * lam) % Q       # v_j = p_j^T r + e2_j + q/2 * share_j
    return u, v


def encrypt(pp, policy, payload, aad=b""):
    M = os.urandom(32)                                  # random 256-bit seed (one coefficient bit each)
    lsss = build_lsss(policy)
    u, v = _lattice_encrypt(pp, policy, M, lsss)
    key = _xof(M, b"kdf", length=32)
    nonce = os.urandom(12)
    body = ChaCha20Poly1305(key).encrypt(nonce, payload, aad + policy_bytes(policy))
    return Ciphertext(policy, u, v, nonce, body)


# ---------------------------------------------------------------- decryption
def cloud_transform(ct, tk):
    """Cloud: w'_j = v_j - <TK_rho(j), u> for every row j whose attribute the user holds."""
    _, rho = build_lsss(ct.policy)
    rows = [j for j, a in enumerate(rho) if a in tk]
    if not rows:
        return {}
    u_hat = ntt(ct.u)
    TK = np.stack([tk[rho[j]] for j in rows])
    s_u = intt((TK * u_hat[None]).sum(axis=1))
    w = (ct.v[rows] - s_u) % Q
    return {j: w[i] for i, j in enumerate(rows)}


def user_finalize(pp, ct, partial, local, aad=b"", check=True, return_noise=False):
    """User: remove the blinding, decode, reconstruct via LSSS, re-encrypt check, AEAD decrypt."""
    y_hat, c = local
    Mat, rho = build_lsss(ct.policy)
    attrs = {rho[j] for j in partial}
    coeffs = reconstruction_coeffs(Mat, rho, attrs)
    if coeffs is None:
        return None
    t = intt((y_hat * ntt(ct.u)).sum(axis=0))                                    # y^T u (one inner product)
    acc = np.zeros(N, dtype=np.int64)
    for j in coeffs:
        w = (partial[j] + c[rho[j]] * t) % Q                                     # = e-terms + q/2 * share_j
        acc ^= ((w > Q // 4) & (w < 3 * Q // 4)).astype(np.int64)                # round to a bit
    M = np.packbits(acc.astype(np.uint8)).tobytes()
    if check:
        u2, v2 = _lattice_encrypt(pp, ct.policy, M, (Mat, rho))
        if not (np.array_equal(u2, ct.u) and np.array_equal(v2, ct.v)):
            return None                                                          # re-encryption check failed
    key = _xof(M, b"kdf", length=32)
    try:
        return ChaCha20Poly1305(key).decrypt(ct.nonce, ct.body, aad + policy_bytes(ct.policy))
    except InvalidTag:
        return None
