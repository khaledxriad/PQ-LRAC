"""Monotone policies and a linear secret-sharing scheme (LSSS) over GF(2).

Policy syntax (JSON-compatible): "attr" | ["AND", p1, p2, ...] | ["OR", p1, ...] | ["T", t, p1, ..., pm]
(threshold t-of-m). Shares are bits, so reconstruction coefficients are in {0,1}; the matrix is
built with the Lewko-Waters conversion, specialised to GF(2).
"""
import itertools
import json
import numpy as np


def policy_bytes(policy):
    return json.dumps(policy, separators=(",", ":")).encode()


def _expand_threshold(node):
    t, subs = node[1], node[2:]
    if not 1 <= t <= len(subs):
        raise ValueError("bad threshold")
    return ["OR"] + [["AND"] + list(c) for c in itertools.combinations(subs, t)]


def build_lsss(policy):
    """Return (M, rho): M is an (L, c) uint8 matrix over GF(2) and rho the attribute of each row."""
    rows, rho = [], []
    counter = [1]

    def rec(node, vec):
        if isinstance(node, str):
            rows.append(list(vec))
            rho.append(node)
            return
        op = node[0]
        if op == "T":
            node = _expand_threshold(node)
            op = "OR"
        subs = node[1:]
        if op == "OR":
            for s in subs:
                rec(s, vec)
        elif op == "AND":
            # chain of binary AND gates: v -> (v, 1) and (0.., 1), sum = (v, 0)
            cur = list(vec)
            for s in subs[:-1]:
                c = counter[0]
                counter[0] += 1  # reserve the new column before recursing
                cur = cur + [0] * (c - len(cur))
                rec(s, cur + [1])
                cur = [0] * c + [1]
            rec(subs[-1], cur)
        else:
            raise ValueError(f"unknown operator {op}")

    rec(policy, [1])
    c = counter[0]
    M = np.zeros((len(rows), c), dtype=np.uint8)
    for i, r in enumerate(rows):
        M[i, :len(r)] = r
    return M, rho


def solve_gf2(A, b):
    """Solve A x = b over GF(2). A is (r, k); returns a 0/1 vector of length k or None."""
    A = (np.array(A, dtype=np.uint8) % 2)
    b = (np.array(b, dtype=np.uint8) % 2).reshape(-1, 1)
    r, k = A.shape
    aug = np.concatenate([A, b], axis=1)
    piv_cols, row = [], 0
    for col in range(k):
        if row >= r:
            break
        p = np.nonzero(aug[row:, col])[0]
        if len(p) == 0:
            continue
        p = p[0] + row
        aug[[row, p]] = aug[[p, row]]
        for i in range(r):
            if i != row and aug[i, col]:
                aug[i] ^= aug[row]
        piv_cols.append(col)
        row += 1
    if np.any(aug[row:, k]):
        return None
    x = np.zeros(k, dtype=np.uint8)
    for i, col in enumerate(piv_cols):
        x[col] = aug[i, k]
    return x


def reconstruction_coeffs(M, rho, attrs):
    """Return {row: 1} for a set of owned rows whose sum is (1,0,...,0), or None if unauthorized."""
    owned = [j for j, a in enumerate(rho) if a in attrs]
    if not owned:
        return None
    target = np.zeros(M.shape[1], dtype=np.uint8)
    target[0] = 1
    w = solve_gf2(M[owned].T, target)
    if w is None:
        return None
    return {owned[i]: 1 for i in range(len(owned)) if w[i]}
