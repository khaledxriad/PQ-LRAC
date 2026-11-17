"""Arithmetic in R_q = Z_q[X]/(X^256 + 1) with q = 7681 (prime, q = 1 mod 512).

The negacyclic NTT is implemented as a dense matrix product (evaluation at the 256 roots of X^n+1).
It is O(n^2) per transform but fully vectorised with NumPy and easy to audit. It is NOT the
optimised butterfly / ARM-assembly NTT described in Section 4.6 of the paper.
"""
import numpy as np

N = 256
Q = 7681


def _find_psi():
    for x in range(2, Q):
        if pow(x, N, Q) == Q - 1:  # primitive 512-th root of unity
            return x
    raise RuntimeError("no primitive 2n-th root of unity")


PSI = _find_psi()
_PSI_INV = pow(PSI, -1, Q)
_N_INV = pow(N, -1, Q)

_T = np.array([[pow(PSI, (2 * k + 1) * j, Q) for j in range(N)] for k in range(N)], dtype=np.int64)
_TINV = np.array([[(_N_INV * pow(_PSI_INV, (2 * k + 1) * j, Q)) % Q for k in range(N)] for j in range(N)],
                 dtype=np.int64)


def ntt(a):
    """Forward transform of coefficient arrays of shape (..., N)."""
    return (np.asarray(a, dtype=np.int64) % Q) @ _T.T % Q


def intt(a_hat):
    """Inverse transform of NTT-domain arrays of shape (..., N)."""
    return (np.asarray(a_hat, dtype=np.int64) % Q) @ _TINV.T % Q
