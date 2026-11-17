import copy
import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pqabe import setup, keygen, make_transform_key, encrypt, cloud_transform, user_finalize  # noqa: E402
from pqabe.lsss import build_lsss, reconstruction_coeffs  # noqa: E402
from pqabe.ring import N, Q, intt, ntt  # noqa: E402

UNIVERSE = [f"attr{i}" for i in range(20)]
PP, MSK = setup(UNIVERSE)


def run(policy, attrs, payload=b"sensor reading 42", check=True):
    ct = encrypt(PP, policy, payload)
    sk = keygen(MSK, attrs)
    tk, local = make_transform_key(sk)
    return ct, user_finalize(PP, ct, cloud_transform(ct, tk), local, check=check)


class RingTests(unittest.TestCase):
    def test_ntt_roundtrip_and_product(self):
        a = np.random.randint(0, Q, N)
        b = np.random.randint(0, Q, N)
        self.assertTrue(np.array_equal(intt(ntt(a)), a))
        c = intt(ntt(a) * ntt(b) % Q)
        ref = np.zeros(2 * N, dtype=object)
        for i in range(N):
            ref[i:i + N] += int(a[i]) * b.astype(object)
        ref = [(ref[i] - ref[i + N]) % Q for i in range(N)]
        self.assertEqual(list(c), ref)


class LSSSTests(unittest.TestCase):
    def test_policies(self):
        pol = ["AND", "a", ["OR", "b", ["AND", "c", "d"]], ["T", 2, "e", "f", "g"]]
        M, rho = build_lsss(pol)
        ok = [{"a", "b", "e", "f"}, {"a", "c", "d", "f", "g"}]
        bad = [{"a", "e", "f"}, {"b", "c", "e", "f"}, {"a", "b", "e"}, {"a", "c", "e", "g", "x"}]
        for s in ok:
            self.assertIsNotNone(reconstruction_coeffs(M, rho, s), s)
        for s in bad:
            self.assertIsNone(reconstruction_coeffs(M, rho, s), s)


class SchemeTests(unittest.TestCase):
    def test_authorized_decrypts(self):
        pol = ["AND", "attr0", ["OR", "attr1", ["AND", "attr2", "attr3"]], ["T", 2, "attr4", "attr5", "attr6"]]
        for attrs in ({"attr0", "attr1", "attr4", "attr6"}, {"attr0", "attr2", "attr3", "attr5", "attr6", "attr9"}):
            _, pt = run(pol, attrs)
            self.assertEqual(pt, b"sensor reading 42")

    def test_unauthorized_fails(self):
        pol = ["AND", "attr0", ["OR", "attr1", "attr2"]]
        for attrs in ({"attr0"}, {"attr1", "attr2"}, {"attr5"}):
            _, pt = run(pol, attrs)
            self.assertIsNone(pt)

    def test_many_trials_no_decoding_errors(self):
        pol = ["AND"] + [f"attr{i}" for i in range(20)]
        for _ in range(10):
            _, pt = run(pol, set(UNIVERSE))
            self.assertEqual(pt, b"sensor reading 42")

    def test_tampering_is_rejected(self):
        pol = ["AND", "attr0", "attr1"]
        attrs = {"attr0", "attr1"}
        ct = encrypt(PP, pol, b"payload")
        sk = keygen(MSK, attrs)
        tk, local = make_transform_key(sk)
        for field in ("u", "v"):
            bad = copy.deepcopy(ct)
            getattr(bad, field)[0, 0] = (getattr(bad, field)[0, 0] + 1) % Q
            self.assertIsNone(user_finalize(PP, bad, cloud_transform(bad, tk), local))
        bad = copy.deepcopy(ct)
        bad.body = bad.body[:-1] + bytes([bad.body[-1] ^ 1])
        self.assertIsNone(user_finalize(PP, bad, cloud_transform(bad, tk), local))

    def test_noise_margin(self):
        """Report the worst decoding margin; must stay far below q/4."""
        pol = ["AND", "attr0", "attr1"]
        ct = encrypt(PP, pol, b"x")
        sk = keygen(MSK, {"attr0", "attr1"})
        tk, (y, c) = make_transform_key(sk)
        part = cloud_transform(ct, tk)
        t = intt((y * ntt(ct.u)).sum(axis=0))
        for j, a in enumerate(["attr0", "attr1"]):
            w = (part[j] + c[a] * t) % Q
            dist = np.minimum(np.abs(w), np.minimum(np.abs(w - Q // 2), np.abs(w - Q)))
            self.assertLess(dist.max(), Q // 4 - 500)


HALF = Q // 2
if __name__ == "__main__":
    unittest.main()
