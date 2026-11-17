"""Time the prototype for policies of 10..100 attributes and write a CSV.

Usage:  python3 bench/run_bench.py [repetitions] [output.csv]

The policy is an AND of n attributes and the user holds all of them (worst case: n LSSS rows).
Times are medians in milliseconds on the machine running the script; they are NOT the
measurements reported in Tables 1-5 of the paper (see docs/DEVIATIONS.md).
"""
import csv
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pqabe import setup, keygen, make_transform_key, encrypt, cloud_transform, user_finalize  # noqa: E402

reps = int(sys.argv[1]) if len(sys.argv) > 1 else 20
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "data", "bench_prototype.csv")
universe = [f"attr{i}" for i in range(100)]
pp, msk = setup(universe)
payload = os.urandom(1024)


def med(f):
    xs = []
    for _ in range(reps):
        t = time.perf_counter()
        r = f()
        xs.append((time.perf_counter() - t) * 1e3)
    return statistics.median(xs), r


rows = []
for n in range(10, 101, 10):
    pol = ["AND"] + universe[:n]
    attrs = set(universe[:n])
    sk = keygen(msk, attrs)
    t_enc, ct = med(lambda: encrypt(pp, pol, payload))
    t_tk, (tk, local) = med(lambda: make_transform_key(sk))
    t_cloud, part = med(lambda: cloud_transform(ct, tk))
    t_fin_nocheck, _ = med(lambda: user_finalize(pp, ct, part, local, check=False))
    t_fin, pt = med(lambda: user_finalize(pp, ct, part, local, check=True))
    assert pt == payload
    rows.append(dict(attributes=n, enc_ms=round(t_enc, 2), transform_key_ms=round(t_tk, 2),
                     cloud_transform_ms=round(t_cloud, 2),
                     user_final_no_check_ms=round(t_fin_nocheck, 2), user_final_with_check_ms=round(t_fin, 2),
                     ciphertext_bytes=len(ct.to_bytes())))
    print(rows[-1])

with open(out, "w", newline="") as f:
    f.write(f"# platform: {platform.platform()} / python {platform.python_version()} / {reps} repetitions, medians\n")
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print("wrote", out)
