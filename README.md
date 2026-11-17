# Post-Quantum Secure and Leakage-Resilient Access Control for IoT Outsourcing

[![DOI](https://zenodo.org/badge/1461452523.svg)](https://doi.org/10.5281/zenodo.24311607)

Reference prototype accompanying the manuscript *"Post-Quantum Secure and Leakage-Resilient Access Control for IoT Outsourcing: A Lattice-Based Approach"* (Khaled Riad, King Faisal University; *Scientific Reports*).

> **Archived release:** Zenodo DOI [10.5281/zenodo.24311607](https://doi.org/10.5281/zenodo.24311607) (all versions; v1.0.0: [10.5281/zenodo.24311608](https://doi.org/10.5281/zenodo.24311608)).

**Please read [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md) first.** This is a Python prototype of the paper's algorithms with a concrete, working instantiation. It is not the C / ARM Cortex-M implementation behind the timings in Tables 1-5, it omits trapdoor sampling, noise flooding and the zero-knowledge proof, and it is not collusion resistant.

## Layout

| Path | Content |
|---|---|
| `src/pqabe/ring.py` | Arithmetic in Z_7681[X]/(X^256+1) with a negacyclic NTT |
| `src/pqabe/lsss.py` | Monotone policies (AND / OR / threshold) and a GF(2) LSSS with reconstruction |
| `src/pqabe/scheme.py` | Setup, KeyGen, transformation key, Encrypt (FO-style hybrid), cloud Transform, user Decrypt with re-encryption check |
| `tests/` | Unit tests: NTT, LSSS, correctness, unauthorised users, tampering, noise margin |
| `bench/run_bench.py` | Timing and ciphertext size for policies of 10-100 attributes |
| `docs/DEVIATIONS.md` | Differences from the paper |

## Requirements

Python 3.9+, `numpy`, `cryptography`:

```
pip install numpy cryptography
```

## Run

```
python3 -m unittest discover -s tests -v     # correctness tests
python3 bench/run_bench.py 20                # writes data/bench_prototype.csv
```

Minimal example:

```python
import sys; sys.path.insert(0, "src")
from pqabe import setup, keygen, make_transform_key, encrypt, cloud_transform, user_finalize

pp, msk = setup(["doctor", "cardiology", "nurse"])
ct = encrypt(pp, ["AND", "doctor", ["OR", "cardiology", "nurse"]], b"patient telemetry")

sk = keygen(msk, {"doctor", "cardiology"})
tk, local = make_transform_key(sk)                 # tk goes to the cloud, local stays on the device
partial = cloud_transform(ct, tk)                  # heavy part, done by the cloud
print(user_finalize(pp, ct, partial, local))       # b'patient telemetry'
```

## Reproducing the paper's tables

The numbers in Tables 1-5 were measured on the hardware listed in Section 6.1 of the paper. This prototype does not reproduce them. `bench/run_bench.py` measures the prototype on the machine that runs it.

## Citation

Please cite the paper and the archived software release (see `CITATION.cff`).

## License

MIT License, see `LICENSE`.
