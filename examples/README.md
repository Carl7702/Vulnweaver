# Controlled examples

This directory contains small, deterministic examples for reviewing and testing the
artifact mechanics. Each example is self-contained:

```text
authorization/
├── case.json
├── replay.json
├── candidate/Exploit.t.sol
└── environments/
    ├── ev/
    └── er/
```

They are not part of `D_tra`, `D_mix`, `D_log`, `D_inc`, or `D_cve` and must not
contribute to paper metrics.

The `golden-` identifiers are stable schema/test identifiers retained for replay-hash
compatibility; “golden” means a controlled test oracle, not a paper benchmark.
