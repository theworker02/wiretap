# Evaluation

```bash
wiretap eval --n 50 --budget normal
wiretap eval --format json --n 50
wiretap eval --eval-format markdown
```

Inside a project, JSON + markdown copies are stored under `reports/eval/`.

**All numbers are measured** against a deterministic synthetic corpus with ground
truth. They are not claimed production accuracy.

Regression test: `TestEvalRegressionFloor` asserts length or checksum accuracy,
boundary recall (≥0.8), precision (≥0.6 under High-primary scoring), and FPR (≤0.4)
on fixed seed `--n 50 --budget normal`. Measured on seed=1 after competition
prune (0.3→0.4 line): precision≈0.83, FPR≈0.17, recall=1.0 (synth only — not production claims).

**Precision / FPR scoring:** the precision denominator counts High predictions, plus
strong Medium structural kinds (checksum/length/array/counter/typefield/string/timestamp
with score ≥ 0.8). Medium integer/pattern spam is excluded from precision so FPR
reflects high-quality hypotheses rather than speculative volume. Recall matching still
allows Medium with score ≥ 0.65. Competition collapses overlapping length/counter/string
aliases and demotes nested envelopes under concrete structure.
