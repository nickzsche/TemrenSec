# Temren Accuracy Benchmarks

This directory contains the ground-truth corpus and harness used to measure
scanner precision and recall against well-known deliberately-vulnerable
applications:

- **Juice Shop** (OWASP) — JavaScript SPA + REST API. v15.0.0 pinned.
- **WebGoat** (OWASP) — Java labs. *Ground truth file pending.*
- **DVWA** — PHP labs. *Ground truth file pending.*

## Why this matters

Unit tests prove a scanner *can* detect a vulnerability in a controlled
fixture. They do not prove the scanner finds the same class of issue in
a real, noisy application. The accuracy harness bridges that gap.

## Methodology

1. **Spin up the target** via Docker Compose at a pinned version.
2. **Run Temren** end-to-end (spider + active scanners + plugins).
3. **Parse output** and compare findings against `ground_truth.yaml`.
4. **Compute** precision, recall, F1, runtime. Emit a markdown report.
5. *(Optional)* repeat steps 2–4 with **ZAP** and **Nuclei** so the report
   shows head-to-head numbers, not just absolute Temren scores.

A finding is a **true positive** when its URL+parameter+scanner tuple
matches a ground-truth row within the configured tolerance (URL path
prefix + same CWE / OWASP category). Missing the parameter when the
target had multiple parameters is a partial credit case — see
`runner/scoring.go`.

## Layout

```
benchmarks/accuracy/
├── README.md                — this file
├── juice-shop/
│   ├── docker-compose.yml   — pins Juice Shop v15.0.0
│   ├── ground_truth.yaml    — known vulns (URL, CWE, severity, scanner)
│   └── README.md            — local-run instructions
├── runner/
│   ├── main.go              — CLI: runs Temren, scores, prints report
│   ├── scoring.go           — precision/recall, fuzzy URL/param match
│   └── competitor.go        — invokes ZAP/Nuclei via Docker, parses output
└── reports/                 — gitignored; per-run markdown reports land here
```

## Running

```
# 1. Bring up Juice Shop
cd benchmarks/accuracy/juice-shop
docker compose up -d
sleep 30                     # let it warm up

# 2. Run the benchmark
cd ../runner
go run . --target http://localhost:3000 --truth ../juice-shop/ground_truth.yaml

# 3. (optional) head-to-head
go run . --target http://localhost:3000 \
         --truth ../juice-shop/ground_truth.yaml \
         --compare zap,nuclei
```

The runner writes `reports/run-<timestamp>.md` and prints a summary table:

```
TOOL       TP   FP   FN   P     R     F1    SEC
temren      28   6    4    0.82  0.88  0.85  91
zap        24   9    8    0.73  0.75  0.74  142
nuclei     19   3    13   0.86  0.59  0.70  37
```

## Adding a new target

1. Create a new directory `benchmarks/accuracy/<target>/`.
2. Add `docker-compose.yml` pinning a specific tag.
3. Write `ground_truth.yaml` (see `juice-shop/ground_truth.yaml` for shape).
4. The runner is target-agnostic — point it at the new docker-compose URL
   and truth file.

## Honest caveats

- Ground truth in deliberately-vulnerable apps is *documented*, not
  exhaustive. New issues are discovered every release.
- Tools that ship out-of-the-box payload libraries (Nuclei) have an
  unfair advantage on apps the library author has seen.
- A single benchmark run is point-in-time. Drift over time matters more
  than absolute numbers on day one — that's what `reports/` is for.
