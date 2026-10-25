# paper-draft — research paper draft

**"What Catches a Lie That Works? Trust Scores, Anomaly Gates and
Load-Misreporting Servers in Zero-Trust Edge Load Balancing"** (revision 8,
2026-10-25: the switch witness acts and holds, and two probation-path defects
are measured in Threats to Validity; revision 7 added ledger replicas that
re-verify the controller; revision 6 added
attestation, revision 5 honest-slow servers and the live switch witness,
revision 4 the liar experiment; see `CHECKLIST.md`)

A conference-length (IEEE-style, two-column) research paper drawing together
the project's findings, measurements and negative results. `paper.pdf` is the
current build: **18 pages, 39 references (all cited), 13 tables, 2 figures (both drawn in LaTeX), 1 proposition.**

---

## Build

```bash
cd paper-draft
make            # pdflatex -> bibtex -> pdflatex x2, then reports undefined refs
```

Requires `pdflatex` and `bibtex` only. No network, no pip, no venv — the same
constraint the rest of the repository runs under.

`IEEEtran.cls` is **not installed** on this box (`kpsewhich IEEEtran.cls`
returns nothing), so `ieeeish.sty` reproduces the IEEE conference *look* on
stock `article` using packages that ship with the installed TeX Live. If you
later submit to a venue that supplies `IEEEtran.cls`, delete `ieeeish.sty` and
change the `\documentclass` line — nothing in the paper body depends on it.

## What is in here

| Path | Role |
|---|---|
| `paper.tex` | the paper |
| `paper.pdf` | the current build |
| `references.bib` | 21 references; keys `[1]`–`[13]` mean the same thing as in `ppt/SECTIONS_1_2_3.md` and the project report |
| `ieeeish.sty` | local IEEE-like two-column layout (see above) |
| `Makefile` | build + a `make data` target |
| `NUMBERS.md` | **every number in the paper → the artifact and command it came from** |
| `CHECKLIST.md` | submission checklist, open placeholders, venue notes |
| `evidence/` | the re-scored evidence the paper cites, regenerated 2026-09-29 |
| `tools/regenerate.sh` | re-scores everything in `evidence/` from the archived recordings |

## Provenance rules this folder follows

1. **Every measured number carries a `\src{...}` tag** naming the artifact it
   was read from. Do not hand-edit a number without regenerating its source.
2. **Figures are referenced at their source paths**, never copied. `paper.tex`
   sets `\graphicspath` to `../ppt/figures/`, `../base_model/` and
   `../data/figures/`, so a regenerated plot updates the paper on the next
   build and cannot drift from the recording that produced it.
3. **`evidence/` in this folder is derived, not raw.** It is the output of
   `tools/regenerate.sh` run against the two archived recordings. The raw
   recordings live in `../data/` and are gitignored.

## Archiving

Live runs overwrite the active recording at start-up and `data/` is gitignored.
`tools/run_replicates.sh` archives each run under `data/runs/<arm>/` before the
next begins, and copied the pre-campaign recordings to `*_pre_replicates.jsonl`.
The 15 recordings this paper scores are ~130 MB each and are **not** in git.

> `../data/comparison/` and `ppt/sections_1_2_3.tex` still carry figures from
> two single runs that this replicate campaign superseded. This paper does not
> use them; they should be re-scored before the next review.

## The experiment

Fifteen live runs, three arms of five. The middle arm is the point: it is the
shipping controller with the anomaly gate's *action* disabled and its *term*
left in the trust score, so the arms differ by one mechanism.

| Arm | Enforcement | Sybil + on-off contained? |
|---|---|---|
| control | none | — (no mechanism) |
| **score-only** | `T < θ` alone | **0/5 and 0/5** |
| both rails | `T < θ` **or** `Ā ≥ g` | **5/5 and 5/5** |

Re-run the scoring with `tools/regenerate.sh` (~4 min). Re-run the
*experiments* with `sudo tools/run_replicates.sh` (~100 min).

## Verified on 2026-09-29

Run on this box (Python 3.12.3, scipy 1.11.4) while producing this draft:

- `pytest tests/ -q` — **832 passed, 11 skipped, 0 failed**
- `evaluation.replicates data/runs` — every live table in the paper
- `evaluation.baseline --runs 30` + `evaluation.stats` — reproduces the
  simulation medians and p-values exactly
- Five references checked against publisher records (see `NUMBERS.md`)

One defect was found and fixed in the process: rail attribution credited the
anomaly gate for quarantines in the arm where the gate is switched off. The
rule now lives in one function that the scorer and its tests both call.
