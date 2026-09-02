# Paper build

Regenerates `docs/paper/zero-trust-sdn-paper.docx`, the research paper.

The Word document is the **deliverable**; everything in this directory is source.
`zero-trust-sdn-paper.html` is an intermediate the `.docx` is walked from — it is
not a deliverable and is regenerated on every build.

## Build

```bash
python3 tools/paper/mkfigs.py       # figures -> fig1..fig6.svg
python3 tools/paper/rasterize.py    # -> fig1..fig6.png (needs cairosvg)
python3 tools/paper/build_paper.py  # template + figures -> intermediate HTML
python3 tools/paper/make_docx.py    # -> docs/paper/zero-trust-sdn-paper.docx
```

Run them in that order; each consumes the previous step's output.

## Files

| File | Role |
|---|---|
| `paper_template.html` | the paper's text, with `{{FIG1}}`…`{{FIG6}}` placeholders |
| `mkfigs.py` | generates all six figures as SVG from measured data |
| `fig_trust.json` | per-node trust/anomaly series extracted from the live run, for Figure 1 |
| `rasterize.py` | resolves the CSS-variable palette and renders PNGs for Word |
| `build_paper.py` | substitutes figures + captions into the template |
| `make_docx.py` | walks the built HTML into a styled `.docx` |
| `validate_palette.py` | Python port of the dataviz palette validator (this box has no JS runtime) |

## Conventions worth not breaking

- **Figures are numbered by document position**, not by the order the generator
  functions were written. `mkfigs.py`'s output filenames encode that order, and
  `build_paper.py`'s `CAPTIONS` keys must match. A Figure 4 that appears before
  Figure 2 is a defect.
- **Table captions are numbered sequentially in document order.** Adding a table
  mid-document means renumbering every later caption *and* the prose that cites
  them.
- **Series colours are CSS custom properties** (`var(--s1)`…`var(--s5)`), so the
  web intermediate can be theme-aware. `rasterize.py` resolves them against the
  light palette for Word, which has no theme to follow.
- **Run `validate_palette.py` before changing any series colour.** It checks the
  lightness band, chroma floor, CVD separation, normal-vision separation and
  contrast. Do not eyeball these.

  ```bash
  python3 tools/paper/validate_palette.py "#2a78d6,#eb6834,#1baf7a,#eda100,#e87ba4" --mode light
  python3 tools/paper/validate_palette.py "#3987e5,#d95926,#199e70,#c98500,#d55181" --mode dark
  ```

## Where the numbers come from

Every figure and table in §7 is measured, not quoted. Regenerate the underlying
data with the commands in the paper's Appendix A — the live-run figures come from
`data/events.jsonl` scored by the four modules in `evaluation/`, the comparison
figures from `evaluation/baseline.py` + `evaluation/stats.py`, and the
scalability figures from `evaluation/scalability_sweep.py`.
