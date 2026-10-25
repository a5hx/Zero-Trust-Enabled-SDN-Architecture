# Submission checklist

State of the draft against the checks a reviewer, a supervisor and most venues
apply. `[x]` done, `[ ]` open. Target: **conference**.

## What changed in revision 3 (2026-10-19)

1. **Headline reframed by the live θ sweep** (15 more runs, prediction registered
   first). "The score is structurally unable / blind" is withdrawn. The claim is
   now margin and speed: at θ = 0.45 the score isolates both task-completing
   attackers, 3.4× and 20× slower than the gate, in a band a few hundredths
   wide that honest servers under load also reach. New §VII-D, Table V, Fig. 2.
2. **"Sybil" renamed** to load-misreporting server (Douceur cited for why).
3. **§V rewritten:** the 0.44 and 0.302 floors reconciled; the tested attacker is
   stated not to be latency-faithful, and the circularity is in §IX.
4. **Fig. 1** is now a TikZ diagram; the slide with stale single-run numbers is gone.
   The standalone Raft figure is dropped in favour of the live failover result.
5. **New results:** per-client flood meter under a heavy flood (§VII-F, Table VII;
   honest latency improves, 10 runs); replicated ledger with a live leader kill
   (§VII-H; 649/649 committed, failover 0.47 s).
6. **Related work widened** with 13 references checked by web search this session.
7. **AI-use declaration restored**; test count corrected (1,166); UCB1 in all arms
   stated in §VI-B.

### Still open after revision 3

- [ ] Per-class recall / balanced accuracy in §VII-H (accuracy is dominated by the 40 honest subjects)
- [x] A load-misreporting server that does not slow itself — done, §VII-E (80 runs, four batches)
- [ ] Page count is **14** (revision 4, 2026-10-20: the liar experiment, §VII-E + Table VI + §VIII-C); trim to the chosen venue's limit (order below)
- [x] Abstract trimmed to 246 words (revision 4); the retraction moved out of it, still in §VIII-B
- [x] Retitled around the liar experiment: "What Catches a Lie That Works? Trust Scores, Anomaly Gates and Load-Misreporting Servers in Zero-Trust Edge Load Balancing"
- [ ] Choose the venue; swap in `IEEEtran.cls`; anonymise if double-blind
- [ ] Data DOI, CRediT roles, confirm the `rfc9334` author list
- [ ] Confirm the volume/issue/page ranges of `burke2023misreporting` (MONET 28(4) 1482–1497) and `yu2024stealthy` (ToN 32(4) 3622–3635) against the publisher; they were taken from saha2025's reference list
- [ ] Fix the Generative AI declaration: the 2026-10-19 edit left the fragment "of §VII-D came about."

## What changed in revision 2 (2026-09-29)

The previous draft rested on one live run per arm and led with an analytic
proposition. Five things changed:

1. **Replication.** 15 live runs (3 arms × 5) replace 2 single runs. Every live
   figure now carries a between-run interval.
2. **A real ablation arm.** `scoreonly` — the shipping controller with the
   anomaly gate's *action* disabled and its *term* left in the score. This is
   now the paper's central experiment.
3. **The headline moved** from the proposition to the ablation result. The
   proposition is retained as the explanation, and is explicitly reported as a
   **valid but conservative** bound rather than a tight prediction.
4. **A retraction.** The containment-vs-attribution trade is not supported by
   replication (ρ = −0.52, p = 0.12, n = 10) and is withdrawn in §VIII-B.
5. **Two withdrawn cost claims.** The mean-latency and throughput costs of
   enforcement do not survive replication — all three arms' intervals overlap.

An analysis-tool defect was found and fixed while preparing this: rail
attribution credited the *gate* for quarantines in an arm where the gate was
switched off. See `NUMBERS.md` § Table III.

## Structure and framing

- [x] Title names the result, not the component list
- [x] Abstract: gap → approach → quantified result → null results → retraction
- [x] Index terms
- [x] Numbered contribution list (§I-A)
- [x] Scope and non-claims before the results (§I-B)
- [x] Related work positions against the closest prior work
- [x] Threat model with adversary, out-of-scope list, TCB (§III)
- [x] Analysis with a stated proposition and proof (§V)
- [x] Methodology separate from results, incl. the statistical treatment (§VI-C)
- [x] Threats to validity: internal / construct / external / conclusion / adversary
- [x] Limitations as a numbered list (§X)
- [x] Reproducibility with exact commands (§XI)
- [x] Conclusion restates the measured claim, the null results and the retraction

## Evidence discipline

- [x] Every measured number carries its source (`\src{...}`); `NUMBERS.md` maps all
- [x] Unit of replication stated and respected (the run, never the task)
- [x] Proportions use Wilson intervals, not t-intervals on 0/1s
- [x] Overlapping intervals are reported as overlapping, not as differences
- [x] **Null results reported with the positives** (the gate buys no service gain)
- [x] **A retraction of the authors' own earlier claim** (§VIII-B)
- [x] Absent mechanisms are "not measured", never zero
- [x] Simulation labelled everywhere; no live claim rests on it
- [x] p-value floor at n=30 disclosed rather than presented as strength
- [x] Fairness over two populations, with the trap explained
- [x] Detection latency reported as measured, with the poll-interval bound named
- [x] Raft: replicated ledger measured live with a leader kill; ablation/sweep/flood runs stated as using the in-process ledger
- [x] PRESENT-80 framed as architecture, not security
- [x] Figures referenced at source; superseded figures removed rather than reused

## Statistics

- [x] Between-run 95 % intervals on every live metric
- [x] Wilson intervals for yes/no outcomes
- [x] Times reported only over runs where the event occurred
- [x] Simulation: paired design, non-parametric test, Holm correction, effect sizes
- [x] Both `p_raw` and `p_adj` available in the evidence files
- [ ] **No between-arm significance tests on service metrics** — deliberate at
      n=5; a venue may ask for more runs instead

## Mandatory sections

- [x] Data Availability *(TODO: deposit + DOI)*
- [x] Ethics (no human subjects — stated explicitly)
- [x] Author Contributions / CRediT *(TODO: confirm per-author roles)*
- [x] **Declaration of Generative AI Use** — substantive and specific
- [x] Conflicts of Interest
- [x] Funding
- [x] Acknowledgements

## Formatting

- [x] Builds clean: `make` → 0 errors, 0 undefined references, 0 overfull boxes
- [x] All 21 cited references resolve; no citation without an entry
- [x] Two-column IEEE-like layout, 10 pt Times
- [ ] **Page count: 11.** Many IEEE conferences allow 8 + 2 paid; references are
      often excluded. See "Trimming" below.
- [ ] Anonymise if the venue is double-blind (author block, acknowledgement and
      repository references all de-anonymise today)
- [ ] Swap in the venue's `IEEEtran.cls` and delete `ieeeish.sty`

## Open placeholders

| Item | Where | Note |
|---|---|---|
| Data DOI | Data Availability | recordings are ~130 MB × 15 |
| CRediT roles | Author Contributions | currently "all authors" |
| ORCIDs, emails | title block | absent |
| Venue template | `\documentclass` | `IEEEtran.cls` not installed here |
| Remaining references | `references.bib` | 5 verified this session; the rest are widely reproduced classics, not re-verified |
| Per-server trust / load figures | — | old ones superseded; regenerate from `data/runs/` if a figure is wanted |

## Trimming to 8 pages, in order

1. §VII-G selector scalability + capacity cliff → three sentences in §X
2. §IV merge the admission/audit subsection into one paragraph
3. §II drop the primitives paragraph, keep the citations inline
4. §VIII-C the ablation-methodology discussion → move to §VI
5. §VII-F NFR prose → one table row each

**Do not cut:** Table II (the ablation), Table V's null-result column, §V-B
(the bound is conservative and why), §VIII-A (enforcement feedback), or
§VIII-B (the retraction). Those are the paper.

## Objections a reviewer will raise, and where they are answered

| Objection | Answered in |
|---|---|
| "n=5 is small" | §VI-C (intervals not tests), §IX internal, §X item 4 |
| "You chose θ=0.30 to make the score fail" | §IX construct — **named as the most direct attack, and not defended away**; §X item 1 makes the θ sweep the top future item |
| "The proposition is trivial" | §V — it is presented as an explanation with a bound, and §V-B reports the bound as loose |
| "Raft is crash-fault, so what does the ledger secure?" | §III TCB |
| "The controller is a trusted single point in a Zero-Trust paper" | §III TCB; §X item 6 |
| "80-bit keys are not secure" | §II primitives; §X item 7 |
| "The adversary is not adaptive" | §IX adversary — with the observation that the honesty term already barely registers a non-adaptive liar |
| "Emulation, not deployment" | §I-B, §IX external |
| "Your p-values are suspiciously small" | §VII-G states the floor explicitly |
| "Fairness measured on a hand-picked population" | §VII-D reports both populations |

## Before the next live run

`run_demo.py --mode mininet` unlinks the active recording at start-up and
`data/` is gitignored. `tools/run_replicates.sh` archives each run before the
next begins, and copied the pre-campaign recordings to `*_pre_replicates.jsonl`.
Archive anything you intend to re-score.

> `../data/comparison/` and `ppt/sections_1_2_3.tex` still carry figures from
> the superseded single runs. They are not used by this paper and should be
> re-scored before the next review.
