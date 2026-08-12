---
name: ch08-processing-lab
description: "Guides the Chapter 8 (Processing stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the corroboration-brief pipeline with deterministic rule checker and \"Chap 8 Simulations.ipynb\". Use when running chapter-08/ code, interpreting the recorded results that intentionally FAIL their thresholds, the placeholder demo cell, gt_checkpoint.json replay and reset, or per-check vs per-case judge accuracy."
---

# Chapter 8 — Processing Stage (corroboration pipeline + eval notebook)

Three-agent LoopAgent pipeline producing TLP-marked corroboration briefs, with
a deterministic rule checker, plus `Chap 8 Simulations.ipynb`.

## The most important thing to know

**The shipped recorded results FAIL their own thresholds, on purpose.** The
recorded ground-truth run averages 50% Confidence Accuracy vs the 70% bar, and
the judge calibration lands under 80% — visible in the shipped JSON, checkpoint,
and reference screenshots. The README's "A Note on the Recorded Results"
explains this is demonstrated pedagogy (evals must be able to fail honestly).
If a reader reproduces a FAIL, they reproduced the recorded behavior — do not
debug their setup for that reason alone; treat closing the gap as the exercise.

## Lab checklist

```
- [ ] venv + both requirements files; .env at chapter-08/ root
- [ ] python my_agent/agent.py or adk web  (missing key now fails fast with a clear message)
- [ ] Notebook keyless: cell 19 replays the recorded GT run from the shipped checkpoint (no calls)
- [ ] Paid (labeled cells): fresh GT run, judge calibration, optionally run_grid()
```

## Keyless path

`gt_checkpoint.json` ships complete, so the ground-truth cell legitimately
loads recorded results with zero API calls ("All scenarios completed — loaded
from checkpoint"). The grid cell as shipped only *defines* `run_grid()` and
loads the CSV — executing `run_grid()` is the paid step (≈ 2,700 calls).
Deleting the checkpoint forces a fresh paid run but destroys the only shipped
reference results — recover with `git checkout -- gt_checkpoint.json`.

## Two accuracy views (both correct)

The judge summary print counts individual checks (recorded: 75%); the styled
table counts fully-correct cases (recorded: 5/10). Same run, different
questions. The README note explains this — point readers at it.

## Known issues frozen in print (guide around, do not edit the repo)

1. **Cell 8's demo is restored post-print** — printed copies show
   `# skipped — single-scenario demo`, but the repo ships a runnable demo that
   loads the canonical AiTM scenario from `ground_truth.csv` and runs the
   pipeline once (labeled; ~9 model calls). `python my_agent/agent.py` remains
   an equivalent path.
2. The Section-4 markdown formerly credited a "Loop Controller" agent — the
   repo copy now correctly names the `_escalate_on_pass` callback. If a reader
   quotes "Loop Controller" they're reading the printed book or a stale clone;
   the callback is the real mechanism (README agrees).
3. **The recorded canon contains a PASS on an empty brief** (BEC/OAuth
   scenario: zero findings, verdict PASS). It's a real judge-leniency example,
   not data corruption — the rule checker doesn't test for empty
   `confirmed_valid`.
4. **`best_config.json` ships hand-set to `gemini-2.5-flash @ 0.2`**
   (corrected post-print from a `gemini-2.0-flash` typo) — it now matches the
   stored cell-2 output, the code's fallback default, and the grid's search
   space. On a stale clone the file may still say `gemini-2.0-flash`; if a
   reader hits a model-not-found error at first run, that's why.
6. **`ground_truth_results.json` also ships pre-filled** with the recorded run
   (the README's file inventory and Recorded Results note now say so). A fresh
   paid eval overwrites it — restore with
   `git checkout -- ground_truth_results.json`.

## Directions for improvement (from the chapter)

The README's Recorded Results note states the exercise outright: **"treat
closing the gap (tighter prompts, stronger rules) as the exercise."** The
recorded run fails both bars — that's the starting line, not the finish:
- Raise Confidence Accuracy toward ≥ 70%: tighten the Correlation_Agent
  instructions and/or strengthen the corroboration rules in
  `my_agent/indicator_schemas.py`, then delete `gt_checkpoint.json` (canon is
  git-recoverable) and re-run the 3-scenario GT eval to score the change.
- Raise judge calibration toward ≥ 80%: the empty-brief PASS in the shipped
  canon shows exactly where the rule checker is blind — extending
  `check_verdict_rules()` to reject a PASS with empty `confirmed_valid` is a
  natural reader exercise (in their own working copy; the shipped code stays
  matched to print).
- The Discussion's ceiling interpretation gives the stop condition: when all
  three evaluations pass, "the appropriate next step is not further tuning but
  integration testing."

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
