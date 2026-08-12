---
name: ch11-dissemination-lab
description: "Guides the Chapter 11 (Dissemination stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the need-to-know stakeholder-routing pipeline and \"Chap 11 Simulations.ipynb\". Use when running chapter-11/ code or evals, reconciling the judge PASS print (24/30 = 80%) with the Fig 11.11 FAIL caption (11/15 = 73%), reading the three red ground-truth rows under the PASS banner, or protecting ground_truth.csv from write-back mixing."
---

# Chapter 11 — Dissemination Stage (routing pipeline + eval notebook)

Multi-phase pipeline (routing → per-audience briefs → judge → verification)
enforcing need-to-know rules over a 10-stakeholder directory, plus
`Chap 11 Simulations.ipynb`. Nothing is stripped — all eval code ships runnable.

## The most important thing to know — PASS and FAIL on the same run

The judge calibration's defined gate is per-check: 24/30 = **80.0%, passing
with zero margin**. The styled table the reader generates — and shipped
Fig 11.11 — show the per-case view: **11/15 = 73%, captioned FAIL in bold**.
Both describe the same recorded run (the README's Known Judge Calibration Gap
section now explains the two computations). Similarly, the ground-truth
"ALL THRESHOLDS MET — PASS" banner is computed on **averages** (avg routing
overlap 72% ≥ 60%, avg classification 94% ≥ 70%) while the table shows 3 of 8
rows red — including a scenario that routed 9 stakeholders where 3 were
expected. The red rows are the chapter's own judge-leniency lesson in the
data; the aggregate PASS is still the stated gate.

## Lab checklist

```
- [ ] venv + both requirements files; .env in chapter-11/ (ADK walks up dirs, placement works)
- [ ] adk web; keyless imports verified (cell 2 runs clean without a key)
- [ ] Keyless: cell 18's plain-text loader shows the recorded canon
- [ ] Paid (no cell labels here — see README cost note): demo, 200-execution grid (optional), 8-scenario GT, 15-call judge
```

## Canon protection

`ground_truth.csv` ships pre-filled (the Fig 11.12 numbers). There is **no
resume logic** — the eval always runs fresh (no ch9-style replay trap) — but
cell 16's write-back overwrites the shipped canon, and a **partial** eval run
followed by the write-back silently mixes reader rows with recorded rows
(per-name update skips unmatched rows). Copy the CSV aside before evals or
restore with `git checkout -- ground_truth.csv`.

## Known issues frozen in print (guide around, do not edit the repo)

1. Cell 5's markdown formerly said "Loop Controller exits on PASS" — the repo
   copy now correctly names the escalation callback. If a reader quotes "Loop
   Controller" they're reading the printed book or a stale clone; no such
   agent exists (README agrees).
2. **The recorded demo output contains "Event from an unknown agent" lines** —
   ADK noise in the stored output, not a broken run.
3. **Two Fig 11.12 image variants ship** (`Ground Truth Eval.png` and a
   `_highres` re-render no notebook cell produces) — same data, different
   styling; not an inconsistency.

## Directions for improvement (from the chapter)

The README's **Known Judge Calibration Gap** section is the chapter's own
improvement brief: the Routing_Judge under-penalizes over-routing at RR-003
and RR-008 (returns PARTIAL where FAIL is required), and the deterministic
`check_over_routing()` backstop exists precisely to compensate. Forward moves:
- **Make the backstop redundant**: sharpen the judge's severity instructions
  so RR-003/RR-008 over-routing scores FAIL on its own — target lifting the
  per-case score from 11/15 toward ≥ 12/15 without dropping below the 24/30
  per-check gate.
- **Attack the three red GT rows** (routing overlap 33%/43%, classification
  50% — including the 9-routed-vs-3-expected scenario): tighten the routing
  agent's need-to-know weighting against the rule catalog in
  `my_agent/stakeholder_directory.py`, then re-run the 8-scenario GT eval and
  compare per-row overlap, not just the averages the PASS banner uses.
- Copy `ground_truth.csv` aside before every re-run (write-back mixes rows on
  partial runs; git-recoverable).

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
