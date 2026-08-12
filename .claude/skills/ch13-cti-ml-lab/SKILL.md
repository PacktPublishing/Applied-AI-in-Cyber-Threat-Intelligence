---
name: ch13-cti-ml-lab
description: "Guides the Chapter 13 lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the classical-ML notebook CTI_ML.ipynb over NVD, CISA KEV, and MITRE ATT&CK data. Use when obtaining the chapter datasets (CTI_ML_and_DATA.zip extraction vs the slow, drifting API download), troubleshooting chapter-13/ cells (the YEARS quick-run Leakage AssertionError, overwritten Images figures, the contradictory GBR key-finding print), or checking results against the README Key Results. No API key needed."
---

# Chapter 13 — Classical ML for CTI (notebook + datasets, no API key)

One 21-cell notebook (`CTI_ML.ipynb`) over public vulnerability data (NVD,
CISA KEV, MITRE ATT&CK). Fully keyless — the only "apiKey" mention is an
optional NVD header the code never uses. The chapter's thesis is **honest
negative results**: no ranker beats CVSS-sort, AUPRC ~0.010 is operationally
insufficient, actor attribution Jaccard ~0.07, and GBR loses to a rolling mean.
If the reader's models lose to baselines, that IS the recorded result.

## Getting the data (also in the README's Data section)

`chapter-13/CTI_ML_and_DATA.zip` (~100 MB) is the **pinned data snapshot**
matching every recorded number digit-for-digit. Extract it so `data/` lands
directly inside `chapter-13/`:

```bash
cd chapter-13 && unzip -o CTI_ML_and_DATA.zip 'data/*' -d .
```

**macOS trap**: double-clicking the zip extracts into a `CTI_ML_and_DATA/`
subfolder the notebook never checks — the notebook then silently falls back to
downloading everything from the NVD API: 1–3 hours, ~800 MB transfer, and a
**different snapshot** (KEV grows weekly, NVD revises CVSS), so numbers will
drift from the README's Key Results. Drift on a fresh download is expected,
not an error — but prefer the zip.

Footprint: ~1 GB disk (zip + extracted), ~4–6 GB peak RAM during the six-year
NVD load (cell 5). 16 GB machines are fine; 8 GB is tight. After data exists,
the full run is ~5–10 minutes.

## Lab checklist

```
- [ ] pip install -r requirements.txt (includes jupyter + kaleido; macOS: brew install libomp)
- [ ] Extract data/ from the zip as above (verify chapter-13/data/kev.json exists)
- [ ] jupyter lab CTI_ML.ipynb, run top-to-bottom
- [ ] Check results against README "Key Results on Public Data" line by line
```

## Known issues frozen in print (guide around, do not edit the repo)

1. **Do NOT follow cell 5's "quick run" advice** (`YEARS = [2024, 2025]`). The
   temporal split hard-codes train ≤ 2023 / test = 2024, so that subset leaves
   an empty training set and cell 7 dies with a *misleading*
   `AssertionError: Leakage: train_max=NaT >= test_min=...`. Any quick subset
   must include at least one year ≤ 2023 plus 2024 (e.g. `[2023, 2024]`).
2. **Figure cells overwrite the shipped book figures**: the notebook writes to
   `images/`, which case-folds into `Images/` on macOS/Windows. Re-running
   figure cells clobbers the canonical PNGs (the Sankey re-render is also a
   known styling regression). Restore with `git checkout -- "chapter-13/Images"`.
3. **Cell 15's printed "Key finding: GBR tracks seasonal patterns that
   persistence misses" contradicts its own table** — GBR is the *worst* model
   there (MAE 283 vs rolling-mean 191). Trust the table and the README's Key
   Results ("GBR loses to simpler baselines"); the print string was never
   updated. This is the chapter's honest-negative point, not a reader mistake.
4. **Cell 15's Monte Carlo band is unseeded** — p10–p90 shifts per run; the
   100% breach headline is immune (true by construction, disclosed).
5. The README folder diagram lists `data/` and the manuscript `.docx` — both
   are gitignored and now annotated as such in the diagram; only the zip
   ships. Seeded model cells (`random_state=42`) reproduce recorded numbers
   exactly on the pinned snapshot.
6. **`Packt Chapter Work.code-workspace`** is a leftover author VS Code
   artifact, now untracked from git — fresh clones won't have it; if present
   in an older clone, ignore it.
7. Cell 2's `!pip install shap xgboost lightgbm` is an unpinned duplicate of
   requirements.txt — skip it when the venv is already installed.

## Directions for improvement (from the chapter)

Section 13.3 of the chapter ships the roadmap explicitly: a
failure-modes-and-fixes table pairing each research question's shortfall with
**the data move that closes it** and a falsification test on enterprise data,
plus a 10-item evaluation harness (7 standard ML hygiene + 3 CTI-specific:
catalog freshness, label-source provenance, TLP propagation) as the takeaway
deliverable. How to move on it:
- **Swap the label proxy**: the README's closing note says it directly — on
  enterprise data, replace the KEV proxy with the org's own SIEM/EDR
  exploitation telemetry; the same pipelines apply unchanged. That is the
  falsification test: do the models that lost to baselines on public data win
  on real exploitation labels?
- **Keep the harness, not the models**: the temporal-split leakage guard,
  baseline-comparison discipline, and calibration checks are the chapter's
  actual deliverable — reuse them on any new data before trusting any lift.
- Practicalities: put new datasets under `data/` (gitignored, stays local),
  keep `random_state=42` for comparability, and write new figures anywhere
  but `Images/` (shipped book figures; case-folding overwrites them).

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo. This chapter needs
no API key anywhere.
