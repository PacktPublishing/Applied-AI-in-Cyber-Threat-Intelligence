---
name: ch04-python-foundations
description: "Guides the Chapter 4 lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the Python-foundations notebook Chapter_4_Work.ipynb — pandas, ydata-profiling EDA, threading vs multiprocessing, scikit-learn classification, Monte Carlo simulation. Use when running or troubleshooting anything in chapter-04/ — BrokenProcessPool multiprocessing failures, the Random Forest figure filename, missing Key Outputs, or results not matching the book. No API key needed."
---

# Chapter 4 — Python Foundations (pure notebook, no API key)

One 10-cell notebook (`Chapter_4_Work.ipynb`), all code cells, no markdown.
Runs top-to-bottom in under a minute on a fresh install. Internet needed only
for cell 0 (plain HTTP GETs to google.com / python.org / github.com — corporate
proxies may block these; the failure is harmless to the rest of the lab).

## Lab checklist

```
- [ ] pip install -r requirements.txt (resolves clean; includes jupyter)
- [ ] jupyter lab Chapter_4_Work.ipynb
- [ ] Run cells top-to-bottom (see cell 1 warning below)
- [ ] Verify the four Key Outputs from the README exist
```

Doneness = the README's "Key Outputs" list: `wealth_distribution_report.html`,
`wealth_distribution_boxplot.png`, the Random Forest metrics PNG, and
`monte_carlo_simulation.png`. Fresh outputs land in the `chapter-04/` root (not
`Images/` — that folder holds the reference copies to compare against). The
seeded ML cells reproduce the book's exact numbers (Accuracy 90.00%, Precision
94.85%, Recall 85.98%, F1 90.20%).

## Known issues frozen in print (guide around, do not edit the repo)

1. **Cell 1 (`ProcessPoolExecutor`) fails on macOS/Windows local Jupyter** with
   `BrokenProcessPool` / `Can't get attribute 'heavy_calculation'`. Cause:
   spawn-based multiprocessing cannot pickle functions defined in a notebook;
   the cell was authored on Colab (fork). Workarounds, best first:
   (a) run the notebook in Google Colab where it works as printed;
   (b) skip cell 1 — nothing downstream depends on it;
   (c) for a local demo, have the reader paste `heavy_calculation` into a
   `helpers.py` next to the notebook and import it — session-local, don't
   commit it.
2. **Cell 7 saves `Random Forest: Performance Metrics.png`** — the colon
   crashes on Windows (illegal filename char) and on macOS produces a name that
   never matches the README checklist's underscore variant. Tell the reader the
   underscore file in `Images/` is the same artifact; on Windows, edit the
   filename in their running kernel (not the repo) before executing cell 7.
3. **Cell 8's Monte Carlo is unseeded** — the reader's 95th-percentile and
   breach numbers will differ from the book figure (book: ~203 min / ~6.3%).
   Variation is expected; the shape matters, not the digits. The comment about
   a `max(value, 1)` clamp describes code that doesn't exist — ignore it.

## Notebook cell map (the notebook has no markdown headers)

Cell 0: threading demo over HTTP requests · cell 1: multiprocessing
comparison · cell 2: pandas descriptive stats + outlier corruption ·
cell 3: ydata-profiling report · cells 4–5: ML classification + the four
metrics · cell 6: wealth-distribution boxplot · cell 7: Random Forest metrics
bar chart · cell 8: Monte Carlo SLA simulation · cell 9: Monte Carlo
histogram. Book sections 4.1–4.2 are prose-only (no cells).

## Directions for improvement (from the chapter)

This is the foundations chapter — its forward path is experimentation, not a
scored eval. Natural extensions, using the notebook's own machinery:
- Vary the Monte Carlo parameters (staff capacity, ticket volume, simulation
  count) and watch how the SLA-breach probability responds — seed the run
  first so comparisons are apples-to-apples.
- Swap the Random Forest for other scikit-learn classifiers on the same seeded
  train/test split and compare all four printed metrics, not just accuracy.
- Point the ydata-profiling cell at the reader's own dataset — the report
  generation pattern transfers unchanged.
Write any new outputs to the chapter root or a scratch folder, never into
`Images/` (those are the book's reference copies).

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo. This chapter needs
no API key anywhere.
