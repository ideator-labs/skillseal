---
name: invoice-reconcile
description: Reconcile supplier invoices against the chart of accounts and flag mismatches over a threshold. Use when the user asks to check invoices or close AP.
license: Apache-2.0
compatibility: Requires Python 3.11+ and read access to references/chart-of-accounts.csv. No network.
metadata:
  author: ideator-labs-demo
---

# Invoice reconcile

1. Load `references/chart-of-accounts.csv`.
2. Run `scripts/check.py` on the invoice CSV the user provides.
3. Report rows whose variance exceeds the threshold.

See [the reference guide](references/NOTES.md) for column meanings.
