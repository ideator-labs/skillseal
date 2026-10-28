#!/usr/bin/env python3
"""Demo script: sum a variance column. Labelled stub for SkillSeal demos."""
import csv
import sys

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "-"
    fh = sys.stdin if path == "-" else open(path, newline="")
    with fh:
        rows = list(csv.DictReader(fh))
    total = sum(float(r.get("variance", 0) or 0) for r in rows)
    print(f"rows={len(rows)} variance_sum={total:.2f}")

if __name__ == "__main__":
    main()
