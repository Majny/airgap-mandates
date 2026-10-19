"""Bench report: ASR, false-block rate, exceptions/100, signatures/100, 95% Wilson intervals. CONTRACTS.md §1.

Owner: WS-F. `python -m bench.report bench/results`. Reads only result files with a .meta.json (frozen runs).
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def _pct(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.0f}% [{100 * lo:.0f}-{100 * hi:.0f}]" if n else "-"


def load(results_dir: str) -> list[dict]:
    rows = []
    for meta in sorted(Path(results_dir).glob("*.meta.json")):
        stem = meta.name[: -len(".meta.json")]
        main = Path(results_dir) / f"{stem}.jsonl"
        extra = Path(results_dir) / f"{stem}.extra.jsonl"
        if not (main.exists() and extra.exists()):
            continue
        ex = {(e["case_id"], e["human_policy"]): e for e in map(json.loads, extra.read_text().splitlines())}
        for r in map(json.loads, main.read_text().splitlines()):
            rows.append({**r, **ex.get((r["case_id"], r["human_policy"]), {}), "_run": stem})
    return rows


def report(results_dir: str) -> str:
    """Markdown table per model x arm x human: attack ASR, money to attacker, false-block, exceptions/100."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in load(results_dir):
        groups[(r["model"], r["arm"], r["human_policy"])].append(r)
    out = ["| model | arm | human | attack n | ASR (95% CI) | money to attacker CZK | in-mandate residual CZK "
           "| benign n | false-block (95% CI) | exceptions/100 | device prompts/100 | USD/100 |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for (model, arm, human), rs in sorted(groups.items()):
        att = [r for r in rs if r.get("kind") == "attack"]
        ben = [r for r in rs if r.get("kind") == "benign"]
        k = sum(r["attack_success"] for r in att)
        fb = sum(not r["utility_ok"] for r in ben)
        n = len(rs)
        out.append(f"| {model.split(':')[0]} | {arm} | {human} | {len(att)} | {_pct(k, len(att))} "
                   f"| {sum(r.get('money_to_attacker_minor', 0) for r in att) / 100:,.0f} "
                   f"| {sum(r.get('excess_minor', 0) for r in att) / 100:,.0f} | {len(ben)} | {_pct(fb, len(ben))} "
                   f"| {100 * sum(r.get('exceptions', 0) for r in rs) / max(n, 1):.0f} "
                   f"| {100 * sum(r.get('device_prompts', 0) for r in rs) / max(n, 1):.0f} "
                   f"| {sum(r['cost_usd_micros'] for r in rs) / 1e6 / max(n, 1) * 100:.2f} |")
    out.append("\nSimulated humans are a model of a human, not a user study. A3 gate = bench twin until the executor merges.")
    return "\n".join(out)


if __name__ == "__main__":
    print(report(sys.argv[1] if len(sys.argv) > 1 else "bench/results"))
