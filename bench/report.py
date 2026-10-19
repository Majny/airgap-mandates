"""Bench report: ASR, false-block rate, exceptions/100, signatures/100, 95% Wilson intervals. CONTRACTS.md §1.

Owner: WS-F. `python -m bench.report bench/results`. Reads only result files with a .meta.json (frozen runs).
"""
from __future__ import annotations

import json
import math
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


def load(results_dir: str, runs: list[str] | None = None) -> list[dict]:
    rows = []
    for meta in sorted(Path(results_dir).glob("*.meta.json")):
        stem = meta.name[: -len(".meta.json")]
        if runs and stem not in runs:
            continue
        main = Path(results_dir) / f"{stem}.jsonl"
        extra = Path(results_dir) / f"{stem}.extra.jsonl"
        if not (main.exists() and extra.exists()):
            continue
        ex = {(e["case_id"], e["human_policy"], e.get("agent_mode", "naive")): e for e in map(json.loads, extra.read_text().splitlines())}
        for r in map(json.loads, main.read_text().splitlines()):
            rows.append({**r, **ex.get((r["case_id"], r["human_policy"], r["agent_mode"]), {}), "_run": stem})
    return rows


def report(results_dir: str, runs: list[str] | None = None, arms_from: dict[str, str] | None = None) -> str:
    """Markdown table per model x arm x human: attack ASR, money to attacker, false-block, exceptions/100."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in load(results_dir, runs):
        if arms_from and arms_from.get(r["arm"], r["_run"]) != r["_run"]:
            continue  # this arm's cells come from another (newer) run
        human = r["human_policy"] if r["arm"] in ("A2", "A3") else "-"  # A0/A1 have no approver
        level = r.get("level", "?") if r.get("kind") == "attack" else "benign"
        groups[(r["model"], level, r["arm"], r["agent_mode"], human)].append(r)
    out = ["| model | level | arm | mode | human | attack n | ASR (95% CI) | money to attacker CZK | in-mandate residual CZK "
           "| benign n | false-block (95% CI) | exceptions/100 | device prompts/100 | USD/100 |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for (model, level, arm, mode, human), rs in sorted(groups.items()):
        att = [r for r in rs if r.get("kind") == "attack"]
        ben = [r for r in rs if r.get("kind") == "benign"]
        k = sum(r["attack_success"] for r in att)
        fb = sum(not r["utility_ok"] for r in ben)
        n = len(rs)
        out.append(f"| {model.split(':')[0]} | {level} | {arm} | {mode} | {human} | {len(att)} | {_pct(k, len(att))} "
                   f"| {sum(r.get('money_to_attacker_minor', 0) for r in att) / 100:,.0f} "
                   f"| {sum(r.get('excess_minor', 0) for r in att) / 100:,.0f} | {len(ben)} | {_pct(fb, len(ben))} "
                   f"| {100 * sum(r.get('exceptions', 0) for r in rs) / max(n, 1):.0f} "
                   f"| {100 * sum(r.get('device_prompts', 0) for r in rs) / max(n, 1):.0f} "
                   f"| {sum(r['cost_usd_micros'] for r in rs) / 1e6 / max(n, 1) * 100:.2f} |")
    out.append("\nSimulated humans are a model of a human, not a user study. A3 gate = bench twin until the executor merges.")
    return "\n".join(out)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir", nargs="?", default="bench/results")
    ap.add_argument("--runs", default="", help="comma-separated run stems (default: all with meta)")
    a = ap.parse_args()
    print(report(a.results_dir, [r for r in a.runs.split(",") if r] or None))
