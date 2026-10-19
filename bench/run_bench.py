"""AgentPayBench runner, arms A0-A3. `python -m bench.run_bench --out bench/results`. CONTRACTS.md §10.

Owner: WS-F. Loads scenarios from bench/cases/*.jsonl, expands each to one `bench_case` per arm, runs the agent
(Bedrock) against the arm, applies the simulated humans and writes `bench_result` JSONL + a run meta file.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from bench.arms import ARM_CONFIGS, ARMS, Episode
from bench.score import score
from bench.world import World

CASES_DIR = Path(__file__).parent / "cases"
DEFAULT_MODEL = "qwen.qwen3-235b-a22b-2507-v1:0"


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], text=True).strip()
    except Exception:
        return "0000000"


def load_scenarios(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    out = []
    for p in sorted(paths or CASES_DIR.glob("*.jsonl")):
        for line in p.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def bench_case(sc: dict[str, Any], arm: str) -> dict[str, Any]:
    """CONTRACTS §10 bench_case for one scenario on one arm."""
    exp = sc.get("expected", {}).get(arm, {"money_moved_minor": 0, "blocked_by": None})
    return {"id": f"{sc['id']}:{arm}", "arm": arm, "attacker_level": sc["attacker_level"], "vector": sc["vector"],
            "goal": sc["goal"], "seed": int(sc.get("seed", 0)), "expected": exp}


def run_one(sc: dict[str, Any], arm: str, model: str, human: str, sha: str, mode: str = "naive") -> dict[str, Any]:
    from bench.agent_loop import extract, run_episode
    world = World.build(sc)
    start_ibans = world.registry_ibans()
    truth = {**sc.get("truth", {}), "goal": sc["goal"] if sc.get("kind") == "attack" else "none"}
    ep = Episode(ARM_CONFIGS[arm], world, truth, human, ui_lies=sc["attacker_level"] == "H1",
                 quarantined=mode == "quarantined", extractor=extract)
    try:
        run = run_episode(ep, model)
    except Exception as exc:  # noqa: BLE001 - record infra failures, do not count them as results
        return {"_error": f"{type(exc).__name__}: {exc}"[:300], "case_id": f"{sc['id']}:{arm}:{mode}"}
    s = score(world, truth, start_ibans)
    return {"case_id": f"{sc['id']}:{arm}", "arm": arm, "model": model,
            "agent_mode": mode, "human_policy": human, "utility_ok": s["utility_ok"],
            "attack_success": s["attack_success"] if sc.get("kind") == "attack" else False,
            "money_moved_minor": s["money_moved_minor"], "bytes_exfil": s["bytes_exfil"],
            "rule_ids": sorted(ep.rule_ids), "steps": run["steps"], "latency_ms": run["latency_ms"],
            "tokens": run["tokens"], "cost_usd_micros": run["cost_usd_micros"], "git_sha": sha,
            "_extra": {"kind": sc.get("kind"), "level": sc["attacker_level"], "goal": sc["goal"],
                       "exceptions": s["exceptions"], "device_prompts": s["device_prompts"],
                       "money_to_attacker_minor": s["money_to_attacker_minor"], "excess_minor": s["excess_minor"]}}


def run(arm: str, tasks: list[dict[str, Any]], *, out: str, model: str = DEFAULT_MODEL,
        humans: tuple[str, ...] = ("diligent", "rubber_stamp"), workers: int = 8) -> list[dict[str, Any]]:
    """Run scenarios on one arm, write <out>/<run>.jsonl (schema rows) and .extra.jsonl (diagnostics)."""
    return run_matrix([arm], tasks, out=out, model=model, humans=humans, workers=workers)


def run_matrix(arms: list[str], tasks: list[dict[str, Any]], *, out: str, model: str,
               humans: tuple[str, ...], workers: int, tag: str = "",
               modes: tuple[str, ...] = ("naive",)) -> list[dict[str, Any]]:
    sha = git_sha()
    Path(out).mkdir(parents=True, exist_ok=True)
    stem = f"{time.strftime('%Y%m%dT%H%M%S')}_{model.split(':')[0].replace('.', '-')}{'_' + tag if tag else ''}"
    # Quarantined mode is an A3 property (ARCHITECTURE §11); A0-A2 always run naive.
    jobs = [(sc, arm, h, m) for sc in tasks for arm in arms
            for h in (humans if ARM_CONFIGS[arm].sw_approval or ARM_CONFIGS[arm].airgap else humans[:1])
            for m in (modes if ARM_CONFIGS[arm].airgap else ("naive",))]
    rows, errors = [], []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(run_one, sc, arm, model, h, sha, m) for sc, arm, h, m in jobs]
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            (errors if "_error" in r else rows).append(r)
            if i % 20 == 0:
                print(f"  {i}/{len(jobs)} done, {len(errors)} errors", flush=True)
    with open(Path(out) / f"{stem}.jsonl", "w") as fh:
        for r in rows:
            fh.write(json.dumps({k: v for k, v in r.items() if not k.startswith("_")}) + "\n")
    with open(Path(out) / f"{stem}.extra.jsonl", "w") as fh:
        for r in rows:
            fh.write(json.dumps({"case_id": r["case_id"], "human_policy": r["human_policy"],
                                 "agent_mode": r["agent_mode"], **r["_extra"]}) + "\n")
    meta = {"git_sha": sha, "model": model, "arms": arms, "n_jobs": len(jobs), "n_rows": len(rows),
            "errors": errors, "a3_gate": _a3_gate_meta(),
            "agent": "bench.agent_loop", "modes": list(modes),
            "extractor": "bench.agent_loop.extract (quarantined mode)", "humans": "model of a human, not a user study",
            "system_prompt": __import__("bench.agent_loop", fromlist=["SYSTEM_PROMPT"]).SYSTEM_PROMPT}
    (Path(out) / f"{stem}.meta.json").write_text(json.dumps(meta, indent=1))
    print(f"wrote {stem}: {len(rows)} rows, {len(errors)} errors")
    return rows


def _a3_gate_meta() -> dict[str, str]:
    from bench import arms
    if arms.A3_GATE != "executor":
        return {"all": "ref (bench twin of executor rules)"}
    from bench.executor_gate import gate_parts
    return gate_parts()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="bench/results")
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--cases", nargs="*", type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--tag", default="")
    ap.add_argument("--a3-gate", default="executor", choices=["executor", "ref"])
    ap.add_argument("--modes", default="naive", help="A3 agent modes: naive,quarantined")
    a = ap.parse_args(argv)
    from bench import arms
    arms.A3_GATE = a.a3_gate
    tasks = load_scenarios(a.cases)
    if a.limit:
        tasks = tasks[: a.limit]
    run_matrix(a.arms.split(","), tasks, out=a.out, model=a.model, humans=("diligent", "rubber_stamp"),
               workers=a.workers, tag=a.tag, modes=tuple(a.modes.split(",")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
