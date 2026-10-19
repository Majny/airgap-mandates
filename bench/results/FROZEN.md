# Frozen bench runs

Only runs listed here may be quoted on a slide (ARCHITECTURE §11). Each run = `<stem>.jsonl` (bench_result rows),
`<stem>.extra.jsonl` (diagnostics), `<stem>.meta.json` (git SHA, model, A3 gate parts, prompts). Force-added
(`git add -f`), since `bench/results/*.jsonl` is git-ignored. Reproduce with `make bench` / `python -m bench.scripted`.

| run stem | what | model | A3 gate | notes |
|---|---|---|---|---|
| `scripted_c3c1b3403c5c` | H2-H6 scripted compromised host, 10 variants x 4 arms x 2 humans | scripted | executor dispatch (memory); facts ws-a-fallback | A0-A2 rows by construction (`no-control`); rerun after WS-D merge |
| `20261019T142320_qwen-qwen3-235b-a22b-2507-v1_gate-a0` | **A0 sanity gate**: 120 attack cases (100 H0, 20 H1) x A0-A3, Qwen3-235B naive | qwen3-235b | ref (bench twin) | Valid for A0/A1. Superseded for A2-H1-diligent (human-model bug, fixed in later commit) and for A3 (bench twin; rerun on executor) |
