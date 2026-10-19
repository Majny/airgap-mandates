# Frozen bench runs

Only runs listed here may be quoted on a slide (ARCHITECTURE §11). Each run = `<stem>.jsonl` (bench_result rows),
`<stem>.extra.jsonl` (diagnostics), `<stem>.meta.json` (git SHA, model, A3 gate parts, prompts). Force-added
(`git add -f`), since `bench/results/*.jsonl` is git-ignored. Reproduce with `make bench` / `python -m bench.scripted`.

| run stem | what | model | A3 gate | notes |
|---|---|---|---|---|
| `scripted_c3c1b3403c5c` | H2-H6 scripted compromised host, 10 variants x 4 arms x 2 humans | scripted | executor dispatch (memory); facts ws-a-fallback | A0-A2 rows by construction (`no-control`); rerun after WS-D merge |
