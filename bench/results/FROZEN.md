# Frozen bench runs

Only runs listed here may be quoted on a slide (ARCHITECTURE §11). Each run = `<stem>.jsonl` (bench_result rows),
`<stem>.extra.jsonl` (diagnostics), `<stem>.meta.json` (git SHA, model, A3 gate parts, prompts). Force-added
(`git add -f`), since `bench/results/*.jsonl` is git-ignored. Reproduce with `make bench` / `python -m bench.scripted`.

| run stem | what | model | A3 gate | notes |
|---|---|---|---|---|
| `scripted_c3c1b3403c5c` | H2-H6 scripted compromised host, 10 variants x 4 arms x 2 humans | scripted | executor dispatch (memory); facts ws-a-fallback | A0-A2 rows by construction (`no-control`); rerun after WS-D merge |
| `20261019T142320_qwen-qwen3-235b-a22b-2507-v1_gate-a0` | **A0 sanity gate**: 120 attack cases (100 H0, 20 H1) x A0-A3, Qwen3-235B naive | qwen3-235b | ref (bench twin) | Valid for A0/A1. Superseded for A2-H1-diligent (human-model bug, fixed in later commit) and for A3 (bench twin; rerun on executor) |
| `20261019T150142_qwen-qwen3-235b-a22b-2507-v1_pitch-attack` | **PITCH** attack: 120 (100 H0 + 20 H1) x A0-A3, A3 naive+quarantined, 2 humans | qwen3-235b | executor dispatch + real WS-D facts/FSM | git 2c19bfd |
| `20261019T151517_qwen-qwen3-235b-a22b-2507-v1_pitch-benign` | SUPERSEDED by pitch-benign-v2 (no prompt breakdown). benign: 100 x A0-A3, A3 naive+quarantined, 2 humans | qwen3-235b | same | git 099760c = 2c19bfd + UI-only commits (no bench/executor change) |
| `scripted_462ade534575` | SUPERSEDED by `scripted_64ff276755d5` (rerun on FACTS-1 code with document-bound H2-H4 fixtures; identical outcomes). H2-H6 scripted, 10 variants, one row per arm without a human | scripted | same | supersedes `scripted_c3c1b3403c5c` |
| `20261019T153447_qwen-qwen3-235b-a22b-2507-v1_pitch-benign-v2` | **PITCH** benign v2: 100 x A0-A3, A3 naive+quarantined, 2 humans, device prompts by reason | qwen3-235b | same | git 3db9604 |
| `20261019T153447_eu-anthropic-claude-sonnet-4-5-20250929-v1_sonnet-spot-attack` | **SONNET spot-check** attack: every 3rd case (34 H0 + 6 H1) x A0 + A3 rubber_stamp, naive | sonnet-4.5 (eu.) | same | git 3db9604, 20 rpm |
| `20261019T155908_eu-anthropic-claude-sonnet-4-5-20250929-v1_sonnet-spot-benign` | **SONNET spot-check** benign: every 5th case x A3 diligent, naive | sonnet-4.5 (eu.) | same | git 3db9604 |
| `scripted_64ff276755d5` | **PITCH** H2-H6 scripted on main 64ff276 (FACTS-1), H2-H4 document-bound (real PAY step-up before each attack) | scripted | same | supersedes `scripted_462ade534575` |
| `20261019T181809_qwen-qwen3-235b-a22b-2507-v1_facts1-check-attack` | FACTS-1 verification only (not a headline): every 6th attack case, A3 rubber_stamp naive; 20/20 rows identical to pitch-attack | qwen3-235b | same | git 64ff276 |
| `20261019T181832_qwen-qwen3-235b-a22b-2507-v1_facts1-check-benign` | FACTS-1 verification only: every 5th benign case, A3 diligent naive+quarantined; utility fails 6/40 vs 4/40 frozen (noise: the two F-AMOUNT-DOC cases pass on rerun) | qwen3-235b | same | git 64ff276 |
