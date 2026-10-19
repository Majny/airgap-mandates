PY := .venv/bin/python

.PHONY: help venv test test-render dev ui bench verify contracts

help:  ## list targets
	@awk -F ":.*## " "/^[a-z-]+:.*## / {printf \"%-12s %s\\n\", \$$1, \$$2}" Makefile

venv:  ## create .venv (Python 3.12) and install the package
	uv venv --python 3.12 .venv && uv pip install --python $(PY) -e .

test:  ## run all tests
	.venv/bin/pytest -q

test-render:  ## run canonical renderer tests only
	.venv/bin/pytest -q tests/test_render.py

dev:  ## run executor locally (in-memory backend) on :8000
	AIRGAP_BACKEND=memory .venv/bin/uvicorn executor.app:app --reload --port 8000

ui:  ## run Streamlit host UI
	.venv/bin/streamlit run host/ui.py

bench:  ## run AgentPayBench
	$(PY) -m bench.run_bench --out bench/results

verify:  ## verify an audit export offline
	$(PY) -m tools.verify_audit

contracts:  ## regenerate contracts/schemas and contracts/fixtures from contracts/build.py
	$(PY) -m contracts.build
