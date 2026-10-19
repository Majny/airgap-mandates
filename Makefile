PY := .venv/bin/python

.PHONY: help venv test test-render dev ui bench verify contracts lint ci lock deploy teardown

help:  ## list targets
	@awk -F ":.*## " "/^[a-z-]+:.*## / {printf \"%-12s %s\\n\", \$$1, \$$2}" Makefile

venv:  ## create .venv (Python 3.12) and install the package with dev/ui/host extras
	uv venv --python 3.12 .venv && uv pip install --python $(PY) -e ".[dev,ui,host]"

lock:  ## refresh uv.lock
	uv lock

test:  ## run all tests (memory/moto backends)
	.venv/bin/pytest -q

test-render:  ## run canonical renderer tests only
	.venv/bin/pytest -q tests/test_render.py

lint:  ## ruff
	.venv/bin/ruff check .

contracts:  ## regenerate contracts/schemas and contracts/fixtures from contracts/build.py
	$(PY) -m contracts.build

ci:  ## contracts (must be up to date) -> ruff -> pytest; run on every merge
	$(PY) -m contracts.build && git diff --exit-code -- contracts/
	.venv/bin/ruff check .
	.venv/bin/pytest -q

dev:  ## run executor locally (in-memory backend, development only) on :8000
	AIRGAP_BACKEND=memory .venv/bin/uvicorn executor.app:app --reload --port 8000

ui:  ## run Streamlit host UI
	.venv/bin/streamlit run host/ui.py

bench:  ## run AgentPayBench
	$(PY) -m bench.run_bench --out bench/results

verify:  ## verify an audit export offline
	$(PY) -m tools.verify_audit

deploy:  ## deploy to AWS eu-central-1 (the demo runs here; WS-E)
	@echo "TODO WS-E: CDK/SAM deploy (AIRGAP_BACKEND=aws, eu-central-1)" && exit 1

teardown:  ## tear down AWS resources incl. Object Lock governance bypass (WS-E)
	@echo "TODO WS-E: teardown" && exit 1
