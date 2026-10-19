PY := .venv/bin/python

.PHONY: help venv data test test-render dev ui bench verify e2e scene-s2 scene-s3 contracts lint ci lock deploy teardown

help:  ## list targets
	@awk -F ":.*## " "/^[a-z-]+:.*## / {printf \"%-12s %s\\n\", \$$1, \$$2}" Makefile

venv:  ## create .venv (Python 3.12) and install the package with dev/ui/host extras
	uv venv --python 3.12 .venv && uv pip install --python $(PY) -e ".[dev,ui,host]"

lock:  ## refresh uv.lock
	uv lock

data:  ## build data/mostlyright/snapshot.sqlite from the (uncommitted) CSV if missing; checks snapshot.sha256
	$(PY) -m tools.load_mostlyright ensure

test: data  ## run all tests (memory/moto backends)
	.venv/bin/pytest -q

test-render:  ## run canonical renderer tests only
	.venv/bin/pytest -q tests/test_render.py

lint:  ## ruff
	.venv/bin/ruff check .

contracts:  ## regenerate contracts/schemas and contracts/fixtures from contracts/build.py
	$(PY) -m contracts.build

ci: data  ## contracts (must be up to date) -> ruff -> pytest; run on every merge
	$(PY) -m contracts.build && git diff --exit-code -- contracts/
	.venv/bin/ruff check .
	.venv/bin/pytest -q

dev: data  ## run executor locally (in-memory backend, development only) on :8000
	AIRGAP_BACKEND=memory .venv/bin/uvicorn executor.app:app --reload --port 8000

ui:  ## run Streamlit host UI
	.venv/bin/streamlit run host/ui.py

bench:  ## run AgentPayBench
	$(PY) -m bench.run_bench --out bench/results

e2e: data  ## demo beat S1 end to end (memory backend; URL=http://127.0.0.1:8000 CLERK_KEY= TREASURY_KEY= to drive a server)
	$(PY) -m executor.e2e $(if $(URL),--url $(URL) --clerk-key $(CLERK_KEY) --treasury-key $(TREASURY_KEY))

scene-s2:  ## demo beat S2 (lookalike BEC, escalation, exfil) through dispatch, memory backend
	$(PY) -m executor.scenes s2

scene-s3:  ## demo beat S3 (takeover rejected via tripwire, then legit 2/3 VCs -> 2/2 -> ACTIVE), memory backend
	$(PY) -m executor.scenes s3

verify:  ## verify an audit export offline
	$(PY) -m tools.verify_audit

deploy:  ## deploy to AWS eu-central-1 (the demo runs here; WS-E)
	@echo "TODO WS-E: CDK/SAM deploy (AIRGAP_BACKEND=aws, eu-central-1)" && exit 1

teardown:  ## tear down AWS resources incl. Object Lock governance bypass (WS-E)
	@echo "TODO WS-E: teardown" && exit 1

.PHONY: demo-bundle offline-demo

demo-bundle:  ## pre-seal the offline demo bundle into docs/audit/demo (refuses unless it verifies green)
	$(PY) -m tools.demo_bundle

offline-demo:  ## "Wi-Fi off" stage check of docs/audit/demo (builds .local/bin/noteverify first)
	cd tools/noteverify && CGO_ENABLED=0 go build -mod=readonly -o ../../.local/bin/noteverify .
	bash tools/offline_demo.sh docs/audit/demo
