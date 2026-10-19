PY := .venv/bin/python

.PHONY: help venv data test test-render dev ui bench verify e2e scene-s2 scene-s3 contracts lint ci lock deploy teardown checkpoint-now

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

deploy:  ## deploy to AWS eu-central-1 (the demo runs here; WS-E): build zip, cdk deploy, post-deploy wiring
	infra/build_lambda.sh
	cd infra && (test -d .venv || (uv venv -q --python 3.12 .venv && uv pip install -q --python .venv/bin/python -r requirements.txt)) && \
	  AWS_PROFILE=$${AWS_PROFILE:-hackathon} npx --yes aws-cdk@2 deploy --require-approval never AirgapMandates
	infra/post_deploy.sh

teardown:  ## tear down AWS resources incl. Object Lock governance bypass (WS-E)
	infra/teardown.sh

checkpoint-now:  ## invoke airgap-checkpointer once (signed checkpoint + W1 cosign now, for the demo beat)
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} aws lambda invoke --region eu-central-1 --function-name airgap-checkpointer \
	  --cli-binary-format raw-in-base64-out --payload '{"action":"tick","log_id":"audit"}' /dev/stdout

.PHONY: demo-bundle offline-demo

# Built once while online; never touches the network afterwards (GOPROXY=off: a cold module cache fails fast).
.local/bin/noteverify: tools/noteverify/main.go tools/noteverify/go.mod tools/noteverify/go.sum
	cd tools/noteverify && CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build -o ../../.local/bin/noteverify .

demo-bundle:  ## pre-seal the offline demo bundle into docs/audit/demo (refuses unless it verifies green)
	$(PY) -m tools.demo_bundle

offline-demo: .local/bin/noteverify  ## "Wi-Fi off" stage check of docs/audit/demo (build noteverify while online)
	bash tools/offline_demo.sh docs/audit/demo
