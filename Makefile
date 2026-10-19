PY := .venv/bin/python

.PHONY: help venv data test test-render dev ui ui-visual bench verify e2e scene-s2 scene-s3 contracts lint ci lock deploy teardown checkpoint-now preflight agent-s1 agent-s2

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

ui:  ## operations console against AWS (AWS_PROFILE=hackathon); UI_URL=memory: for seeded local data
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} AIRGAP_EXECUTOR_URL=$(or $(UI_URL),$(DEMO_URL)) .venv/bin/streamlit run host/ui.py

ui-visual:  ## visual test: headless Chromium clicks every console tab on seeded data, screenshots in .local/ui-visual/
	$(PY) -m playwright install chromium >/dev/null
	$(PY) -m tools.ui_visual

bench:  ## run AgentPayBench
	$(PY) -m bench.run_bench --out bench/results

e2e: data  ## demo beat S1 end to end (memory backend; URL=http://127.0.0.1:8000 CLERK_KEY= TREASURY_KEY= to drive a server)
	$(PY) -m executor.e2e $(if $(URL),--url $(URL) --clerk-key $(CLERK_KEY) --treasury-key $(TREASURY_KEY))

scene-s2:  ## demo beat S2 (lookalike BEC, escalation, exfil) through dispatch, memory backend
	$(PY) -m executor.scenes s2 $(if $(URL),--url $(URL))

scene-s3:  ## demo beat S3 (takeover rejected via tripwire, then legit 2/3 VCs -> 2/2 -> ACTIVE), memory backend
	$(PY) -m executor.scenes s3 $(if $(URL),--url $(URL))

verify:  ## verify an audit export offline
	$(PY) -m tools.verify_audit

deploy:  ## deploy to AWS eu-central-1 (the demo runs here; WS-E): build zip, cdk deploy, post-deploy wiring
	infra/build_lambda.sh
	cd infra && (test -d .venv || (uv venv -q --python 3.12 .venv && uv pip install -q --python .venv/bin/python -r requirements.txt)) && \
	  AWS_PROFILE=$${AWS_PROFILE:-hackathon} npx --yes aws-cdk@2 deploy --require-approval never AirgapMandates
	infra/post_deploy.sh

teardown:  ## tear down AWS resources incl. Object Lock governance bypass (WS-E)
	infra/teardown.sh

agent-s1:  ## agent beat S1 on AWS (agent λ in the no-NAT VPC, quarantined, Sonnet): 3 legit invoices
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} $(PY) -m agent run --scenario s1 --url $(DEMO_URL)

agent-s2:  ## agent beat S2 on AWS: lookalike BEC email (expect no payment)
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} $(PY) -m agent run --scenario s2 --url $(DEMO_URL)

checkpoint-now:  ## invoke airgap-checkpointer once (signed checkpoint + W1 cosign now, for the demo beat)
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} aws lambda invoke --region eu-central-1 --function-name airgap-checkpointer \
	  --cli-binary-format raw-in-base64-out --payload '{"action":"tick","log_id":"audit"}' /dev/stdout

.PHONY: demo-bundle offline-demo

# Built once while online; never touches the network afterwards (GOPROXY=off: a cold module cache fails fast).
.local/bin/noteverify: tools/noteverify/main.go tools/noteverify/go.mod tools/noteverify/go.sum
	cd tools/noteverify && CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build -o ../../.local/bin/noteverify .

demo-bundle:  ## pre-seal the offline demo bundle into docs/audit/demo (refuses unless it verifies green)
	$(PY) -m tools.demo_bundle

preflight:  ## stage-laptop checklist: Safe 3 GENUINE + unlocked, treasury emulator, AWS creds + /health hashes, offline bundle, Bedrock
	AWS_PROFILE=$${AWS_PROFILE:-hackathon} $(PY) -m tools.preflight $(ARGS)

offline-demo: .local/bin/noteverify  ## "Wi-Fi off" stage check of docs/audit/demo (build noteverify while online)
	bash tools/offline_demo.sh docs/audit/demo

# ---------------------------------------------------------------- live demo on AWS (WS-F; scenes refuse non-AWS)
.PHONY: demo-reset demo-s1 demo-s2 demo-s3 demo-s5 stage-bundle rehearse
DEMO_URL ?= $(shell $(PY) -c "import json;print(json.load(open('infra/evidence/post_deploy.json'))['api_url'])" 2>/dev/null)
# W2 (litewitness on EC2) holds its own key, not KMS: pin it from the committed W2 evidence, out of band
W2_VKEY ?= $(or $(AIRGAP_W2_VKEY),$(shell $(PY) -c "import json;print(json.load(open('docs/audit/aws-w2-mon/trust-keys.json'))['w2'])" 2>/dev/null))
DEMO_ENV = AIRGAP_BACKEND=aws AWS_REGION=eu-central-1 AIRGAP_EXECUTOR_URL=$(DEMO_URL) AIRGAP_W2_VKEY=$(W2_VKEY)

demo-reset:  ## AWS OWNER ONLY (docs/STAGE.md T-60): = infra.reset_state --yes (wipes the airgap-* tables, re-seeds)
	$(DEMO_ENV) $(PY) -m infra.reset_state --yes

demo-s1:  ## S1 rehearsal on AWS with software keys (stage: host.signer s1 --url, Safe 3; docs/STAGE.md)
	$(DEMO_ENV) $(PY) -m demo.scene_s1

demo-s2:  ## live S2 on AWS (lookalike BEC, escalation, exfil)
	$(DEMO_ENV) $(PY) -m demo.scene_s2

demo-s3:  ## live S3 on AWS (takeover -> ATT 0/3 -> tripwire reject; legit 2/3 VCs -> 2/2 -> ACTIVE; waits 20 s cooling)
	$(DEMO_ENV) $(PY) -m demo.scene_s3

demo-s5:  ## seal the audit export from AWS (auditor role, read-only) + tampered copy, for the offline beat
	$(DEMO_ENV) $(PY) -m demo.scene_s5

rehearse:  ## FULL stage rehearsal in one command: preflight, reset+inbox, S1 (Safe 3), S2, S3, S5 offline; times each beat
	bash tools/rehearse.sh

stage-bundle:  ## seal the AWS export into docs/audit/demo (W2 pinned; refuses unless green), then: make offline-demo
	$(DEMO_ENV) $(PY) -m tools.demo_bundle --from-aws $(DEMO_URL) --out docs/audit/demo
