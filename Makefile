.PHONY: deploy-production deploy-staging infra-preview-production infra-preview-staging preflight test-infra \
        e2e-deployed e2e-teardown venv update-admin-cidr \
        bench-local bench-relay \
        bench-deploy

# Process substitution <(echo ...) requires bash.
SHELL := /bin/bash

# Read default version from Ansible group_vars/all.yml - single source of truth.
# Override at the command line: make deploy-staging RELAY_VERSION=v1.2.3
RELAY_VERSION ?= $(shell grep '^relay_version:' ansible/playbooks/group_vars/all.yml | sed 's/.*"\(.*\)"/\1/')

# ---------------------------------------------------------------------------
# Python interpreter: prefer infra/.venv if it exists, fall back to python3.
# Run `make venv` once to create the virtualenv and install dependencies.
# ---------------------------------------------------------------------------
INFRA_VENV  := infra/.venv
INFRA_PYTHON := $(shell [ -x "$(CURDIR)/$(INFRA_VENV)/bin/python" ] && echo "$(CURDIR)/$(INFRA_VENV)/bin/python" || echo "python3")

# ---------------------------------------------------------------------------
# Staging Pulumi environment - injected automatically into staging targets.
# Priority (highest to lowest):
#   1. Variables already exported in the calling shell (CI, direnv, ~/.bashrc)
#   2. infra/.pulumi-env-staging file on disk (gitignored, operator local)
#   3. Hardcoded staging defaults
#
# To create the local file once per machine:
#   cat > infra/.pulumi-env-staging <<'EOF'
#   export AWS_PROFILE=relay-xdp-infra
#   export PULUMI_BACKEND_URL=s3://relay-xdp-pulumi-state?region=us-east-1
#   export PULUMI_CONFIG_PASSPHRASE=staging
#   EOF
#   chmod 600 infra/.pulumi-env-staging
#
# Production requires all three vars set explicitly in the calling shell.
# No defaults are injected for production to prevent cross-env accidents.
# ---------------------------------------------------------------------------
_PULUMI_ENV_STAGING = \
  { [ -f $(CURDIR)/infra/.pulumi-env-staging ] && source $(CURDIR)/infra/.pulumi-env-staging || true; }; \
  export AWS_PROFILE=$${AWS_PROFILE:-relay-xdp-infra}; \
  export PULUMI_BACKEND_URL=$${PULUMI_BACKEND_URL:-s3://relay-xdp-pulumi-state?region=us-east-1}; \
  export PULUMI_CONFIG_PASSPHRASE=$${PULUMI_CONFIG_PASSPHRASE:-staging}

# ---------------------------------------------------------------------------
# venv: create infra/.venv and install dependencies (run once per machine)
# ---------------------------------------------------------------------------
venv:
	python3 -m venv $(INFRA_VENV)
	$(INFRA_VENV)/bin/pip install -q --upgrade pip
	$(INFRA_VENV)/bin/pip install -q -r infra/requirements.txt
	@echo "venv ready: $(INFRA_VENV)"
	@echo "To activate manually: source $(INFRA_VENV)/bin/activate"


# ---------------------------------------------------------------------------
# Preflight: abort if either Pulumi stack still carries an open admin_cidr.
# Set your real CIDR with:
#   pulumi config set relay-xdp-infra:admin_cidr "$(curl -4 -s ifconfig.me)/32" --stack staging
#   pulumi config set relay-xdp-infra:admin_cidr "$(curl -4 -s ifconfig.me)/32" --stack production
# ---------------------------------------------------------------------------
preflight:
	@if grep -rq '0\.0\.0\.0/0' infra/Pulumi.production.yaml infra/Pulumi.staging.yaml; then \
		echo "ERROR: admin_cidr is set to 0.0.0.0/0 - restrict to your ops CIDR before deploying"; \
		exit 1; \
	fi
	@if grep -rq 'REPLACE_ME' infra/Pulumi.production.yaml infra/Pulumi.staging.yaml; then \
		echo "ERROR: admin_cidr contains REPLACE_ME placeholder - set a real CIDR before deploying"; \
		exit 1; \
	fi
	@echo "preflight: admin_cidr looks ok"

# ---------------------------------------------------------------------------
# update-admin-cidr: fetch current public IPv4 and write it into both stacks.
# Run this whenever your home/office IP changes before deploying.
#
# Usage:
#   make update-admin-cidr            # update staging only (default)
#   make update-admin-cidr STACK=both # update staging + production
# ---------------------------------------------------------------------------
update-admin-cidr:
	$(eval MY_CIDR := $(shell curl -4 -s ifconfig.me)/32)
	@if [ -z "$(MY_CIDR)" ] || [ "$(MY_CIDR)" = "/32" ]; then \
		echo "ERROR: could not fetch public IP from ifconfig.me"; exit 1; \
	fi
	@echo "[update-admin-cidr] detected public IP: $(MY_CIDR)"
	@$(_PULUMI_ENV_STAGING); \
	pulumi config set relay-xdp-infra:admin_cidr "$(MY_CIDR)" --stack staging --cwd infra/ && \
	echo "[update-admin-cidr] staging -> $(MY_CIDR)"
	@if [ "$(STACK)" = "both" ]; then \
		$(_PULUMI_ENV_STAGING); \
		pulumi config set relay-xdp-infra:admin_cidr "$(MY_CIDR)" --stack production --cwd infra/ && \
		echo "[update-admin-cidr] production -> $(MY_CIDR)"; \
	fi
	@echo "[update-admin-cidr] done. Run 'make infra-preview-staging' to verify, then 'make deploy-staging' to apply."

# ---------------------------------------------------------------------------
# Infra unit tests (no AWS credentials required)
# ---------------------------------------------------------------------------
test-infra:
	$(INFRA_PYTHON) infra/test_admin_cidr_validation.py
	$(INFRA_PYTHON) infra/test_inventory_gen.py
	$(INFRA_PYTHON) infra/test_stack_outputs.py

# ---------------------------------------------------------------------------
# Production deploy - full 3-step pipeline.
# Requires AWS_PROFILE, PULUMI_BACKEND_URL, PULUMI_CONFIG_PASSPHRASE set in
# the calling shell. No defaults injected (cross-env safety).
# ---------------------------------------------------------------------------
deploy-production: preflight
	pulumi up --stack production --cwd infra/ --yes
	$(INFRA_PYTHON) infra/inventory_gen.py --stack production
	cd ansible && ansible-playbook \
		-i inventory/production.yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		--ask-vault-pass

# ---------------------------------------------------------------------------
# Staging vault passphrase - 3-tier priority (highest to lowest):
#   1. VAULT_PASS_STAGING env var  - CI secrets / direnv
#   2. ansible/.vault-pass-staging - operator local file (gitignored)
#   3. Literal "staging"           - dev default per ansible/README.md
#
# Production always prompts interactively (--ask-vault-pass) to prevent
# accidental use of the staging passphrase against the production vault.
# ---------------------------------------------------------------------------
ifeq ($(STACK),production)
_VAULT_FLAG := --ask-vault-pass
else ifdef VAULT_PASS_STAGING
_VAULT_FLAG := --vault-password-file <(echo "$(VAULT_PASS_STAGING)")
else ifneq ($(wildcard ansible/.vault-pass-staging),)
_VAULT_FLAG := --vault-password-file ansible/.vault-pass-staging
else
_VAULT_FLAG := --vault-password-file <(echo staging)
endif

# ---------------------------------------------------------------------------
# Staging deploy - Pulumi env vars injected automatically (no manual export).
# All commands run in one subshell so exported vars carry across steps.
# ---------------------------------------------------------------------------
deploy-staging: preflight
	@$(_PULUMI_ENV_STAGING); \
	pulumi up --stack staging --cwd infra/ --yes && \
	$(INFRA_PYTHON) infra/inventory_gen.py --stack staging && \
	cd ansible && ansible-playbook \
		-i inventory/staging.yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		$(_VAULT_FLAG)

# ---------------------------------------------------------------------------
# Dry-run previews (no changes applied, no preflight check)
# ---------------------------------------------------------------------------
infra-preview-production:
	pulumi preview --stack production --cwd infra/

infra-preview-staging:
	@$(_PULUMI_ENV_STAGING); \
	pulumi preview --stack staging --cwd infra/

# ---------------------------------------------------------------------------
# Destroy (staging only - production requires manual pulumi destroy)
# ---------------------------------------------------------------------------
infra-destroy-staging:
	@$(_PULUMI_ENV_STAGING); \
	pulumi destroy --stack staging --cwd infra/ --yes

# ---------------------------------------------------------------------------
# E2E deployed test - full pipeline against a live provisioned stack.
#
# Usage:
#   make e2e-deployed                        # staging, full pulumi up + deploy + test
#   make e2e-deployed REUSE_STACK=1          # skip pulumi up (infra unchanged)
#   make e2e-deployed STACK=production       # production (requires explicit env vars)
#
# On failure the stack is left alive for forensic inspection.
# When investigation is complete run: make e2e-teardown STACK=<stack>
# ---------------------------------------------------------------------------

STACK       ?= staging
REUSE_STACK ?= 0

e2e-deployed: preflight
	@# -- Steps 1-4: run in one subshell so _PULUMI_ENV_STAGING carries through.
	@$(_PULUMI_ENV_STAGING); \
	if [ "$(REUSE_STACK)" != "1" ]; then \
		echo "[e2e] pulumi up --stack $(STACK)"; \
		pulumi up --stack $(STACK) --cwd infra/ --yes; \
	else \
		echo "[e2e] REUSE_STACK=1 - skipping pulumi up"; \
	fi && \
	$(INFRA_PYTHON) infra/inventory_gen.py --stack $(STACK) && \
	cd ansible && ansible-playbook \
		-i inventory/$(STACK).yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		$(_VAULT_FLAG) && \
	ansible-playbook \
		-i inventory/$(STACK).yml \
		playbooks/e2e-verify.yml \
		$(_VAULT_FLAG)
	@# -- Step 5: HTTP control-plane assertions against live backend ----------
	@$(_PULUMI_ENV_STAGING); \
	eval $$($(INFRA_PYTHON) infra/stack_outputs.py --stack $(STACK) --format env) && \
		STACK=$(STACK) bash tests/e2e-deployed.sh
	@# -- Step 6: UDP data-plane E2E (ClientInner -> relays -> ServerInner) --
	@$(_PULUMI_ENV_STAGING); \
	eval $$($(INFRA_PYTHON) infra/stack_outputs.py --stack $(STACK) --format env) && \
		RELAY_E2E_UDP=1 cargo run -p relay-sdk --bin relay_sdk_smoke
	@echo "[e2e] ALL CHECKS PASSED for stack=$(STACK)"

# ---------------------------------------------------------------------------
# E2E teardown - destroy the stack after investigation is complete.
# Refuses to destroy the production stack; production must be torn down
# manually via: pulumi destroy --stack production --cwd infra/
# ---------------------------------------------------------------------------
e2e-teardown:
	@if [ "$(STACK)" = "production" ]; then \
		echo "ERROR: e2e-teardown refuses to destroy the production stack."; \
		echo "       Run manually: pulumi destroy --stack production --cwd infra/"; \
		exit 1; \
	fi
	@echo "[e2e-teardown] destroying stack=$(STACK)"
	@$(_PULUMI_ENV_STAGING); \
	pulumi destroy --stack $(STACK) --cwd infra/ --yes
	@echo "[e2e-teardown] stack=$(STACK) destroyed"

# ---------------------------------------------------------------------------
# Benchmark targets
#
# bench-local: direct mode loopback, no relay-xdp required.
#   Starts bench_server in the background, runs bench_client in direct mode,
#   kills bench_server on exit. Asserts p99 RTT < 500 us via exit code.
#
# bench-deploy: build + deploy bench_server (bench node) + relay-backend (backend node).
#   bench_client always runs locally (laptop/CI). Full deploy + validate workflow:
#
#     Step 1 - provision infra (once per stack):
#       make deploy-staging          # or: cd infra && pulumi up --stack staging
#
#     Step 2 - deploy bench_server (bench node) + relay-backend (backend node):
#       make bench-deploy STACK=staging
#
#     Step 3 - run bench_client locally for >=60 s (addresses auto-resolved from stack):
#       make bench-relay STACK=staging DURATION_SECS=60
#
#       Or override individual addresses explicitly:
#       make bench-relay \
#         RELAY_ADDR=${RELAY_PUBLIC_IPS%% *}:40000 \
#         BACKEND_ADMIN=http://${BACKEND_HOST}:8091 \
#         BENCH_SERVER_HTTP=${BENCH_HOST}:18080 \
#         BENCH_SERVER_UDP=${BENCH_HOST}:17777 \
#         DURATION_SECS=60
#
#   A healthy 60 s run shows pkt_sent=~500 every second with loss <1% and
#   zero drops to pkt_sent=0 (which would indicate the SDK route expired
#   without the 10 s refresh task kicking in).
#
# bench-relay: relay mode against a live relay-xdp instance.
#   All address variables are OPTIONAL when STACK= is set - they are auto-resolved
#   from Pulumi stack outputs via stack_outputs.py when not explicitly provided.
#
#   Minimal usage (auto-resolve addresses from staging stack):
#     make bench-relay
#     make bench-relay STACK=staging DURATION_SECS=120
#
#   Explicit usage (override individual vars, bypasses stack_outputs.py):
#     make bench-relay RELAY_ADDR=10.0.0.1:40000 BACKEND_ADMIN=http://10.0.0.2:8091
#
#   Optional overrides:
#     STACK            (default: staging)   Pulumi stack to resolve addresses from
#     RELAY_ADDR       auto: first IP in RELAY_PUBLIC_IPS + :40000
#     BACKEND_ADMIN    auto: http://BACKEND_HOST:ADMIN_BACKEND_PORT
#     BENCH_SERVER_HTTP auto: BENCH_HOST:18080
#     BENCH_SERVER_UDP  auto: BENCH_HOST:17777
#     BENCH_CLIENT_UDP  (default 0.0.0.0:17778)
#     TARGET_PPS        (default 500)
#     DURATION_SECS     (default 60 - long enough to exercise route refresh)
# ---------------------------------------------------------------------------
RELAY_ADDR        ?=
BACKEND_ADMIN     ?=
BENCH_SERVER_HTTP ?=
BENCH_SERVER_UDP  ?=
BENCH_CLIENT_UDP  ?= 0.0.0.0:17778
TARGET_PPS        ?= 500
DURATION_SECS     ?= 60

bench-local:
	cargo build --release -p relay-bench
	@{ \
		./target/release/bench_server & SERVER_PID=$$!; \
		BENCH_SERVER_HTTP=127.0.0.1:18080 BENCH_SERVER_UDP=127.0.0.1:17777 \
		BENCH_MODE=direct DURATION_SECS=10 TARGET_PPS=1000 \
		./target/release/bench_client; \
		STATUS=$$?; kill $$SERVER_PID 2>/dev/null || true; wait $$SERVER_PID 2>/dev/null; exit $$STATUS; \
	}

bench-relay:
	cargo build --release -p relay-bench
	@$(_PULUMI_ENV_STAGING); \
	_relay="$(RELAY_ADDR)"; \
	_admin="$(BACKEND_ADMIN)"; \
	_bench_http="$(BENCH_SERVER_HTTP)"; \
	_bench_udp="$(BENCH_SERVER_UDP)"; \
	if [ -z "$$_relay" ]; then \
		echo "[bench-relay] RELAY_ADDR not set - resolving from stack=$(STACK) via stack_outputs.py..."; \
		eval $$($(INFRA_PYTHON) infra/stack_outputs.py --stack $(STACK) --format env); \
		_relay=$$(echo $$RELAY_PUBLIC_IPS | awk '{print $$1}'):40000; \
		_admin=http://$$BACKEND_HOST:$$ADMIN_BACKEND_PORT; \
		_bench_http=$$BENCH_HOST:18080; \
		_bench_udp=$$BENCH_HOST:17777; \
	fi; \
	echo "[bench-relay] relay=$$_relay backend=$$_admin bench_http=$$_bench_http bench_udp=$$_bench_udp duration=$(DURATION_SECS)s pps=$(TARGET_PPS)"; \
	BENCH_MODE=relay \
	DURATION_SECS=$(DURATION_SECS) \
	TARGET_PPS=$(TARGET_PPS) \
	RELAY_ADDR=$$_relay \
	BACKEND_ADMIN=$$_admin \
	BENCH_SERVER_HTTP=$$_bench_http \
	BENCH_SERVER_UDP=$$_bench_udp \
	BENCH_CLIENT_UDP=$(BENCH_CLIENT_UDP) \
	./target/release/bench_client

# bench-deploy: build and deploy ALL bench-related services to the staging stack.
#   Deploys relay-backend (backend node) AND bench_server (bench node).
#   bench_client is NOT deployed - it always runs from the local machine.
#
#   Deployment order:
#     1. relay-backend  -> backend_servers  (bench-backend-deploy.yml)
#     2. bench_server   -> bench_servers    (bench-deploy.yml)
#
#   Requires:
#     - bench node + backend node provisioned (pulumi up --stack staging)
#     - bench_servers + backend_servers groups in inventory
#       (auto-populated by infra/inventory_gen.py)
#   Override stack or inventory at the command line:
#     make bench-deploy STACK=staging
#     make bench-deploy STACK=staging INVENTORY=ansible/inventory/staging.yml
STACK     ?= staging
INVENTORY ?= ansible/inventory/$(STACK).yml

bench-deploy:
	cargo build --release -p relay-bench -p relay-backend
	ansible-playbook -i $(INVENTORY) ansible/playbooks/bench-backend-deploy.yml \
	$(_VAULT_FLAG)
	ansible-playbook -i $(INVENTORY) ansible/playbooks/bench-deploy.yml \
	$(_VAULT_FLAG)
