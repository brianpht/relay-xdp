.PHONY: deploy-production deploy-staging infra-preview-production infra-preview-staging preflight test-infra \
        e2e-deployed e2e-teardown venv

RELAY_VERSION ?= v0.1.0

# ---------------------------------------------------------------------------
# Python interpreter: prefer infra/.venv if it exists, fall back to python3.
# Run `make venv` once to create the virtualenv and install dependencies.
# ---------------------------------------------------------------------------
INFRA_VENV  := infra/.venv
INFRA_PYTHON := $(shell [ -x "$(CURDIR)/$(INFRA_VENV)/bin/python" ] && echo "$(CURDIR)/$(INFRA_VENV)/bin/python" || echo "python3")

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
# Required environment variables for any infra target:
#   export AWS_PROFILE=relay-xdp-infra
#   export PULUMI_BACKEND_URL=s3://relay-xdp-pulumi-state?region=us-east-1
#   export PULUMI_CONFIG_PASSPHRASE="staging"   # or production passphrase
# See infra/README.md for full setup instructions.
# ---------------------------------------------------------------------------

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
# Infra unit tests (no AWS credentials required)
# ---------------------------------------------------------------------------
test-infra:
	$(INFRA_PYTHON) infra/test_admin_cidr_validation.py
	$(INFRA_PYTHON) infra/test_inventory_gen.py
	$(INFRA_PYTHON) infra/test_stack_outputs.py

# ---------------------------------------------------------------------------
# Production deploy - full 3-step pipeline:
#   1. pulumi up  - provision AWS infrastructure
#   2. inventory_gen.py - render ansible/inventory/production.yml
#   3. ansible-playbook - deploy software
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
# Staging deploy - same pipeline, vault password prompted interactively
# ---------------------------------------------------------------------------
deploy-staging: preflight
	pulumi up --stack staging --cwd infra/ --yes
	$(INFRA_PYTHON) infra/inventory_gen.py --stack staging
	cd ansible && ansible-playbook \
		-i inventory/staging.yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		--ask-vault-pass

# ---------------------------------------------------------------------------
# Dry-run previews (no changes applied, no preflight check)
# ---------------------------------------------------------------------------
infra-preview-production:
	pulumi preview --stack production --cwd infra/

infra-preview-staging:
	pulumi preview --stack staging --cwd infra/

# ---------------------------------------------------------------------------
# Destroy (staging only - production requires manual pulumi destroy)
# ---------------------------------------------------------------------------
infra-destroy-staging:
	pulumi destroy --stack staging --cwd infra/ --yes

# ---------------------------------------------------------------------------
# E2E deployed test - full pipeline against a live provisioned stack.
#
# Usage:
#   make e2e-deployed                        # staging, full pulumi up + deploy + test
#   make e2e-deployed REUSE_STACK=1          # skip pulumi up (infra unchanged)
#   make e2e-deployed STACK=production       # production (requires --ask-vault-pass)
#
# Required env vars (same as deploy targets):
#   export AWS_PROFILE=relay-xdp-infra
#   export PULUMI_BACKEND_URL=s3://relay-xdp-pulumi-state?region=us-east-1
#   export PULUMI_CONFIG_PASSPHRASE="staging"
#
# On failure the stack is left alive for forensic inspection.
# When investigation is complete run: make e2e-teardown STACK=<stack>
# ---------------------------------------------------------------------------

STACK       ?= staging
REUSE_STACK ?= 0

# Vault flag: production requires --ask-vault-pass; staging uses --vault-password-file
ifeq ($(STACK),production)
_VAULT_FLAG := --ask-vault-pass
else
_VAULT_FLAG := --vault-password-file ansible/.vault-pass-staging
endif

e2e-deployed: preflight
	@# -- Step 1: provision infra (skip with REUSE_STACK=1) ------------------
	@if [ "$(REUSE_STACK)" != "1" ]; then \
		echo "[e2e] pulumi up --stack $(STACK)"; \
		pulumi up --stack $(STACK) --cwd infra/ --yes; \
	else \
		echo "[e2e] REUSE_STACK=1 - skipping pulumi up"; \
	fi
	@# -- Step 2: render Ansible inventory from Pulumi outputs ---------------
	$(INFRA_PYTHON) infra/inventory_gen.py --stack $(STACK)
	@# -- Step 3: deploy software --------------------------------------------
	cd ansible && ansible-playbook \
		-i inventory/$(STACK).yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		$(_VAULT_FLAG)
	@# -- Step 4: operational verification (systemd, bpftool, lsmod, ss, journal)
	cd ansible && ansible-playbook \
		-i inventory/$(STACK).yml \
		playbooks/e2e-verify.yml \
		$(_VAULT_FLAG)
	@# -- Step 5: HTTP control-plane assertions against live backend ----------
	eval $$($(INFRA_PYTHON) infra/stack_outputs.py --stack $(STACK) --format env) && \
		STACK=$(STACK) bash tests/e2e-deployed.sh
	@# -- Step 6: UDP data-plane E2E (ClientInner -> relays -> ServerInner) --
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
	pulumi destroy --stack $(STACK) --cwd infra/ --yes
	@echo "[e2e-teardown] stack=$(STACK) destroyed"


