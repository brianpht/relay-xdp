.PHONY: deploy-production deploy-staging infra-preview-production infra-preview-staging preflight test-infra

RELAY_VERSION ?= v0.1.0

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
	cd infra && python test_admin_cidr_validation.py
	cd infra && python test_inventory_gen.py

# ---------------------------------------------------------------------------
# Production deploy - full 3-step pipeline:
#   1. pulumi up  - provision AWS infrastructure
#   2. inventory_gen.py - render ansible/inventory/production.yml
#   3. ansible-playbook - deploy software
# ---------------------------------------------------------------------------
deploy-production: preflight
	pulumi up --stack production --cwd infra/ --yes
	python infra/inventory_gen.py --stack production
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
	python infra/inventory_gen.py --stack staging
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

