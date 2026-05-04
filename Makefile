.PHONY: deploy-production deploy-staging infra-preview-production infra-preview-staging \
        infra-destroy-staging _preflight-admin-cidr-production _preflight-admin-cidr-staging

RELAY_VERSION ?= v0.1.0

# ---------------------------------------------------------------------------
# Pulumi preflight checks (P1-04). Refuse to apply if admin_cidr is the
# placeholder REQUIRED_OVERRIDE, missing, or wide-open on production. The
# config.py loader enforces the same invariants at Pulumi-evaluation time;
# this Makefile check fails earlier and with a clearer error.
# ---------------------------------------------------------------------------
_preflight-admin-cidr-production:
	@CIDR=$$(cd infra && pulumi config get admin_cidr --stack production 2>/dev/null); \
	if [ -z "$$CIDR" ] || [ "$$CIDR" = "REQUIRED_OVERRIDE" ]; then \
		echo "ERROR: production admin_cidr is unset or REQUIRED_OVERRIDE."; \
		echo "       Set it with: pulumi config set admin_cidr <YOUR_IP>/32 --cwd infra --stack production"; \
		echo "       See P1-04 in docs/sessions/2026-05-04-project-audit-plan-v2.md"; \
		exit 1; \
	fi; \
	case "$$CIDR" in \
		0.0.0.0/0|::/0|0.0.0.0/*|*/0) \
			echo "ERROR: production admin_cidr=$$CIDR is wide-open. P1-04 refuses this on production."; \
			echo "       Narrow it: pulumi config set admin_cidr <YOUR_IP>/32 --cwd infra --stack production"; \
			exit 1; ;; \
	esac; \
	echo "preflight OK: production admin_cidr=$$CIDR"

_preflight-admin-cidr-staging:
	@CIDR=$$(cd infra && pulumi config get admin_cidr --stack staging 2>/dev/null); \
	if [ -z "$$CIDR" ] || [ "$$CIDR" = "REQUIRED_OVERRIDE" ]; then \
		echo "ERROR: staging admin_cidr is unset or REQUIRED_OVERRIDE."; \
		echo "       Set it with: pulumi config set admin_cidr <YOUR_IP>/32 --cwd infra --stack staging"; \
		exit 1; \
	fi; \
	echo "preflight OK: staging admin_cidr=$$CIDR"

# ---------------------------------------------------------------------------
# Production deploy - full 3-step pipeline:
#   0. preflight - refuse if admin_cidr is wide-open / unset (P1-04)
#   1. pulumi up  - provision AWS infrastructure
#   2. inventory_gen.py - render ansible/inventory/production.yml
#   3. ansible-playbook - deploy software
# ---------------------------------------------------------------------------
deploy-production: _preflight-admin-cidr-production
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
deploy-staging: _preflight-admin-cidr-staging
	pulumi up --stack staging --cwd infra/ --yes
	python infra/inventory_gen.py --stack staging
	cd ansible && ansible-playbook \
		-i inventory/staging.yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		--ask-vault-pass

# ---------------------------------------------------------------------------
# Dry-run previews (no changes applied) - preflight still runs so a missing
# admin_cidr fails loud at preview time, not at apply time.
# ---------------------------------------------------------------------------
infra-preview-production: _preflight-admin-cidr-production
	pulumi preview --stack production --cwd infra/

infra-preview-staging: _preflight-admin-cidr-staging
	pulumi preview --stack staging --cwd infra/

# ---------------------------------------------------------------------------
# Destroy (staging only - production requires manual pulumi destroy)
# ---------------------------------------------------------------------------
infra-destroy-staging:
	pulumi destroy --stack staging --cwd infra/ --yes

