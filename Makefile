.PHONY: deploy-production deploy-staging infra-preview-production infra-preview-staging

RELAY_VERSION ?= v0.1.0

# ---------------------------------------------------------------------------
# Production deploy - full 3-step pipeline:
#   1. pulumi up  - provision AWS infrastructure
#   2. inventory_gen.py - render ansible/inventory/production.yml
#   3. ansible-playbook - deploy software
# ---------------------------------------------------------------------------
deploy-production:
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
deploy-staging:
	pulumi up --stack staging --cwd infra/ --yes
	python infra/inventory_gen.py --stack staging
	cd ansible && ansible-playbook \
		-i inventory/staging.yml \
		playbooks/site.yml \
		-e relay_version=$(RELAY_VERSION) \
		--ask-vault-pass

# ---------------------------------------------------------------------------
# Dry-run previews (no changes applied)
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

