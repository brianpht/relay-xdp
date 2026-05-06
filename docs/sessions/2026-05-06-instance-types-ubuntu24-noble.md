# Session Summary: Plan: Instance Types + Ubuntu 24.04 Noble - Final

**Date:** 2026-05-06<br>
**Duration:** ~5 interactions<br>
**Focus Area:** infra / CI - instance type upgrade + OS migration plan + ENA Express ADR<br>

## Objectives

- [x] Identify all files affected by instance type + OS change
- [x] Design AZ map strategy for c6in.8xlarge (production) and c5n.2xlarge (staging)
- [x] Resolve AMI filter bug (jammy-22.04 vs noble-24.04 discrepancy)
- [x] Plan CI runner update (ubuntu-22.04 -> ubuntu-24.04)
- [x] Capture ENA Express follow-up as a new ADR
- [x] Produce final implementation-ready file list with per-file change descriptions
- [ ] Implement all file changes (follow-on work)

## Work Completed

### Codebase Analysis

Reviewed all affected files to understand current state before planning:

| File | Current State | Issue |
|------|--------------|-------|
| `infra/config.py` | `AMI_NAME_FILTER = "ubuntu-jammy-22.04-amd64-*"` | Bug: docstring in `relay_node.py` claims Ubuntu 24.04 Noble; filter is 22.04 Jammy |
| `infra/config.py` | `C5N_AZ_MAP` with 3 AZ values | Name is c5n-specific; used for both staging (c5n) and production (c6in) |
| `infra/Pulumi.staging.yaml` | `relay_instance_type: t3.medium` | XDP generic mode only; does not match production ENA path |
| `infra/Pulumi.production.yaml` | `relay_instance_type: c5n.xlarge` | Upgrade to c6in.8xlarge for higher network bandwidth |
| `.github/workflows/build-release.yml` | `runs-on: ubuntu-22.04` (all 3 jobs) | Target hosts moving to Ubuntu 24.04; CI runner should match |
| `docs/decisions/ADR-003` | References `c5n.xlarge` (native) + `t3.medium` (SKB) | Staging will also run native XDP after c5n.2xlarge upgrade |

### Design Decisions Confirmed

| # | Topic | Decision |
|---|-------|----------|
| 1 | AZ map strategy | Rename `C5N_AZ_MAP` -> `RELAY_AZ_MAP`; same 3 AZ values apply to both c5n.2xlarge and c6in.8xlarge (c6in is available in these AZs) |
| 2 | AMI change is destructive | EC2 instance replacement on `pulumi up`; staging first, then production; maintenance window required per stack |
| 3 | ENA Express | Out of scope for this change; capture in new ADR-005 as deferred pending RTT profiling on live c6in.8xlarge stack |
| 4 | CI runners | `ubuntu-22.04` -> `ubuntu-24.04` across all 3 jobs in `build-release.yml`; `rust.yml` uses `ubuntu-latest` (already resolves to 24.04) - leave unchanged |
| 5 | Noble AMI path | Use `hvm-ssd-gp3` prefix: `ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-*` (Canonical switched Noble to gp3 path) |
| 6 | Staging XDP mode | `c5n.2xlarge` supports XDP native mode via ENA driver; staging now matches production XDP path |

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| `c5n.2xlarge` for staging | Same ENA driver family as c5n.xlarge; XDP native mode available; staging can now validate native XDP path | N/A |
| `c6in.8xlarge` for production | Higher network bandwidth ceiling than c5n.xlarge; same ENA driver; XDP native mode supported | N/A |
| Rename `C5N_AZ_MAP` -> `RELAY_AZ_MAP` | c6in.8xlarge is available in the same known-good AZs; a family-specific name is misleading once both instance types share the map | N/A |
| Fix AMI filter to Noble 24.04 | `relay_node.py` docstring claimed Ubuntu 24.04 but filter was Ubuntu 22.04 Jammy; target OS stated in repo doc must match actual AMI | N/A |
| ENA Express deferred to ADR-005 | No RTT profiling data yet on c6in.8xlarge; premature to enable a protocol-level change without a measured baseline | [ADR-005](../decisions/ADR-005-c6in-ena-express.md) |
| Update CI runners to ubuntu-24.04 | Target hosts run Ubuntu 24.04; building binaries on the same OS eliminates potential glibc version skew | N/A |

## Tests Added/Modified

No test code changes in this session. All changes are infrastructure config, docs, and CI runner updates.

| File | Change | Type | Status |
|------|--------|------|--------|
| `.github/workflows/build-release.yml` | Runner `ubuntu-22.04` -> `ubuntu-24.04` | CI | Planned |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `AMI_NAME_FILTER` in `config.py` references `ubuntu-jammy-22.04` but `relay_node.py` docstring says Ubuntu 24.04 | Fix `AMI_NAME_FILTER` to `hvm-ssd-gp3/ubuntu-noble-24.04-amd64-*`; rewrite block comment | No |
| `C5N_AZ_MAP` name is c5n-specific but will be used for c6in.8xlarge | Rename to `RELAY_AZ_MAP`; update all references in `config.py`, `network.py`, `infra/README.md` | No |
| AMI + instance type change is destructive (EC2 replacement on `pulumi up`) | Deploy staging first; verify XDP native on c5n.2xlarge; plan maintenance window before production | No |
| Noble AMI uses `hvm-ssd-gp3` path, not the old `hvm-ssd` path used for Jammy | Use `ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-*`; fallback to `hvm-ssd` if `pulumi preview` shows no AMI match in a region | No |

## Next Steps

1. **High:** Edit `infra/config.py` - fix `AMI_NAME_FILTER`, rename `C5N_AZ_MAP` -> `RELAY_AZ_MAP`, update all comments
2. **High:** Edit `infra/Pulumi.staging.yaml` - `relay_instance_type: t3.medium` -> `c5n.2xlarge`
3. **High:** Edit `infra/Pulumi.production.yaml` - `relay_instance_type: c5n.xlarge` -> `c6in.8xlarge`
4. **High:** Edit `infra/relay_node.py` - update module docstring and `instance_type` param example
5. **High:** Edit `infra/network.py` - update AZ comment (`C5N_AZ_MAP` -> `RELAY_AZ_MAP`)
6. **High:** Edit `infra/README.md` - Stack Config Reference table + Instance Type Rationale section
7. **High:** Edit `.github/workflows/build-release.yml` - `ubuntu-22.04` -> `ubuntu-24.04` (3 jobs)
8. **Medium:** Edit `docs/decisions/ADR-002` - Consequences/Neutral sentence: update instance type comparison
9. **Medium:** Edit `docs/decisions/ADR-003` - Consequences/Positive + Migration Plan: update c5n.xlarge/t3.medium refs
10. **Medium:** Edit `docs/decisions/ADR-004` - Context + Consequences: update instance type refs
11. **Medium:** Write `docs/decisions/ADR-005-c6in-ena-express.md` - new ADR capturing deferred ENA Express decision

## Files Changed

| Status | File |
|--------|------|
| A | `docs/sessions/2026-05-06-instance-types-ubuntu24-noble.md` |
| M (planned) | `infra/config.py` |
| M (planned) | `infra/Pulumi.staging.yaml` |
| M (planned) | `infra/Pulumi.production.yaml` |
| M (planned) | `infra/relay_node.py` |
| M (planned) | `infra/network.py` |
| M (planned) | `infra/README.md` |
| M (planned) | `.github/workflows/build-release.yml` |
| M (planned) | `docs/decisions/ADR-002-pulumi-infra-over-manual-inventory.md` |
| M (planned) | `docs/decisions/ADR-003-custom-kfunc-elf-loader.md` |
| M (planned) | `docs/decisions/ADR-004-e2e-deployed-test-flow.md` |
| A (planned) | `docs/decisions/ADR-005-c6in-ena-express.md` |

