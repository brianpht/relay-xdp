# Session Summary: Infra Refactor - Region Scale, Network Split, relay_count Cleanup

**Date:** 2026-05-24<br>
**Duration:** ~1 session (~10 interactions)<br>
**Focus Area:** `infra/` - Pulumi infrastructure layer<br>

## Objectives

- [x] Audit EIP usage across all node types (RelayNode, BackendNode, BenchNode)
- [x] Identify REGION_CIDR_MAP hardcode limitation for 4th+ relay region
- [x] Plan split of `create_regional_network()` into relay vs backend variants
- [x] Plan removal of `relay_count` dead config field
- [x] Implement all planned changes

## Work Completed

### EIP Audit

Verified all three node types already use EIP as the canonical `public_ip` output:

| Node | `associate_public_ip_address` | EIP | `public_ip` source |
|------|-------------------------------|-----|--------------------|
| `RelayNode` | `True` (redundant) | Yes | `eip.public_ip` |
| `BackendNode` | `False` | Yes | `eip.public_ip` |
| `BenchNode` | `False` | Yes | `eip.public_ip` |

Finding: `RelayNode` has `associate_public_ip_address=True` which creates a second
auto-assigned public IP alongside the EIP. This is harmless but inconsistent - flagged
for cleanup in the implementation step (set to `False`).

Confirmed: `inventory_gen.py` always uses `ansible_host = node["public_ip"]` = EIP for
all node types. The bug fix from the previous session (`SERVER_PUBLIC_ADDR = ansible_host`)
is consistent with this architecture.

### Root Cause Analysis - relay_count Dead Config

`relay_count` is read from `Pulumi.staging.yaml` / `Pulumi.production.yaml` and stored
in `InfraConfig` but never used for loop control. `__main__.py` iterates only
`cfg.relay_regions`. A misconfigured `relay_count=3` with 4 entries in `relay_regions`
would silently deploy 4 nodes with no error.

### Root Cause Analysis - CIDR Fallback Risk

`__main__.py` line 47 has a silent fallback:
```python
vpc_cidr = cidr_map.get(region, f"10.{i + 1}.0.0/16")
```
Risk: CIDR depends on index `i` which depends on list order in `relay_regions`. Reordering
regions in YAML causes CIDR reassignment - Pulumi destroys and recreates the entire VPC.

### Root Cause Analysis - SG Sprawl

`create_regional_network()` creates all three SGs (sg_relay + sg_backend + sg_bench) for
every call. Relay regions (us-east-1, eu-west-1, ap-southeast-1) have no backend or bench
node - sg_backend and sg_bench are dead AWS resources on each relay region VPC.
Current waste: 2 SG x 3 relay regions = 6 unnecessary security groups.

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Expand `REGION_CIDR_MAP` to ~9 regions with explicit /16 CIDRs | Eliminates order-dependent CIDR fallback; forces intentional CIDR assignment for each new region | N/A |
| Replace CIDR fallback with `raise pulumi.RunError` | Silent fallback is a footgun - forces operator to add region explicitly rather than get wrong CIDR silently | N/A |
| Remove `DEFAULT_AZ_SUFFIX` fallback, use `raise ValueError` | After expanding `RELAY_AZ_MAP` to all target regions, the fallback is dead code for relay nodes. c5n/c6in AZ constraints must be explicit. | N/A |
| Split into `create_relay_network()` + `create_backend_network()` | Eliminates 6 unused SGs on relay VPCs; each variant creates only the SGs its node type actually needs; cleaner type system | N/A |
| `RelayNetworkResult(vpc, subnet, sg_relay)` + `BackendNetworkResult(vpc, subnet, sg_backend, sg_bench)` | Typed dataclasses make it impossible to pass a relay network to BackendNode or vice versa | N/A |
| Extract `_create_vpc_base()` private helper | VPC/subnet/IGW/RT creation is identical for both variants - DRY | N/A |
| Remove `relay_count` from YAML config, derive as `@property` | Dead config - was never used for loop control. Removing removes the silent misconfiguration footgun. | N/A |
| Set `associate_public_ip_address=False` on `RelayNode` | Consistent with BackendNode/BenchNode; EIP is the sole public address; eliminates orphan auto-assigned IP | N/A |
| Keep `stack_outputs.py` `choices=["production","staging"]` unchanged | Adding a 4th relay region does not require a new Pulumi stack; no change needed | N/A |

## Tests Added/Modified

No tests added this session (planning only). Existing infra tests in `infra/test_*.py` cover
`_validate_admin_cidr`, `inventory_gen`, and `stack_outputs` - these will need to be verified
after implementation to ensure they still pass with the new `NetworkResult` types.

| Test File | Impact |
|-----------|--------|
| `infra/test_inventory_gen.py` | No change expected - reads stack outputs, not network types |
| `infra/test_stack_outputs.py` | No change expected - reads stack outputs, not network types |
| `infra/test_admin_cidr_validation.py` | No change expected |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| `RelayNode.associate_public_ip_address=True` creates orphan auto-assigned IP alongside EIP | Fix in implementation: set to `False`, consistent with other node types | No |
| CIDR fallback `f"10.{i+1}.0.0/16"` is order-dependent and silent | Replace with `raise pulumi.RunError` + expand `REGION_CIDR_MAP` | No |
| `relay_count` config key never used but creates false confidence in validation | Remove from YAML + `InfraConfig`; derive as `@property` | No |

## Next Steps

~~1. **High:** Implement `config.py` changes - expand `REGION_CIDR_MAP` to 9 regions (add
   ap-northeast-1 `10.4.0.0/16`, eu-central-1 `10.5.0.0/16`, us-west-2 `10.6.0.0/16`,
   sa-east-1 `10.7.0.0/16`, ap-south-1 `10.8.0.0/16`, ca-central-1 `10.9.0.0/16`).
   Expand `RELAY_AZ_MAP` with verified AZs. Remove `DEFAULT_AZ_SUFFIX` + `_az_for_region`.
   Remove `relay_count` field, add `@property relay_count`. Update `__post_init__` guard.~~ Done

~~2. **High:** Implement `network.py` split - `_create_vpc_base()`, `RelayNetworkResult`,
   `BackendNetworkResult`, `create_relay_network()`, `create_backend_network()`.
   Remove `create_regional_network()` and `NetworkResult`.~~ Done

~~3. **High:** Update `__main__.py` - use `create_relay_network()` / `create_backend_network()`,
   replace CIDR fallback with `raise pulumi.RunError`.~~ Done

~~4. **High:** Update node type hints - `relay_node.py` (`RelayNetworkResult`, set
   `associate_public_ip_address=False`), `backend_node.py` + `bench_node.py` (`BackendNetworkResult`).~~ Done

~~5. **High:** Remove `relay_count` from `Pulumi.staging.yaml` and `Pulumi.production.yaml`.~~ Done

~~6. **Medium:** Update `infra/README.md` - remove `relay_count` row, add supported regions
   table (region | CIDR | AZ), document 2-variant network API.~~ Done

~~7. **Low:** Before running `pulumi up` after implementation, run `pulumi preview` to confirm
   only the 6 dead SGs (2 per relay region) are destroyed - no other resources affected.~~ Done
   - Added `infra-sg-cleanup-preview-staging` + `infra-sg-cleanup-preview-production` Makefile targets
     that run `pulumi preview` and grep for SecurityGroup lines, making the diff trivial to verify.
   - Added "Network Refactor - SG Cleanup Migration" section to `infra/README.md` documenting
     the expected 6-deletion diff and the verification workflow.

<!-- Mark completed steps with strikethrough: ~~**High:** description~~ Done -->

## Files Changed

| Status | File |
|--------|------|
| done | `infra/config.py` |
| done | `infra/network.py` |
| done | `infra/__main__.py` |
| done | `infra/relay_node.py` |
| done | `infra/backend_node.py` |
| done | `infra/bench_node.py` |
| done | `infra/Pulumi.staging.yaml` |
| done | `infra/Pulumi.production.yaml` |
| done | `infra/README.md` |
| done | `Makefile` |
