# ADR-005: Defer ENA Express Enablement on c6in.8xlarge Pending RTT Baseline

**Date:** 2026-05-06<br>
**Status:** Deferred<br>
**Deciders:** developer<br>
**Related Tasks:** `infra/Pulumi.production.yaml` instance type upgrade<br>
**Related ADRs:** [ADR-002](ADR-002-pulumi-infra-over-manual-inventory.md)<br>
**Related Sessions:** `docs/sessions/2026-05-06-instance-types-ubuntu24-noble.md`<br>

## Context

Production relay nodes are being upgraded from `c5n.xlarge` to `c6in.8xlarge`
(see session `2026-05-06-instance-types-ubuntu24-noble.md`). The `c6in` instance
family supports ENA Express, a low-latency enhancement to the ENA driver that
reduces single-flow latency between instances in the same placement group via
AWS Scalable Reliable Datagram (SRD) transport.

ENA Express is distinct from XDP native mode:
- XDP native mode: packet processing at the ENA driver level, bypassing the
  kernel network stack. Already enabled and required by relay-xdp.
- ENA Express: AWS-level transport protocol between EC2 instances, reducing
  tail latency for single UDP flows within the same region/placement group.

ENA Express must be enabled per Elastic Network Interface via the AWS API or
console (`modify-network-interface-attribute --ena-srd-specification`). It is
not enabled by Pulumi's `aws.ec2.Instance` resource by default.

No RTT profiling data exists yet for the live `c6in.8xlarge` stack. Enabling
ENA Express is a protocol-level change that affects the network path between
relay nodes in the same region. Without a measured baseline on `c6in.8xlarge`,
the benefit cannot be quantified and any regression would be difficult to
attribute.

## Options Considered

### Option A: Enable ENA Express immediately at instance launch

- **Description:** Add `ena_srd_specification` to the Pulumi `aws.ec2.Instance`
  resource configuration to enable ENA Express on all relay node ENIs at
  creation time.
- **Pros:** Potential latency reduction from day one on c6in.8xlarge.
- **Cons:** No baseline RTT data to compare against; cannot quantify improvement
  or detect regression if ENA Express introduces unexpected behaviour.
- **Effort:** Impl: Low / Risk: Unknown without baseline

### Option B: Defer - establish RTT baseline first, then evaluate

- **Description:** Deploy `c6in.8xlarge` without ENA Express. Collect RTT and
  jitter measurements from the ping thread (`10 Hz UDP relay-to-relay`) over a
  sustained period. Then evaluate ENA Express enablement against that baseline.
- **Pros:** Data-driven decision; any change is measurable; no risk of
  unintributed regression on production traffic.
- **Cons:** ENA Express benefit is deferred; requires a second change window.
- **Effort:** Impl: Low (when ready) / Risk: Low

### Option C: Do not enable ENA Express

- **Description:** Accept XDP native mode on `c6in.8xlarge` without ENA Express.
  Inter-relay UDP uses the standard ENA path.
- **Pros:** No additional configuration or change risk.
- **Cons:** Leaves potential latency improvement unused if RTT profiling later
  shows a meaningful gain.
- **Effort:** None

## Decision

**Chosen: Option B - Defer ENA Express pending RTT baseline on live c6in.8xlarge**

ENA Express will not be configured in the initial `c6in.8xlarge` deployment.
The decision will be revisited once RTT/jitter baseline data is collected from
the ping thread (`10 Hz relay-to-relay`) on the live production stack.

## Rationale

- The `c6in.8xlarge` instance type upgrade is primarily for higher network
  bandwidth ceiling and continued XDP native mode support, not for ENA Express.
- ENA Express targets single-flow tail latency within a region. The relay-xdp
  workload spans 3 regions; ENA Express only benefits intra-region hops.
- Without a measured RTT baseline from the live stack, Option A is premature.
  A baseline requires at least one full production traffic cycle to be meaningful.
- Option C remains valid if baseline data shows negligible benefit; this ADR
  ensures the evaluation is not forgotten by capturing it explicitly.

## Consequences

- **Positive:** `c6in.8xlarge` instances launch with a clean, known configuration.
  Any future RTT improvement from ENA Express can be measured as a delta against
  the established baseline.
- **Negative:** ENA Express benefit is deferred. If RTT profiling is never
  performed, ENA Express is never evaluated.
- **Neutral:** XDP native mode is unaffected by this decision. All other
  `c6in.8xlarge` benefits (bandwidth, ENA driver version) are available
  from day one.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `infra/relay_node.py` | None | No `ena_srd_specification` field added at this time |
| `infra/Pulumi.production.yaml` | None | No ENA Express config added |
| Ping thread (`relay-xdp/src/ping.rs`) | Read-only | RTT/jitter stats from 10 Hz ping are the data source for the baseline |

## Revisit When

- At least 7 days of continuous production traffic have been logged on
  `c6in.8xlarge` and RTT/jitter baseline is established from ping thread stats.
- Both relay nodes in a region are confirmed to be in the same placement group
  (ENA Express requires same-region, same-placement-group for maximum benefit).
- AWS adds Pulumi `aws.ec2.Instance` native support for `ena_srd_specification`
  without requiring a separate `modify-network-interface-attribute` call
  (reduces deployment complexity).

