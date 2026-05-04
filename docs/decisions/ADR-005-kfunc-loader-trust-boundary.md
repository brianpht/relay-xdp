# ADR-005: kfunc Loader Trust Boundary

**Date:** 2026-05-04<br>
**Status:** Proposed<br>
**Deciders:** developer<br>
**Related Tasks:** Phase 1 action P1-07 (audit v2)<br>
**Related ADRs:** [ADR-003](ADR-003-custom-kfunc-elf-loader.md)<br>
**Related Sessions:** [Session 2026-05-04 v2](../sessions/2026-05-04-project-audit-plan-v2.md)<br>

## Context

[ADR-003](ADR-003-custom-kfunc-elf-loader.md) established `relay-xdp/src/kfunc.rs` (~1300 lines) as the in-tree replacement for the parts of Aya that cannot load module kfuncs. The audit v2 pass found 27 `.unwrap()` / `.expect()` call sites in `kfunc.rs` that operate on byte-level ELF and BTF input. Their inputs come from two sources:

1. **`relay_xdp_rust.o`** - the compiled eBPF object on disk, produced by our own `xtask build-ebpf-rust` and shipped alongside the userspace binary.
2. **`relay_module.ko` BTF** - read out of the running kernel via `BPF_BTF_GET_NEXT_ID` enumeration after the module has been loaded by the operator (typically via the `relay-module` Ansible role).

A malformed or attacker-controlled input on either side panics the userspace process. The audit raised this as Critical, but the **right fix depends on the threat model**, not on the panic count. Specifically:

- If `relay_module.ko` can be replaced on disk by a non-root attacker, the attacker already has kernel module load privilege - userspace integrity checks add nothing because the kernel will load whatever module it is given.
- If `relay_xdp_rust.o` can be replaced on disk by a non-root attacker, the attacker can already inject arbitrary eBPF that the verifier alone defends against - again, userspace integrity checks add nothing.
- The only realistic non-attacker failure modes are: (a) bit-rot, (b) version skew between userspace and the eBPF object / module after a partial deploy, (c) `bpf-linker` output format change. All three are operational issues that should surface as readable startup errors, not panics.

Consequences of inaction:

- A partially-deployed update (new userspace, old `relay_xdp_rust.o`) crashes with a `.expect()` panic and a backtrace that does not name the contract violation. Operators must read the source to debug.
- A future audit will keep flagging the `.expect()` count as Critical without an architectural answer for what the contract should be. The decision needs to be written down once.
- Without a stated trust boundary, a future contributor may add a "harmless" userspace signature check that creates an illusion of defense-in-depth while consuming review bandwidth.

## Options Considered

### Option A: Trusted-input contract; convert panics to typed errors

- **Description:** Document that `relay_xdp_rust.o` and `relay_module.ko` (and its BTF) are part of the same trust domain as the userspace binary itself. Any attacker who can replace those files already has kernel-load privilege; userspace will not attempt to verify their authenticity. Replace every `.expect()` / `.unwrap()` in `kfunc.rs` with a typed `KfuncLoadError` enum that names the failing step (e.g. `KfuncLoadError::ElfMagicMismatch`, `KfuncLoadError::BtfTypeIdNotFound { name: &'static str }`). Bubble up to a single startup error path.
- **Pros:** Operationally clear (panics become readable startup errors). Honest about the threat model. Minimal code change - the existing 11-step pipeline is unchanged, only the error type is refactored. Future audits get a single concrete answer instead of recurring "unwrap count" findings.
- **Cons:** Requires touching every `.expect()` site. The error enum will accumulate variants over time; needs a discipline of "one variant per failure mode, not one per call site".
- **Effort:** Impl: medium (mechanical) / Migration: none / Maintenance: low

### Option B: In-userspace signature verification of `relay_xdp_rust.o` and the kernel module

- **Description:** Sign both artefacts at build time with a vendor key. `kfunc.rs` verifies the signature before parsing.
- **Pros:** Detects on-disk tampering by an attacker without root.
- **Cons:** **The threat model already fails before this defense activates.** `relay_module.ko` is loaded by `insmod` / `modprobe`, which requires `CAP_SYS_MODULE`; an attacker with that capability does not need to tamper with files. `relay_xdp_rust.o` is loaded by a userspace process running as root with `CAP_BPF`; tampering with the file on disk is no easier than tampering with the running binary. Adds a key management burden (vendor key rotation, signature embedding, build pipeline change) for a defense that does not gate access to anything an attacker would not already have.
- **Effort:** Impl: high / Migration: medium / Maintenance: high

### Option C: Run the loader in a sandboxed sub-process; isolate panics

- **Description:** Fork a worker process for the load pipeline; main process treats a worker crash as a startup error.
- **Pros:** Panics no longer crash the long-lived process.
- **Cons:** The loader runs **once at startup**, before XDP attach. There is no long-lived process to protect - if the loader panics, the binary cannot start, which is exactly what we want when the input is malformed. Adds IPC and lifecycle complexity for no reliability gain. Also harder to debug than Option A's typed errors.
- **Effort:** Impl: high / Migration: medium / Maintenance: medium

### Option D: Do nothing

- **Description:** Keep `.expect()` panics; document the trust boundary in code comments only.
- **Pros:** Zero work.
- **Cons:** Operational ambiguity persists; ops debugging continues to require source reads. Audit will flag this every cycle.
- **Effort:** none

## Decision

**Chosen: Option A - Trusted-input contract; convert panics to typed errors**

## Rationale

Option B is the most tempting because "verify before use" is a security reflex, but its threat model does not survive scrutiny: the privilege required to tamper with the inputs (kernel module load capability or root + write access to `/usr/local/bin`) is the same privilege the attacker would otherwise need to bypass any userspace check. Adding a verification step in front of a privilege the attacker already has is security theatre, and it imposes ongoing key-management cost.

Option C solves a problem we do not have. The loader runs once, at startup, before XDP attach. If it panics, the daemon does not start - which is the right behaviour for a malformed input. There is no in-flight work to protect from a crash.

Option D leaves the operational ambiguity that motivated the audit finding in the first place.

Option A is honest about what userspace can and cannot defend, and it converts the actual operational concern (readable diagnostics for partial deploys, bit-rot, `bpf-linker` format drift) into the right shape: typed errors that name the failing contract.

The deciding factor: the threat model question is binary - either userspace can defend the inputs or it cannot. ADR-003 already established that the kernel verifier is the load-time defense for the eBPF object, and the kernel module loader is the load-time defense for the module. Userspace adds nothing on top. Once that is written down, the remaining work is purely operational diagnostics, and Option A is the simplest answer.

## Consequences

- **Positive:** Startup failures produce actionable error messages naming the failing step (`KfuncLoadError::BtfTypeIdNotFound { name: "bpf_relay_sha256" }`) instead of `.expect("kfunc not found")` panics with no context. Future audits stop flagging the `.expect()` count - the answer is "by design, with typed error reporting". The trust boundary is documented in one place (this ADR), not re-derived from code on every review.
- **Negative:** ~27 `.expect()` sites need to be rewritten and cross-checked against the error enum. The error enum becomes a small contract that future kfunc.rs changes must extend rather than panic.
- **Neutral:** No runtime behaviour change for the happy path - all of these sites are panic-or-success today, and they remain error-or-success after the change. The verifier and BPF syscall paths are untouched.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-xdp/src/kfunc.rs` | Modified | New `KfuncLoadError` enum; every `.expect()` / `.unwrap()` returns `Result<_, KfuncLoadError>` |
| `relay-xdp/src/bpf.rs` | Modified | Surface `KfuncLoadError` at the single startup error site; stringify into `anyhow::Error` |
| `relay-xdp/src/main.rs` | None | The startup error path already prints the `anyhow::Error` chain |
| `docs/ARCHITECTURE.md` | Updated | Add a "Trust boundary" subsection to the kfunc loader chapter pointing here |
| Tests | Optional | Targeted unit tests for `KfuncLoadError` variants (parse a deliberately corrupted byte slice; assert specific variant) |

## Revisit When

- A realistic threat model emerges in which an attacker can tamper with `relay_xdp_rust.o` or `relay_module.ko` **without** already having kernel-load or root-write privilege. Examples: shipping the eBPF object via a download path that runs as a non-privileged service account; or supporting unattended module updates from an untrusted source. At that point Option B may be warranted, with full key-management cost.
- `bpf-linker` changes its output in a way that makes the parser's input shape less predictable (this revisits ADR-003 too) - a more defensive parser may be needed regardless of trust boundary.
- The `kfunc.rs` error enum grows past `~15` variants - that suggests the parser is doing too much in one module and should be split.

## Migration Plan

1. Define `KfuncLoadError` (enum, `#[derive(Debug, thiserror::Error)]` if `thiserror` already in deps; otherwise hand-rolled `Display` impl).
2. Convert `.expect()` / `.unwrap()` sites in dependency order: ELF magic / header parse first, then section walk, then relocation patch, then BTF parse, then syscall result handling.
3. After each batch, run `cargo run -p xtask -- build-ebpf-rust` and the existing `kfunc.rs` unit tests to confirm no behavioural change on the happy path.
4. Add 2-3 negative-path unit tests (corrupted ELF magic; missing section; truncated BTF) that assert the expected `KfuncLoadError` variant.
5. Update `docs/ARCHITECTURE.md` with the trust-boundary subsection.
6. No production rollout concerns - the change is internal to startup.