# ADR-003: Custom kfunc ELF Loader Instead of Forking Aya

**Date:** 2026-05-02<br>
**Status:** Accepted<br>
**Deciders:** developer<br>
**Related Tasks:** -<br>
**Related ADRs:** [ADR-001](ADR-001-compose-nobpf.md)<br>
**Related Sessions:** -<br>

## Context

`relay-xdp-ebpf` calls two kernel module kfuncs (`bpf_relay_sha256`,
`bpf_relay_xchacha20poly1305_decrypt`) exported by `relay_module.ko`.
It also calls two standard BPF helpers (`bpf_xdp_adjust_head`,
`bpf_xdp_adjust_tail`).

`bpf-linker` emits all four of these as `BPF_PSEUDO_CALL` (src_reg=1, imm=-1)
with `R_BPF_64_32` ELF relocations against UNDEF (section=0) symbols. Aya's
standard load path has two hard failures against this output:

1. `aya-obj::relocate_calls()` filters UNDEF-symbol relocations. It then falls
   through to a pc-relative callee lookup that computes
   `callee_address = instruction_offset` (a self-reference not in
   `obj.functions`), and fails with `UnknownFunction` for every kfunc and BPF
   helper call in the program.

2. Aya has no concept of `fd_array` in `BPF_PROG_LOAD`. Module kfuncs require
   the kernel verifier to resolve BTF type IDs from a module BTF object passed
   via `bpf_attr.fd_array`. Without this, `BPF_PROG_LOAD` fails because the
   kfunc type IDs reference the module's BTF namespace, not vmlinux.

Additionally, `relay-xdp-ebpf` uses inline asm `core::arch::asm!` for kfunc
calls to work around an LLVM eBPF backend bug that does not materialize r1-r4
argument registers for extern calls declared the normal way.

The consequence of inaction: the relay binary cannot load the XDP program at
all when `relay_module.ko` is loaded and kfuncs are required.

## Options Considered

### Option A: Patch / fork aya-obj and aya

- **Description:** Modify `aya-obj::relocate_calls()` to handle UNDEF-symbol
  `R_BPF_64_32` entries as kfunc or helper calls. Modify `aya::Ebpf::load`
  to accept an `fd_array` for module BTF. Publish a fork or upstream the
  patches.
- **Pros:** Uses the Aya abstraction layer; future upstream improvements apply
  automatically.
- **Cons:** Aya is under active development; the patch surface is large and
  the diff is non-trivial. Each Aya version bump risks divergence. Upstreaming
  requires community review bandwidth. Maintenance: high.
- **Effort:** Impl: high / Migration: medium / Maintenance: high

### Option B: Custom ELF patcher + raw BPF syscalls in-tree (kfunc.rs)

- **Description:** Keep Aya only for map creation and map FD access (what it
  does well). Implement a standalone `kfunc.rs` module that:
  1. Patches kfunc call sites (src_reg 1->2, encode kfunc index in imm).
  2. Patches BPF helper calls (src_reg 1->0, imm -> kernel helper ID).
  3. Patches map FD values directly into `BPF_LD_IMM64` instructions in the
     ELF, bypassing `relocate_maps()`.
  4. Calls `aya_obj::relocate_calls()` on the patched ELF (kfunc stubs are
     skipped because src_reg=2).
  5. Enumerates loaded BTF objects via `BPF_BTF_GET_NEXT_ID` to find
     `relay_module` BTF.
  6. Parses split BTF (module local types + vmlinux base offsets) to compute
     global kfunc type IDs.
  7. Patches kfunc instructions with final `imm=btf_type_id`,
     `off=fd_array_idx`.
  8. Calls `BPF_PROG_LOAD` with `fd_array=[0, module_btf_fd]` via raw
     `libc::syscall`.
  9. Calls `BPF_LINK_CREATE` with native XDP, fallback to SKB mode on
     `EOPNOTSUPP`/`EINVAL`.
- **Pros:** Zero Aya fork. Self-contained, auditable, fully tested in-tree
  (unit tests in `kfunc.rs`, integration via `relay_xdp_rust.o`). Pinned
  to our exact requirements - no churn from unrelated Aya changes. The raw
  syscall interface is stable (Linux BPF ABI is append-only).
- **Cons:** ~1309 lines of low-level ELF + BTF + syscall code to own and
  maintain. Must be updated if `bpf-linker` changes its relocation output.
- **Effort:** Impl: high (one-time) / Migration: none / Maintenance: low

### Option C: Replace bpf-linker with LLVM / clang-based toolchain

- **Description:** Compile `relay-xdp-ebpf` with Clang instead of
  `bpf-linker`. Clang emits kfunc calls and BPF helpers in the
  standard way that Aya can handle.
- **Pros:** Avoids ELF patching entirely.
- **Cons:** Lose Rust eBPF source. The entire `relay-xdp-ebpf` codebase is
  Rust; rewriting to C is prohibitive. Clang-for-Rust eBPF is not a
  supported workflow.
- **Effort:** Impl: prohibitive / Migration: prohibitive / Maintenance: high

## Decision

**Chosen: Option B - Custom ELF patcher + raw BPF syscalls in-tree**

## Rationale

Option A requires forking a dependency and maintaining a diff against an
active upstream. Option C is non-viable (requires rewriting eBPF in C). Option
B has the highest one-time implementation cost but zero ongoing fork surface,
zero Aya version coupling for the load path, and a narrow, well-defined scope:
ELF relocation patching and BPF syscall invocation, both of which use stable
Linux kernel ABIs.

The critical deciding factor: the Linux BPF `bpf_attr` structures are
append-only (old fields never change meaning). The `R_BPF_64_32` relocation
format and BTF binary format are similarly stable. This makes maintenance risk
low once the implementation is correct and tested.

The 256 KB verifier log buffer in `raw_load_xdp` ensures that any future
verifier rejections produce actionable diagnostics, reducing the risk of silent
failures.

## Consequences

- **Positive:** No Aya fork to maintain. Load path is fully auditable in-tree.
  Native + SKB XDP mode auto-fallback works correctly for both production
  (native, c5n.xlarge) and staging (SKB, t3.medium) instances. Unit tests
  exercise the ELF patching logic against the real `relay_xdp_rust.o` object.
- **Negative:** ~1309 lines of low-level syscall code to own. Must be revisited
  if `bpf-linker` changes its UNDEF relocation strategy or if the BPF ELF
  format changes (unlikely - both are de-facto stable).
- **Neutral:** Aya is still used for map creation, map FD management, and
  userspace map access. Only the program load + attach path is bypassed.
  Relationship with Aya is partial, not eliminated.

## Affected Components

| Component            | Impact   | Description                                                                    |
|----------------------|----------|--------------------------------------------------------------------------------|
| `relay-xdp/bpf.rs`   | Modified | Orchestrates kfunc.rs 11-step load; owns BpfContext struct + map accessors    |
| `relay-xdp/kfunc.rs` | New      | All ELF patching functions + BPF syscall wrappers + BTF parser                |
| `relay-xdp-ebpf`     | None     | eBPF source unchanged; inline asm kfunc wrappers remain as-is                 |
| `module/`            | None     | Kfunc signatures and BTF_SET8 registration unchanged                          |
| `docs/ARCHITECTURE.md` | Updated | BPF loader section rewritten to reflect 11-step flow; kfunc.rs added          |

## Revisit When

- `bpf-linker` changes its relocation output format for kfunc or helper calls
  (watch for LLVM eBPF backend updates that affect `R_BPF_64_32` emission).
- Aya adds first-class `fd_array` support and module kfunc loading
  (`aya::Ebpf::load_with_fd_array` or equivalent) - Option A may become viable
  with low maintenance cost at that point.
- Kernel BPF ABI breaks compatibility (extremely unlikely; BPF ABI is
  guaranteed stable by the kernel community).

## Migration Plan

1. `kfunc.rs` implemented and unit-tested (complete 2026-05-01).
2. `bpf.rs` updated to call `kfunc.rs` instead of `Ebpf::load_file` +
   `Xdp::attach` (complete 2026-05-01).
3. Staging deploy (t3.medium, SKB mode) validated via Ansible (complete
   2026-05-02: all 3 staging nodes, kfunc matched 2/2).
4. Architecture documentation updated (this ADR + ARCHITECTURE.md update,
   2026-05-02).
5. Production deploy to follow using same Ansible playbook, native XDP mode
   expected on c5n.xlarge (ENA driver supports native XDP).

