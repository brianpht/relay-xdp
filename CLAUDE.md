# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

UDP game relay processing packets at the NIC driver level via Linux XDP. Rust + eBPF + a small C kernel module that exposes SHA-256 and XChaCha20-Poly1305 as eBPF kfuncs.

## Workspace Layout

Cargo workspace (`resolver = "2"`) with `relay-xdp-ebpf` deliberately **excluded** because it targets `bpfel-unknown-none`:

- `relay-xdp-common/` - `#![no_std]`, `#[repr(C)]` shared types loaded into BPF maps. Compiled for both targets.
- `relay-xdp/` - userspace control plane binary + lib (1 Hz HTTP main thread, 10 Hz UDP ping thread).
- `relay-xdp-ebpf/` - eBPF data plane (`bpfel-unknown-none`, nightly + `rust-src`). **NOT a workspace member.**
- `relay-backend/` - axum + tokio route optimization service.
- `relay-sdk/` - rlib + cdylib + staticlib game client/server SDK; `build.rs` runs cbindgen.
- `module/` - C, GPL kernel module exposing 2 kfuncs.
- `xtask/` - build helper (`build-ebpf-rust`, `func-test`).
- `infra/` - Pulumi (Python) AWS provisioning.
- `ansible/` - bare-metal deployment playbooks.
- `tests/` - shared compose helpers and fixtures (per-crate tests live in each crate's `tests/`).

## Build, Test, Lint

```bash
cargo build --release                    # userspace workspace
cargo run -p xtask -- build-ebpf-rust    # eBPF program -> writes ./relay_xdp_rust.o (nightly toolchain pinned)
cd module && make                        # kernel module (requires kernel headers, kernel 6.5+)

cargo fmt --all -- --check               # CI: must pass
cargo clippy --workspace --lib --bins -- -D warnings   # CI: zero warnings
cargo test                               # unit + wire_compat + integration tests

cargo run -p xtask -- func-test          # functional parity tests; runs `cargo test --test func_parity -- --ignored --test-threads=1` with RELAY_NO_BPF=1. --test-threads=1 is required because env var mutations are not thread-safe.
cargo bench --no-run -p relay-sdk        # benchmark compile check (matches CI)

# Single-test invocations
cargo test -p relay-xdp --test wire_compat
cargo test -p relay-backend --test integration_xdp <test_name>

# Multi-process integration (RELAY_NO_BPF=1, real HTTP/UDP/Redis)
docker compose -f docker-compose.test.yml up --build -d
bash tests/compose-test.sh --no-build
docker compose -f docker-compose.test.yml down -v --remove-orphans
```

The eBPF crate has its own `target/` and `Cargo.lock` because it is outside the workspace. `cargo test` in the workspace root never touches it.

`xtask build-ebpf-rust` copies the linker output to `./relay_xdp_rust.o` at the repo root - this is the path `RELAY_XDP_OBJ` defaults to.

## Three-Plane Architecture

```
+----------------------------+      6 BPF maps (shared kernel memory)      +-----------------------------+
| relay-xdp (userspace)      | <==========================================> | relay-xdp-ebpf (kernel XDP) |
|  Main thread  - 1 Hz HTTP  |                                              |  per-packet, sub-microsecond|
|  Ping thread  - 10 Hz UDP  |                                              |  calls kfuncs in module.ko  |
+----------------------------+                                              +-----------------------------+
        | HTTP POST /relay_update (1 Hz)                                                 |
        v                                                                                v
+----------------------------+      GET /route_matrix      +-------------+         module/relay_module.ko
| relay-backend (axum)       | <-------------------------- | server_bknd |          (SHA-256 + XChaCha20)
|  RelayManager -> Optimize2 |                             +-------------+
|  Redis leader election     |
+----------------------------+
```

Two planes, strictly separated. They communicate **only** through 6 BPF maps:

| Map             | Type           | Writer                | Notes                              |
|-----------------|----------------|-----------------------|------------------------------------|
| `config_map`    | Array[1]       | Userspace (once)      | RelayConfig 88B                    |
| `state_map`     | Array[1]       | Userspace (1 Hz)      | RelayState 64B (timestamp, magic)  |
| `stats_map`     | PerCpuArray[1] | eBPF (per-packet)     | 150 u64 counters                   |
| `relay_map`     | HashMap[2048]  | Userspace (on change) | Known relay set                    |
| `session_map`   | LruHash[200K]  | eBPF + Userspace      | SessionKey -> SessionData          |
| `whitelist_map` | LruHash[200K]  | eBPF + Userspace      | WhitelistKey -> WhitelistValue     |

Schema and offsets: `docs/ARCHITECTURE.md` Section "BPF Map Schema". Struct definitions: `relay-xdp-common/src/lib.rs`. The `wire_compat` tests assert exact sizes and offsets.

Userspace IPC between Main and Ping threads uses `Arc<Mutex<VecDeque<T>>>` queues only - no channels. The BPF context is `Option<Arc<Mutex<BpfContext>>>` so `RELAY_NO_BPF=1` disables it cleanly for tests.

## Custom kfunc Loader (key non-obvious design)

Aya's `Ebpf::load_file()` + `Xdp::attach()` cannot load programs that call kernel-module kfuncs - bpf-linker emits those as `BPF_PSEUDO_CALL` with UNDEF-symbol relocations that `aya-obj::relocate_calls()` rejects. `relay-xdp/src/kfunc.rs` (~1300 lines) and `bpf.rs` implement an 11-step manual load path: ELF patching for kfuncs and BPF helpers, BTF resolution from the loaded `relay_module.ko`, raw `BPF_PROG_LOAD` and `BPF_LINK_CREATE` syscalls. Rationale and full step-by-step in `docs/decisions/ADR-003-custom-kfunc-elf-loader.md` and `docs/ARCHITECTURE.md` Section "kfunc Loader". Touch this code with care; changes typically require rebuilding all three layers (module, eBPF, userspace).

## Cross-Cutting Rules

These constraints span multiple crates and are not derivable from local context:

- **Wire types in `relay-xdp-common` MUST stay `#![no_std]`, `#[repr(C)]`, fixed-size primitives only.** No `String`/`Vec`/`Option`/pointers. Run `cargo test` after any struct change - `wire_compat` asserts byte-level layout.
- **eBPF crate constraints:** 512-byte stack, no heap, only `aya-ebpf` + `relay-xdp-common`, all loops bounded, all functions `#[inline(always)]`, all pointer access bounds-checked against `ctx.data_end()`.
- **kfunc calls in eBPF use `core::arch::asm!` with explicit `in("r1")..in("r4")` constraints**, not `extern "C"` - LLVM's BPF backend won't materialize argument registers for extern symbols and the verifier will reject. `verify_ping_token` and `verify_session_header` are `#[inline(never)]` to fit the 512-byte stack, so the loader must walk all `.text*` sections.
- **Kfunc signature changes require rebuilding all three layers:** `module/relay_module.c`, `extern` blocks in `relay-xdp-ebpf/src/main.rs`, and `Chacha20Poly1305Crypto` in `relay-xdp-common`.
- **Byte order:** network headers big-endian (`from_be()`/`to_be()`); relay payload little-endian (byte-level reads).
- **DDoS filter (pittle/chonkle) is implemented in three places** - `relay-xdp-ebpf` (eBPF), `relay-xdp/src/packet_filter.rs` (userspace), `relay-sdk/src/route/mod.rs` (SDK). All three MUST produce identical output.
- **Packet processing order is fixed (NEVER reorder):** parse -> size check -> DDoS filter -> whitelist -> session lookup -> crypto -> forward. Cheapest rejection first; no map lookups or crypto before the DDoS filter.
- **XDP action cost:** `XDP_DROP` (cheapest) -> `XDP_TX` (reflect/forward) -> `XDP_PASS` (kernel stack, expensive). Minimize `XDP_PASS`.
- **Userspace is pure Rust, no C deps.** Crypto via `sha2`, `crypto_box`, `x25519-dalek`, `blake2`, `getrandom`. Errors are `anyhow::Result`; no `unwrap()` on production paths. Config is read once at startup from env vars (`config.rs`).
- **Encoding:** userspace `encoding::Writer`/`Reader` is little-endian and must match wire format byte-for-byte. `relay-backend` has two encoders - "Simple LE" for relay update packets, "Bitpacked" for cost/route matrices.

## Style and Process

- **No em-dashes (-), no emojis** in code, comments, docs, or markdown. Use ` - ` and ASCII symbols only.
- **Diagrams must be Mermaid** (flowchart/sequenceDiagram/stateDiagram). ASCII art is prohibited for non-trivial diagrams.
- **Architectural source of truth:** `docs/decisions/` (ADRs). Do NOT treat anything in `docs/sessions/` as implementation rules - those are working notes.
- **CI gates:** `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, `cargo xtask func-test`, `cargo bench --no-run -p relay-sdk`, and the docker-compose integration suite must all pass.
- **Git:** local commits and local tags are fine; do not push commits, tags, or any refs to a remote.

## Reference Docs

- `docs/ARCHITECTURE.md` - system diagram, crate breakdown, BPF map schema, packet handlers, kfunc loader steps.
- `docs/PERFORMANCE_DESIGN.md` - per-packet budgets, design principles.
- `docs/decisions/` - ADRs (architectural source of truth).
- `relay-backend/ARCHITECTURE.md` - route optimization, wire format, encoding, relay-xdp interaction protocol.
- `relay-sdk/ARCHITECTURE.md` - SDK module map, FFI contract, wire compat test vectors.
- `.github/copilot-instructions.md` - the same rules in machine-parseable form.