# Copilot Instructions

> Format: machine-parseable directives. Not for human reading.

## Project

UDP game relay, XDP packet processing at NIC driver level. Rust + eBPF + C kernel module.

## Workspace

### Core Data Plane

- `relay-xdp/` - Rust, x86_64, userspace control plane (main binary)
- `relay-xdp-common/` - Rust, `#![no_std]`, shared types (both targets)
- `relay-xdp-ebpf/` - Rust, `bpfel-unknown-none`, eBPF data plane (**NOT a workspace member** - separate Cargo target)
- `module/` - C, Linux kernel module (SHA-256 + XChaCha20-Poly1305 kfuncs)

### Control & Optimization

- `relay-backend/` - Rust, x86_64, route optimization backend (tokio + axum, HTTP endpoint for relay updates)
- `relay-sdk/` - Rust + C FFI bindings, game server SDK (cbindgen exports `relay_sdk.h` for C/C++)

### Build & Deployment

- `xtask/` - Rust, x86_64, build helper (targets: `build-ebpf-rust`, `func-test`)
- `infra/` - Pulumi Python, AWS infrastructure provisioning (EC2, VPC, security groups)
- `ansible/` - Bare-metal deployment (systemd units, binaries, kernel module, secrets management)
- `tests/` - Integration tests (docker-compose, functional parity with/without eBPF)

## Threading Model

- Main Thread: 1 Hz HTTP update, BPF map management, session timeouts
- Ping Thread: 10 Hz UDP relay-to-relay ping/pong, RTT/jitter/loss
- IPC: `Arc<Mutex<VecDeque<T>>>` queues only. No channels.
- BPF context: `Option<Arc<Mutex<BpfContext>>>` (supports `RELAY_NO_BPF=1`)

## BPF Maps (only IPC between userspace ↔ eBPF)

| Map | Type | Key → Value | Writer |
|-----|------|-------------|--------|
| `config_map` | Array\[1\] | u32 → RelayConfig (88B) | Userspace (once) |
| `state_map` | Array\[1\] | u32 → RelayState (64B) | Userspace (1 Hz) |
| `stats_map` | PerCpuArray\[1\] | u32 → RelayStats (1200B) | eBPF (per-pkt) |
| `relay_map` | HashMap\[2048\] | u64 → u64 | Userspace (on change) |
| `session_map` | LruHash\[200K\] | SessionKey → SessionData | eBPF + Userspace |
| `whitelist_map` | LruHash\[200K\] | WhitelistKey → WhitelistValue | eBPF + Userspace |

Struct definitions: `relay-xdp-common/src/lib.rs`.
Field layouts + byte offsets: [`docs/architecture.md` § BPF Map Schema](../docs/ARCHITECTURE.md#bpf-map-schema).

## Rules: `relay-xdp-common`

- MUST stay `#![no_std]` - no std, no alloc, no heap
- MUST use `#[repr(C)]` on all structs - binary layout shared with eBPF
- MUST use fixed-size primitives only (u8-u64, fixed arrays). NEVER String, Vec, Option, pointers
- MUST feature-gate userspace deps - `user` feature enables aya derives
- MUST run `cargo test` after any struct change (wire_compat tests verify sizes + offsets)

## Rules: `relay-xdp-ebpf`

- NEVER add to workspace members (separate target: `bpfel-unknown-none`)
- Stack limit: **512 bytes**. No heap. No alloc.
- ONLY external crates: `aya-ebpf`, `relay-xdp-common`
- ALL loops: bounded (verifier must prove termination). No iterators, no recursion.
- ALL functions: `#[inline(always)]`
- ALL pointer access: bounds-check against `ctx.data_end()` before every dereference
- Crypto: kfuncs only (`bpf_relay_sha256`, `bpf_relay_xchacha20poly1305_decrypt`). Signatures in `relay-xdp-ebpf/src/main.rs` extern block.
- Byte order: network headers = big-endian (`from_be()`/`to_be()`), relay payload = little-endian (byte-level reads)
- XDP actions by cost: XDP_DROP (cheapest) → XDP_TX (reflect) → XDP_PASS (kernel stack, expensive - minimize)
- Build: `cargo xtask build-ebpf-rust` (nightly required)

## Rules: `module/` (C kernel module)

- Pure C, GPL. Uses kernel crypto API (crypto_shash, chacha20_crypt + poly1305)
- Kfuncs: `__bpf_kfunc` + `BTF_SET8`. Requires kernel 6.5+
- NEVER change kfunc signatures without updating BOTH `extern "C"` in ebpf AND `Chacha20Poly1305Crypto` in common
- Kfunc change → rebuild all three: module → eBPF → userspace

## Rules: Cross-Cutting

- DDoS filter (pittle/chonkle): implemented in BOTH eBPF AND userspace (`packet_filter.rs`). MUST produce identical output. Change one → change both.
- 14 packet types (1-14) in relay-xdp-common. Full table: [`docs/architecture.md` § Packet Handlers](../docs/ARCHITECTURE.md#packet-handlers)
- Processing order (NEVER reorder): parse → size check → DDoS filter → whitelist → session lookup → crypto → forward
- NEVER add map lookups or crypto before DDoS filter
- NEVER use em-dashes (—) or emojis in code comments, docs, or markdown. Use ` - ` instead and ASCII symbols only.
- ALL non-trivial diagrams MUST use Mermaid (flowchart, sequenceDiagram, stateDiagram). ASCII art is prohibited.
- ONLY treat /docs/decisions as architectural source of truth.
- NEVER use or reference files in /docs/sessions as implementation rules.
- CI checks: Agent MUST ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass locally with zero errors and zero warnings before committing. Commits with failing checks are forbidden.
- Git operations: Agent MAY create local commits and local tags. MUST NOT push commits, tags, or any refs to any remote repository. All changes MUST remain local.

## Conventions: Rust Userspace

- Pure Rust, no C deps. Crypto: sha2, crypto_box, x25519-dalek, blake2, getrandom
- Errors: `anyhow::Result`. NEVER `unwrap()` in production paths.
- Config: env vars in `config.rs`, read once at startup
- Wire encoding: `encoding::Writer`/`Reader` (little-endian). Must match wire format byte-for-byte.
- BPF map access: Aya typed API only

## Conventions: Rust eBPF

- `unsafe` expected - document safety invariants when non-obvious
- All helpers: small, `#[inline(always)]`
- Handler pattern: parse → validate → map lookup → crypto verify → rewrite headers → XDP action
- All events tracked via `increment_counter`/`add_counter` through stats_map

## Conventions: C Module

- Linux kernel coding style (tabs, K&R braces)
- Minimal scope - only crypto eBPF cannot do itself
- Self-test in `module_init`

## Build Commands

```
cargo build --release                  # userspace
cargo run -p xtask -- build-ebpf-rust  # eBPF (nightly)
cd module && make                      # kernel module
cargo test                             # unit + wire_compat
cargo run -p xtask -- func-test        # functional parity (RELAY_NO_BPF=1)
```

## Dependency Chain

```
relay-xdp-common → relay-xdp (userspace)
relay-xdp-common → relay-xdp-ebpf (eBPF) ← loads via Aya ← relay-xdp
relay-xdp-ebpf → relay_module.ko (C) via kfuncs
relay-xdp ↔ relay-backend (HTTP POST /relay_update, 1 Hz)
relay-backend ← server_backend (GET /route_matrix)
```

Change shared types or kfunc signatures → trace + rebuild across all layers.

## Reference Docs

- Struct layouts, data flows, crypto stack: [`docs/architecture.md`](../docs/ARCHITECTURE.md)
- Performance principles, targets, budgets: [`docs/performance_design.md`](../docs/PERFORMANCE_DESIGN.md)
- Relay backend architecture, wire format, encoding: [`relay-backend/ARCHITECTURE.md`](../relay-backend/ARCHITECTURE.md)
