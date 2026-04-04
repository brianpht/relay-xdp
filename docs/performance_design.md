# Performance Design

> **Ultra-low-latency UDP game relay processing packets at NIC driver level
> using Linux XDP, written in Rust + eBPF.**

---

## Table of Contents

- [Deployment Assumptions](#deployment-assumptions)
- [Performance Targets](#performance-targets)
- [Core Design Principles](#core-design-principles)
    - [1. Kernel Bypass First](#1-kernel-bypass-first)
    - [2. Zero-Copy Packet Pipeline](#2-zero-copy-packet-pipeline)
    - [3. Allocation-Free Data Plane](#3-allocation-free-data-plane)
    - [4. Stack Budget Discipline (512 bytes)](#4-stack-budget-discipline-512-bytes)
    - [5. Inlining Policy](#5-inlining-policy)
    - [6. BPF Map Access Patterns](#6-bpf-map-access-patterns)
    - [7. Bounded Execution](#7-bounded-execution)
    - [8. Raw Pointer Arithmetic](#8-raw-pointer-arithmetic)
    - [9. Crypto in Kernel](#9-crypto-in-kernel)
    - [10. DDoS Filter as First Gate](#10-ddos-filter-as-first-gate)
    - [11. Byte Order Discipline](#11-byte-order-discipline)
    - [12. Two-Plane Separation](#12-two-plane-separation)
    - [13. Per-CPU Counters](#13-per-cpu-counters)
    - [14. Unsafe Policy](#14-unsafe-policy)
- [Performance Budget](#performance-budget)
- [Final Principle](#final-principle)

---

## Deployment Assumptions

| Assumption                 | Value                                                          |
|----------------------------|----------------------------------------------------------------|
| Kernel version             | Linux 6.5+ (BTF, kfunc support)                                |
| Primary target             | x86_64                                                         |
| XDP attach mode            | Native (driver-level), fallback to SKB                         |
| Wire format                | Mixed: network headers big-endian, relay payload little-endian |
| Crypto backend (kernel)    | `crypto_shash` (SHA-256), `chacha20_crypt` + `poly1305`        |
| Crypto backend (userspace) | `sha2`, `crypto_box`, `x25519-dalek`, `blake2` (pure Rust)     |
| Max concurrent sessions    | 200,000 (LRU hash map)                                         |
| Max relay peers            | 2,048                                                          |
| Priority                   | Latency > throughput > portability                             |

> The relay is designed for dedicated Linux servers. No Windows, macOS, or
> cross-endian support is planned.

---

## Performance Targets

### Data Plane (eBPF/XDP)

| Metric                    | Target                           | Rationale                            |
|---------------------------|----------------------------------|--------------------------------------|
| Packet processing latency | Sub-microsecond per packet       | XDP runs before kernel network stack |
| DDoS filter latency       | Nanosecond range                 | Byte-range checks only, no hashing   |
| Packet drop path          | Minimal instructions to XDP_DROP | Reject garbage as early as possible  |
| Session lookup            | O(1) via LRU hash map            | BPF map backed by kernel hash table  |
| Crypto verify (SHA-256)   | Single kfunc call per packet     | Kernel crypto API, no context switch |

### Control Plane (Userspace)

| Metric               | Target          | Rationale                                            |
|----------------------|-----------------|------------------------------------------------------|
| Update loop          | 1 Hz            | Backend sync, not latency-critical                   |
| Ping loop            | 10 Hz per relay | RTT measurement resolution                           |
| Session timeout scan | 1 Hz full scan  | Acceptable for 200K LRU entries                      |
| BPF map contention   | Minimal         | Userspace writes infrequently, eBPF reads per-packet |

### Regression Policy

- DDoS filter must reject invalid packets **before** any map lookup or crypto
- Adding instructions to the XDP hot path requires justification
- Any new BPF map lookup in the fast path requires measurement

---

## Core Design Principles

### 1. Kernel Bypass First

The entire point of XDP is to process packets **before** the kernel allocates
an `sk_buff`. Every packet that can be handled in eBPF (forward, reflect, drop)
MUST stay in eBPF. Only pong packets destined for the userspace ping thread
use `XDP_PASS`.

**Rule**: `XDP_PASS` is the slow path. Minimize its use.

---

### 2. Zero-Copy Packet Pipeline

Packets are **never copied** between kernel and userspace for relay routing.
The eBPF program operates directly on the packet buffer in the NIC's DMA ring:

| Operation                 | Copy?    | Method                                     |
|---------------------------|----------|--------------------------------------------|
| Parse ETH/IP/UDP headers  | No       | Raw pointer cast at known offsets          |
| Read relay payload fields | No       | `read_u64_le()` from packet pointer        |
| SHA-256 header verify     | No       | Hash computed over packet data in-place    |
| XChaCha20 token decrypt   | In-place | Kfunc decrypts over same buffer            |
| Header rewrite (redirect) | In-place | Overwrite ETH/IP/UDP fields directly       |
| Route request stripping   | In-place | `bpf_xdp_adjust_head` shifts start pointer |

The only "copy" operations are `copy_bytes()` for MAC addresses (6B) and
crypto struct setup (nonce: 24B, key: 32B).

**Rule**: Never allocate a second buffer for packet data in eBPF.

---

### 3. Allocation-Free Data Plane

There is **no heap** in eBPF. Every variable lives on the stack or in a BPF map.

| Resource       | Allocation Strategy                         |
|----------------|---------------------------------------------|
| Packet buffer  | Provided by NIC driver (DMA ring)           |
| Config/State   | BPF Array maps (pre-allocated at load time) |
| Session data   | BPF LRU Hash map (kernel manages eviction)  |
| Crypto structs | Stack variables                             |
| Counters       | Per-CPU Array map (no locking needed)       |

---

### 4. Stack Budget Discipline (512 bytes)

The BPF verifier enforces a **hard 512-byte stack limit**.

| Struct                   | Size | When allocated               |
|--------------------------|------|------------------------------|
| `Chacha20Poly1305Crypto` | 56B  | Route/continue request only  |
| `PingTokenData`          | 52B  | Ping handlers only           |
| `HeaderData`             | 50B  | Session packet handlers only |
| `SessionKey`             | 16B  | Every session lookup         |
| SHA-256 output           | 32B  | Every crypto verify          |

Rules:

- Never declare large structs at function entry if not needed in that path
- Crypto structs only in handlers that use them
- No arrays larger than 32 bytes on stack
- If approaching limit, move data to a per-CPU map

---

### 5. Inlining Policy

| Annotation          | When               | Rationale                              |
|---------------------|--------------------|----------------------------------------|
| `#[inline(always)]` | All eBPF functions | Eliminate call overhead, help verifier |
| No annotation       | Userspace code     | Let the compiler decide                |

---

### 6. BPF Map Access Patterns

| Map             | eBPF Access                   | Userspace Access          | Contention         |
|-----------------|-------------------------------|---------------------------|--------------------|
| `config_map`    | Read every packet             | Write once at init        | None               |
| `state_map`     | Read every packet             | Write every 1s            | Negligible         |
| `stats_map`     | Write every packet (per-CPU)  | Read every 1s             | **None** (per-CPU) |
| `relay_map`     | Read on ping/pong only        | Write on relay set change | Rare               |
| `session_map`   | Read/write per session packet | Read/delete every 1s      | Low (LRU)          |
| `whitelist_map` | Read/write per packet         | Read/delete every 1s      | Low (LRU)          |

Rules:

- Use `get_ptr` / `get_ptr_mut` to avoid copy
- Never iterate maps in eBPF (only userspace timeout scan)
- Per-CPU arrays for counters (zero contention)
- LRU maps for session/whitelist (kernel handles eviction)

---

### 7. Bounded Execution

The BPF verifier requires **proof of termination**.

| Pattern                                         | Status                              |
|-------------------------------------------------|-------------------------------------|
| `while i < N { ... i += 1; }` with constant `N` | **Allowed**                         |
| `for item in iterator`                          | **Forbidden in eBPF**               |
| Recursive functions                             | **Forbidden**                       |
| Unbounded loops                                 | **Forbidden**                       |
| `loop { ... break on condition }`               | **Forbidden** (verifier may reject) |

---

### 8. Raw Pointer Arithmetic

The verifier tracks pointer ranges and rejects access outside `[data, data_end)`.

Rules:

- Bounds check before **every** pointer dereference
- Check `ptr + size > data_end` pattern (not `>=`)
- Never store packet pointers across map lookups
- Re-derive pointers after `bpf_xdp_adjust_head/tail`

**Rule**: The verifier is always right. If it rejects your code, restructure.

---

### 9. Crypto in Kernel

| Operation              | Kfunc                                 | Input  | Cost        |
|------------------------|---------------------------------------|--------|-------------|
| Header/ping verify     | `bpf_relay_sha256`                    | 50–52B | ~200–500ns  |
| Route token decrypt    | `bpf_relay_xchacha20poly1305_decrypt` | 87B    | ~500–1000ns |
| Continue token decrypt | `bpf_relay_xchacha20poly1305_decrypt` | 33B    | ~300–700ns  |

Rules:

- Minimize crypto calls per packet (1 SHA-256 for most types)
- Never do crypto after the packet is already determined invalid
- Order checks: size → expiry → map lookup → crypto verify

---

### 10. DDoS Filter as First Gate

Processing order (cheapest reject first):

```
1. ETH/IP/UDP parse           -- reject non-UDP
2. Destination check          -- reject wrong destination
3. Size check (18–1400B)      -- reject oversized/undersized
4. Packet filter (pittle/chonkle) -- reject DDoS noise
5. Packet type dispatch       -- ping types skip whitelist
6. Whitelist check            -- reject unknown senders
7. Session lookup             -- reject unknown sessions
8. Crypto verify              -- reject tampered packets
9. Forward / reflect / pass   -- actual work
```

**Rule**: Never add a map lookup or crypto call before step 4.

---

### 11. Byte Order Discipline

| Layer                     | Byte Order            | Fields                                                         |
|---------------------------|-----------------------|----------------------------------------------------------------|
| Ethernet/IPv4/UDP headers | Big-endian (network)  | `h_proto`, `saddr`, `daddr`, ports                             |
| Relay protocol payload    | Little-endian         | `sequence`, `session_id`, `expire_timestamp`                   |
| BPF map address fields    | Big-endian            | `relay_public_address`, `next_address`, `WhitelistKey.address` |
| BPF map native fields     | Native (LE on x86_64) | `expire_timestamp`, sequence counters                          |

Rules:

- Network header fields: always use `.to_be()` / `.from_be()`
- Relay payload fields: always use `read_u64_le()` byte-by-byte decode
- BPF map address fields: store in big-endian (match network headers)
- Never use `u32::from_ne_bytes` on address fields

---

### 12. Two-Plane Separation

The control plane and data plane share **no memory** except through BPF maps.

Rules:

- No shared memory outside BPF maps
- Userspace never touches packet data
- eBPF never makes syscalls or uses helpers that block
- Config is write-once from userspace, read-only in eBPF
- State updates are atomic (single map write per second)

---

### 13. Per-CPU Counters

`stats_map` is a `PerCpuArray` with 150 u64 counters. Each CPU core writes to
its own copy with **zero locking**. Userspace sums across all CPUs once per
second.

**Rule**: Never use atomics or locks for counter updates in eBPF.

---

### 14. Unsafe Policy

**eBPF** (`relay-xdp-ebpf`):

- `unsafe` for packet pointer access, kfunc FFI, `copy_bytes`, `read_u64_le` - all required
- Document bounds check before each unsafe block
- Every `unsafe` must have a preceding verifier-visible bounds check

**Userspace** (`relay-xdp`):

- `unsafe` for libc calls (`geteuid`, `setsockopt`) and `PingTokenData` raw pointer cast - allowed
- `unwrap()` in production paths - **forbidden**
- `unwrap()` in tests - allowed

**Kernel module** (`module/`):

- All code is inherently unsafe (kernel C)
- `memzero_explicit` after crypto operations - required
- Error checking on `crypto_alloc_shash` - required
- Self-test in `module_init` - required

---

## Performance Budget

### Per-Packet Fast Path (eBPF)

| Step                               | Budget    |
|------------------------------------|-----------|
| ETH/IP/UDP parse                   | < 50ns    |
| DDoS filter (pittle/chonkle)       | < 20ns    |
| Map lookup (session/whitelist)     | < 100ns   |
| Crypto verify (SHA-256 kfunc)      | < 500ns   |
| Header rewrite + checksum          | < 50ns    |
| **Total (session packet forward)** | **< 1μs** |

### Per-Packet Expensive Path (Route Request)

| Step                       | Budget    |
|----------------------------|-----------|
| XChaCha20-Poly1305 decrypt | < 1μs     |
| Session map insert         | < 200ns   |
| Header copy + adjust       | < 100ns   |
| **Total (route request)**  | **< 2μs** |

### Investigation Triggers

- Any single packet handler exceeds 5μs → investigate
- DDoS filter path exceeds 50ns → investigate
- XDP_DROP path touches a map → investigate

---

## Final Principle

```
Packets never leave the NIC if they don't need to.
Crypto never runs if the packet is already invalid.
Maps never lock if per-CPU alternatives exist.
Userspace never touches what eBPF can handle.
```

