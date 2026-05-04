# ADR-006: FFI Panic Policy for relay-sdk

**Date:** 2026-05-04<br>
**Status:** Accepted (implementation landed same day - see P1-02 in companion session)<br>
**Deciders:** developer<br>
**Related Tasks:** Phase 1 action P1-02 (audit v2)<br>
**Related ADRs:** N/A<br>
**Related Sessions:** [Session 2026-05-04 v2](../sessions/2026-05-04-project-audit-plan-v2.md)<br>

## Context

`relay-sdk` exposes a C ABI (`pub extern "C"`) loaded by game clients and servers as either a `cdylib` or `staticlib`. Every public FFI entry point wraps its body in `std::panic::catch_unwind` because a Rust panic that crosses the FFI boundary is undefined behaviour.

Today the SDK has two shapes of FFI function:

1. **Functions that return an integer status code** (e.g. `relay_client_get_stats(handle, out) -> c_int`). On panic, `catch_unwind` returns `Err(_)` and the wrapper converts that to a documented error sentinel (e.g. `RELAY_ERR_INTERNAL`).
2. **Void FFI functions** (e.g. various `relay_*_free` and reset / configure helpers). On panic, `catch_unwind` returns `Err(_)` and the wrapper has nowhere to report it - the function returns to the caller as if nothing happened. The panic payload is dropped silently.

The audit v2 flagged the second shape as a Critical correctness/observability bug: a C/C++ embedder has no way to know that an internal invariant violation occurred. The bug class hides:

- Logic errors in `relay-sdk` itself (panics from `unwrap()` on internal invariants, slice-index OOB in pure Rust code).
- Resource exhaustion (mutex poisoning, allocation failure if `set_alloc_error_hook` ever surfaces).
- Future contributors who add `unwrap()` to a hot path under the assumption that "it cannot fail".

The decision needs to specify both a **runtime contract** (what happens on panic) and a **C-side surface** (how an embedder learns about it). The choice affects what guarantees `relay-sdk`'s public header can promise.

Consequences of inaction:

- Embedders cannot tell a "everything is fine, nothing happened" call from a "the SDK panicked, is now in an unknown state" call. This is a worse contract than no FFI wrapper at all - at least an unwrap-and-abort would surface in a crash dump.
- The `catch_unwind` wrapper currently provides correctness (no UB across FFI) at the cost of observability. We should not lose either.

## Options Considered

### Option A: Registered C log callback + best-effort error sentinel

- **Description:** Add a single `relay_set_panic_hook(fn(*const c_char))` FFI entry that lets the embedder register a C callback. On `catch_unwind` failure inside any FFI function, the wrapper formats the panic payload (`PanicInfo` + thread name) into a stack-allocated `c_char` buffer and invokes the registered callback before returning. Functions that have a return value still return an error sentinel; void functions invoke the callback and return normally. Process state continues - the panic is treated as a recoverable error that the embedder is now informed about.
- **Pros:** Embedders learn about panics without losing the no-UB guarantee. The hook is opt-in - embedders that do not register one get today's silent behaviour, which is a strict superset of current capability. The hook is low-overhead in the success path (one branch on a static `AtomicPtr`). The mechanism is the same shape as `std::panic::set_hook` so the design is familiar.
- **Cons:** Adds a new FFI surface (one function + one function-pointer type) that must be in the cbindgen-generated header. The callback is invoked from inside the panic recovery path; embedders need to know not to do anything that may itself panic in the callback (we document this). After the panic, the SDK is in a "best effort" state - some operations on the affected handle may produce stale data; the embedder is responsible for treating the affected handle as suspect.
- **Effort:** Impl: low / Migration: low (header regen) / Maintenance: low

### Option B: Abort the process on any FFI panic

- **Description:** Convert the `catch_unwind` wrapper to abort instead of returning. Embedders see a process crash with a panic backtrace.
- **Pros:** Failures are loud and impossible to miss. No silent-corruption risk.
- **Cons:** Aborting an embedder process from inside a library is a very strong policy choice that game engines typically reject. A game server that panics inside `relay_server_get_stats` should not take down the match. Also makes integration testing harder - any negative-path test that triggers a panic now requires a sub-process harness.
- **Effort:** Impl: very low / Migration: medium (embedder communication) / Maintenance: low

### Option C: Status quo - silent swallow

- **Description:** Keep the current behaviour.
- **Pros:** Zero work.
- **Cons:** The original audit finding stands. Embedders cannot detect SDK panics.
- **Effort:** none

### Option D: Per-handle "last error" string buffer queried by a `relay_*_last_error` accessor

- **Description:** Store the panic payload in a `Mutex<Option<CString>>` field on each handle struct. On `catch_unwind` failure, write the payload there. Add `relay_*_last_error(handle, out, out_len)` accessors.
- **Pros:** Pull-model API; embedders query when they want.
- **Cons:** Requires embedders to poll, which most will not. Some FFI functions have no handle (e.g. global initialization), so the model has gaps. Adds a mutex on every handle for a path that should be cold. Reporting a panic on `relay_*_free` is awkward because the handle is being freed.
- **Effort:** Impl: medium / Migration: medium / Maintenance: medium

## Decision

**Chosen: Option A - Registered C log callback + best-effort error sentinel**

## Rationale

Option B is the wrong default for a library embedded in a game runtime. Killing the host process from inside `relay-sdk` violates the principle of least surprise; embedders expect a library to fail in-band. We can leave a configurable "abort on panic" for embedders who want it (a future extension to the same hook surface), but it must not be the default.

Option C is what the audit flagged as Critical; it cannot stand.

Option D is the only competitive alternative. The reason Option A wins: panics are rare, and a push-model log callback is the right shape for rare events. Pull-model error buffers force every well-behaved embedder to write polling code for an event that ~never happens. Option A also handles the global / no-handle case naturally (the hook is process-global), which Option D does not.

The deciding factor: the hook design is opt-in. Embedders who do not register a hook get exactly the current behaviour; we add observability without forcing any embedder to change their integration. Option B is opt-out (you must embed the abort hook to get current behaviour), which is a worse default for a library.

## Consequences

- **Positive:** Embedders gain a single, simple way to learn about SDK panics. The C header documents the contract clearly. No UB across the FFI boundary (existing `catch_unwind` correctness is preserved). The wrapper change is a one-line addition per FFI function (call the hook in the `Err` arm before returning). Unit tests can register a capturing hook to assert "this negative-path call did/did not panic".
- **Negative:** New global state (the `AtomicPtr<extern "C" fn(*const c_char)>` holding the registered hook). Embedders must understand that registering a hook that itself panics is a programming error - documented in the header. After a panic, the affected handle is in an unspecified state; the embedder must treat it as suspect. This is true of Option C too, just now visibly so.
- **Neutral:** The void-FFI panic still does not have a return-value surface, but with the hook it has an observability surface. The semantics are: "panic was reported via hook; void function returned normally; handle is suspect". This is documented per-function in the cbindgen header.

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `relay-sdk/src/ffi/mod.rs` | Modified | New `relay_set_panic_hook` entry; `catch_unwind` `Err` arms invoke the hook before returning |
| `relay-sdk/src/ffi/panic.rs` | New | `AtomicPtr` holding the hook + safe accessor |
| `relay-sdk/cbindgen.toml` | Modified | Ensure the new `extern "C"` symbol is exported |
| `relay-sdk/include/relay_generated.h` (regenerated) | Updated | Documented in cbindgen post-amble |
| `relay-sdk/tests/` | New | One test that registers a capturing hook, calls a function whose body panics on a poisoned input, and asserts the hook fired |
| `relay-sdk/ARCHITECTURE.md` | Updated | New "FFI panic policy" subsection pointing here |
| Embedders | None | Opt-in; no code changes required to keep current behaviour |

## Revisit When

- A real embedder requests "abort on panic" semantics for hardened deployments. The hook surface can be extended with a `relay_set_panic_abort_on_call(true)` toggle without breaking Option A.
- Panics inside the SDK are observed in production via the hook; their frequency suggests we need a richer payload (e.g. structured fields, not just a string).
- Rust stabilises a different FFI panic story (e.g. zero-cost `?` across `extern "C"` boundaries); revisit the wrapper shape.

## Migration Plan

1. Add `relay-sdk/src/ffi/panic.rs` with the `AtomicPtr<extern "C" fn(*const c_char)>`, a thread-safe setter, and a `report_panic(payload: Box<dyn Any + Send>)` helper that formats and invokes the hook (no-op when unset).
2. Add `pub extern "C" fn relay_set_panic_hook(hook: extern "C" fn(*const c_char))` in `ffi/mod.rs`.
3. Modify the `catch_unwind` wrapper macro / helper used by every FFI entry point: in the `Err(payload)` arm, call `report_panic(payload)` before returning the error sentinel (or before returning unit for void functions).
4. Regenerate the cbindgen header; verify the new symbol appears.
5. Add the unit test that asserts the hook fires.
6. Document the contract in `relay-sdk/ARCHITECTURE.md` (one paragraph + pointer to this ADR).
7. No protocol or wire change; no embedder migration required for default behaviour.