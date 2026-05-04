//! FFI panic hook (P1-02 / ADR-006).
//!
//! `relay-sdk`'s FFI entry points wrap their bodies in
//! [`std::panic::catch_unwind`] because a Rust panic crossing the FFI
//! boundary is undefined behaviour. Without a hook, a panic inside a
//! void-returning entry point is silently swallowed; embedders cannot tell
//! whether internal state has been corrupted.
//!
//! This module exposes:
//!   - [`set_hook`] - register / unregister a C callback that receives a
//!     null-terminated panic message string.
//!   - [`ffi_catch`] - the wrapper used by every FFI entry point. On panic,
//!     it formats the payload and invokes the registered hook (if any) before
//!     returning `default`.
//!
//! The hook is **opt-in**: embedders that never call `relay_set_panic_hook`
//! observe the historical "silent swallow" behaviour. Embedders that do
//! register a hook get visibility without paying any other contract change.
//!
//! See `docs/decisions/ADR-006-ffi-panic-policy-for-relay-sdk.md`.

use std::any::Any;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicPtr, Ordering};

/// C-compatible callback signature: receives a null-terminated UTF-8 string
/// describing the panic. The pointer is only valid for the duration of the
/// call - do not retain it past the callback.
pub type PanicHook = extern "C" fn(*const c_char);

/// Registered hook, encoded as a function pointer cast to `*mut ()` so we
/// can use `AtomicPtr` (which has no `*mut fn(...)` variant). Null = unset.
static HOOK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// Register or unregister the panic hook. Pass `Some(fn)` to set, `None` to
/// clear. Thread-safe; the new hook becomes visible to all other threads
/// after this returns.
pub fn set_hook(hook: Option<PanicHook>) {
    let ptr = match hook {
        Some(f) => f as *mut (),
        None => std::ptr::null_mut(),
    };
    HOOK.store(ptr, Ordering::Release);
}

fn get_hook() -> Option<PanicHook> {
    let ptr = HOOK.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // Safety: only `set_hook` writes to `HOOK`, and it only ever stores
        // either null or a value produced by `f as *mut ()` where `f:
        // PanicHook`. So a non-null pointer here is always a valid
        // `PanicHook`.
        Some(unsafe { std::mem::transmute::<*mut (), PanicHook>(ptr) })
    }
}

fn format_payload(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "panic with non-string payload".to_string()
}

/// Format `payload` and invoke the registered hook, if any. No-op if no
/// hook is registered or if the message contains an interior NUL.
fn report(payload: Box<dyn Any + Send>) {
    let Some(hook) = get_hook() else {
        return;
    };
    let msg = format_payload(&*payload);
    let Ok(c_msg) = CString::new(msg) else {
        return;
    };
    // Safety: the hook is a `extern "C" fn(*const c_char)`; the pointer is
    // valid for the duration of the call.
    hook(c_msg.as_ptr());
}

/// Wrap an FFI body. On panic, invokes the registered hook (if any) and
/// returns `default`. Replaces direct `catch_unwind(...).unwrap_or(...)` /
/// `let _ = catch_unwind(...)` patterns at every entry point so the hook
/// fires uniformly.
pub fn ffi_catch<R>(default: R, f: impl FnOnce() -> R + std::panic::UnwindSafe) -> R {
    match std::panic::catch_unwind(f) {
        Ok(r) => r,
        Err(payload) => {
            report(payload);
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    /// Test hook: append received message to a global buffer.
    static FIRED_COUNT: AtomicUsize = AtomicUsize::new(0);
    static LAST_MESSAGE: Mutex<Option<String>> = Mutex::new(None);

    /// Hook + counters are process-global, so cargo's parallel test runner
    /// would interleave the three test bodies and trash the assertions.
    /// `TEST_LOCK` serializes them. The lock is intentionally NOT poisoned-
    /// recoverable; if a test panics with the lock held, subsequent tests
    /// fail loudly rather than silently observe stale state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    extern "C" fn capturing_hook(msg: *const c_char) {
        FIRED_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        if msg.is_null() {
            return;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(msg) }
            .to_string_lossy()
            .into_owned();
        *LAST_MESSAGE.lock().unwrap() = Some(s);
    }

    fn reset_capture() {
        FIRED_COUNT.store(0, AtomicOrdering::Relaxed);
        *LAST_MESSAGE.lock().unwrap() = None;
    }

    #[test]
    fn no_hook_no_invocation() {
        let _g = TEST_LOCK.lock().unwrap();
        set_hook(None);
        reset_capture();
        let r = ffi_catch(99, || panic!("no hook installed"));
        assert_eq!(r, 99);
        assert_eq!(FIRED_COUNT.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn hook_fires_on_panic_and_returns_default() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_capture();
        set_hook(Some(capturing_hook));
        let r = ffi_catch(-1i32, || panic!("custom panic message"));
        assert_eq!(r, -1);
        assert_eq!(FIRED_COUNT.load(AtomicOrdering::Relaxed), 1);
        let captured = LAST_MESSAGE.lock().unwrap().clone();
        assert_eq!(captured.as_deref(), Some("custom panic message"));
        set_hook(None);
    }

    #[test]
    fn hook_does_not_fire_on_success() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_capture();
        set_hook(Some(capturing_hook));
        let r = ffi_catch(0u32, || 42);
        assert_eq!(r, 42);
        assert_eq!(FIRED_COUNT.load(AtomicOrdering::Relaxed), 0);
        set_hook(None);
    }
}
