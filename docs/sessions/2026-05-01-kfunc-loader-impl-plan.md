# Session Summary: kfunc Loader Implementation Plan

**Date:** 2026-05-01<br>
**Duration:** ~6 hours (~30 interactions)<br>
**Focus Area:** relay-xdp BPF load path - kfunc relocation implementation via raw syscall<br>

## Objectives

- [x] Confirm aya git HEAD has no kfunc support (neither aya-obj nor aya-ebpf-macros)
- [x] Confirm `fd_array` exists in aya-obj generated bindings (`bpf_attr__bindgen_ty_4.fd_array` at offset 120)
- [x] Confirm `Ebpf::load()` does NOT call `bpf_prog_load` - only `program.load()` does (lazy)
- [x] Confirm `aya_obj::Function::instructions` is `pub` and accessible directly
- [x] Confirm instruction byte layout: `src_reg=1, imm=0xffffffff` at kfunc call sites
- [x] Design full implementation architecture
- [x] Verify 3 API gaps before implementation (aya-obj, object crate, Map::fd)
- [x] Implement `relay-xdp/src/kfunc.rs`
- [x] Modify `relay-xdp/src/bpf.rs` to use kfunc loader
- [x] Build + test locally (dev + release, 21/21 tests pass)
- [ ] Deploy to staging, verify `bpftool prog list` shows relay_xdp with kfuncs resolved

## Work Completed

### Root Cause Trace (Continued from previous session)

Confirmed the exact instruction encoding produced by bpf-linker 0.10.3 for
`extern "C"` kfunc declarations. Reading from `relay_xdp_rust.o` at the three
kfunc relocation offsets (0xeb0, 0xfa8, 0x1ce8):

```
code=0x85  src_reg=1  dst_reg=0  imm=0xffffffff  raw=85100000ffffffff
```

- `code=0x85` = `BPF_JMP | BPF_CALL` (call instruction)
- `src_reg=1` = `BPF_PSEUDO_CALL` (NOT `BPF_PSEUDO_KFUNC_CALL=2`)
- `imm=0xffffffff` = -1 (placeholder, relocation target via `R_BPF_64_32`)

bpf-linker emits these as regular-looking calls with an ELF relocation,
NOT as pre-formed kfunc calls with `src_reg=2`.

### ELF Deep Analysis (New - 2026-05-01)

Full readelf inspection of `relay_xdp_rust.o` revealed:

**Sections:**
- `.text`: section 2, 0x260 bytes (76 instructions) - BPF subroutines (memset, etc.)
- `xdp`: section 3, 0x9400 bytes (4736 instructions) - main XDP program
- `.relxdp`: section 4, 44 relocation entries (both R_BPF_64_64 and R_BPF_64_32)
- `maps`: section 5 - map definitions

**Correction to session plan**: plan stated "3 kfunc offsets (0xeb0, 0xfa8, 0x1ce8)".
Actual count from readelf: **14 R_BPF_64_32 kfunc call sites** across the XDP section:
- `bpf_relay_sha256`: 12 call sites
- `bpf_relay_xchacha20poly1305_decrypt`: 2 call sites

**Non-kfunc R_BPF_64_32 symbols** (aya-obj handles via BPF helper ID table):
- `bpf_xdp_adjust_tail` (sym=19): 3 call sites with `src_reg=1, imm=-1`
- `bpf_xdp_adjust_head` (sym=22): 2 call sites with `src_reg=1, imm=-1`
- `memset` (sym=21): 1 call site, `FUNC GLOBAL HIDDEN 2` - lives in `.text` section

All above have identical byte encoding `85100000ffffffff`. Distinction between
kfunc and helper is done by symbol NAME in `collect_kfunc_offsets`, NOT by sym kind.

### aya-obj Failure Path Confirmed

`relocate_calls()` failure trace for kfunc offsets:

1. `insn_is_call(&ins)` returns `true` (code=0x85, src_reg=1)
2. Symbol filter `.filter(|(_rel, sym)| sym.kind == SymbolKind::Text || ...)` returns
   `false` for `NOTYPE GLOBAL UND` symbols → `rel = None`
3. `!is_call && rel.is_none()` = `false` → does NOT skip
4. Falls to pc-relative branch: `callee_address = section_offset + (ins_index * 8) + (imm+1) * 8`
   With `imm=-1`, `callee_address = 0xeb0`
5. `self.functions.get(&(section_idx, 0xeb0))` → None →
   `UnknownFunction { address: 0xeb0, caller_name: "relay_xdp" }`

### aya git HEAD Audit

Cloned `aya-rs/aya` at commit `07391268`:

- `grep "kfunc|PSEUDO_KFUNC" aya-obj/src/ --exclude-dir=generated` → **zero results**
- `grep "kfunc|fd_array" aya/src/` → **zero results**
- Neither aya nor aya-ebpf-macros has any kfunc support in non-generated files
- aya's `bpf_load_program()` does NOT set `fd_array` in `bpf_attr`

### API Verification Results (New - 2026-05-01)

Verified from `cargo doc -p aya-obj --no-deps` generated HTML:

**1. `bpf_insn` correct path:**
```rust
aya_obj::generated::bpf_insn  // NOT aya_obj::generated::linux_bpf::bpf_insn
```
Fields: `pub code: u8`, `pub off: i16`, `pub imm: i32`
Bitfield methods: `src_reg() -> u8`, `set_src_reg(u8)`, `dst_reg() -> u8`

**2. `aya_obj::Object::relocate_calls` signature:**
```rust
pub fn relocate_calls(&mut self, text_sections: &HashSet<usize>) -> Result<(), ...>
```
Takes immutable reference to `HashSet<usize>`.

**3. `aya_obj::Program::function_key` signature:**
```rust
pub fn function_key(&self) -> (usize, u64)
// "The key used by Object::functions"
```

**4. `aya_obj::Object` fields:**
```rust
pub programs: HashMap<String, Program>
pub functions: BTreeMap<(usize, u64), Function>
```

**5. `object` crate (0.36.7):** Already transitive dep via aya-obj.
Added as direct dep in `relay-xdp/Cargo.toml` with `features = ["read"]`.

**6. `aya_obj::Object::relocate_maps` NOT needed:**
Bypassed entirely by `patch_elf_map_fds()` which writes map FD values directly
into BPF_LD_IMM64 instruction bytes in the ELF before second aya_obj parse.

### Key Architectural Discoveries

**1. `Ebpf::load()` is lazy - does not call `bpf_prog_load`**

`Ebpf::load(bytes)` in aya:
- Calls `obj.relocate_maps(...)` - creates maps, patches map FD instructions
- Calls `obj.relocate_calls(...)` - inlines `.text` functions, fails on kfuncs
- Stores program objects (as `Program { data: ProgramData { obj: Some(...), fd: None } }`)
- `bpf_prog_load` is only called later via `program.load()`

This means: if we make `relocate_calls()` succeed, `Ebpf::load()` returns a valid
`Ebpf` handler with all maps created and accessible. We skip `program.load()`.

**2. `aya_obj::Function::instructions` is public**

`aya_obj::Function` (file `src/obj.rs:192`):
```rust
pub struct Function {
    pub instructions: Vec<bpf_insn>,  // line 202
    ...
}
```
`Object.functions: BTreeMap<(usize, u64), Function>` and
`Object.programs: HashMap<String, Program>` are also `pub`.

**3. `fd_array` field exists at offset 120 in `bpf_attr__bindgen_ty_4`**

From `aya-obj-0.2.1/src/generated/linux_bindings_x86_64.rs:599`:
```rust
pub struct bpf_attr__bindgen_ty_4 {
    pub prog_type: __u32,   // offset 0
    pub insn_cnt: __u32,    // offset 4
    pub insns: __u64,       // offset 8
    pub license: __u64,     // offset 16
    // ... (omitted for brevity)
    pub core_relo_cnt: __u32, // offset 116
    pub fd_array: __u64,    // offset 120  <-- NEEDED
    pub core_relos: __u64,  // offset 128
    pub core_relo_rec_size: __u32, // offset 136
    pub log_true_size: __u32,     // offset 140
    pub prog_token_fd: __s32,     // offset 144
}
```
aya's `bpf_load_program()` builds this struct but never sets `fd_array` - it
is zeroed by default (meaning: no kfunc BTF FDs passed to kernel).

**4. Module kfuncs require `insn->off != 0` and `fd_array`**

When `relay_module.ko` calls `register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, set)`,
it registers kfunc BTF IDs relative to the MODULE's own BTF object.

In the kernel verifier `check_kfunc_call`:
- `insn->off = 0` → looks in vmlinux BTF only → **module kfuncs NOT found**
- `insn->off = n` → looks in `fd_array[n-1]` (module BTF FD) → **found**

Setting `insn->off = 1` with `fd_array = [relay_module_btf_fd]` is required.

**5. `BPF_LINK_CREATE` for XDP uses `target_ifindex` (not `target_fd`)**

In kernel `bpf_attr` for `BPF_LINK_CREATE` XDP variant, offset 4 is
`target_ifindex` (u32 network interface index), NOT a file descriptor.
No `/sys/class/net/<name>` open required.

### Revised Implementation Architecture

The actual loading flow implemented in `kfunc.rs`:

```
1. Read ELF bytes from disk
       |
       v
2. collect_kfunc_offsets(elf, RELAY_MODULE_KFUNCS)
   - Parse .relxdp for R_BPF_64_32 against symbol names matching kfunc list
   - Returns: HashMap<xdp_byte_offset, kfunc_name>
   - NOTE: bpf_xdp_adjust_* and memset are NOT included (handled by aya-obj)
       |
       v
3. patch_elf_skip_kfuncs(elf, kfunc_offsets) -> patched_v1
   - Change src_reg byte 0x10 -> 0x20 at each kfunc offset in xdp section
       |
       v
4. Ebpf::load(&patched_v1)
   - relocate_maps(): creates all 6 maps with real FDs
   - relocate_calls(): inlines memset from .text, patches bpf_xdp_* helpers,
                       SKIPS kfunc insns (src_reg=2)
   - returns Ebpf with live map FDs (program fd = None, not kernel-loaded)
       |
       v
5. Collect map FDs from aya: bpf.map("name")? -> via Map API
   - config_map, state_map, stats_map, relay_map, session_map, whitelist_map
       |
       v
6. patch_elf_map_fds(patched_v1, map_fds) -> patched_v2
   - Parse .relxdp R_BPF_64_64 entries, find map load instruction positions
   - Write real FD values into BPF_LD_IMM64 imm fields directly in ELF bytes
   - Avoids need for aya_obj::Object::relocate_maps()
       |
       v
7. get_xdp_instructions(patched_v2)
   - aya_obj::Object::parse(patched_v2)
   - Compute text_sections: HashSet<usize> from section names with object crate
   - obj.relocate_calls(&text_sections) [SUCCESS - kfuncs skipped, map FDs already patched]
   - key = obj.programs["relay_xdp"].function_key()
   - insns = obj.functions[&key].instructions.clone()
       |
       v
8. find_module_btf("relay_module")
   - BPF_BTF_GET_NEXT_ID (cmd 23) loop over all loaded BTF objects
   - BPF_BTF_GET_FD_BY_ID (cmd 19) -> btf_fd
   - BPF_OBJ_GET_INFO_BY_FD (cmd 15) -> name check, btf_size
   - If name matches: fetch BTF bytes, return (btf_fd, btf_bytes)
       |
       v
9. parse_btf_func_ids(btf_bytes, RELAY_MODULE_KFUNCS)
   - Parse BTF header (magic=0xeb9f), walk type section
   - Count type IDs from 1 (BTF_KIND_FUNC has 0 extra bytes)
   - Return HashMap<kfunc_name, btf_type_id>
       |
       v
10. patch_kfunc_instructions(insns, kfunc_offsets, btf_ids, fd_array_idx=1)
    - Sort kfunc_offsets by byte offset (stable ordering)
    - Scan insns for src_reg=2 call instructions (in same relative order)
    - ZIP: Nth src_reg=2 insn <-> Nth sorted kfunc_offset entry
    - Set: insn.off = 1, insn.imm = btf_id as i32
       |
       v
11. raw_load_xdp(insns, module_btf_fd)
    - [u8; 152] attr, zeroed
    - Write fields at byte offsets: prog_type(0), insn_cnt(4), insns(8),
      license(16), log_level+buf(24-39), prog_name(48), fd_array(120)
    - fd_array = ptr to [module_btf_fd as u32]
    - libc::syscall(SYS_BPF=321, BPF_PROG_LOAD=5, &attr, 152)
    - On failure: print verifier log (256KB buffer)
    - Returns prog_fd (raw i32)
       |
       v
12. raw_create_xdp_link(prog_fd, ifindex)
    - [u8; 64] attr: prog_fd(0), target_ifindex(4), BPF_XDP=37(8), flags=0(12)
    - libc::syscall(SYS_BPF=321, BPF_LINK_CREATE=28, &attr, 64)
    - Returns link_fd
       |
       v
Done: BpfContext { bpf: Ebpf, prog_fd, link_fd }
- bpf: holds all map FDs via aya's normal map API
- prog_fd: raw kernel prog fd
- link_fd: XDP link - closing detaches from NIC
```

### BTF Parsing Notes

BTF format reference:
```
struct btf_header { magic(2), version(1), flags(1), hdr_len(4),
                    type_off(4), type_len(4), str_off(4), str_len(4) }
Each type entry base: name_off(4), info(4), size_or_type(4) = 12 bytes
kind = (info >> 24) & 0x1f
vlen = info & 0xffff
```
Extra bytes after base (needed to advance iterator):
- BTF_KIND_INT (1): +4 bytes
- BTF_KIND_ARRAY (3): +12 bytes
- BTF_KIND_STRUCT/UNION (4,5): +vlen*12 bytes
- BTF_KIND_ENUM (6): +vlen*8 bytes
- BTF_KIND_FUNC (12): +0 bytes  <- our target
- BTF_KIND_FUNC_PROTO (13): +vlen*8 bytes
- BTF_KIND_VAR (14): +4 bytes
- BTF_KIND_DATASEC (15): +vlen*12 bytes
- BTF_KIND_DECL_TAG (17): +4 bytes
- BTF_KIND_ENUM64 (19): +vlen*12 bytes
- All others: +0 bytes

BTF ID = 1-based sequential index in type iteration order (0 = void/invalid).

### BPF Syscall Command Reference

| Command | Number | Used For |
|---------|--------|----------|
| `BPF_PROG_LOAD` | 5 | Load program with fd_array |
| `BPF_BTF_GET_NEXT_ID` | 23 | Enumerate BTF objects |
| `BPF_BTF_GET_FD_BY_ID` | 19 | Open BTF FD by ID |
| `BPF_OBJ_GET_INFO_BY_FD` | 15 | Get BTF info (name, data) |
| `BPF_LINK_CREATE` | 28 | Attach XDP to interface |

BPF attach type for XDP: `BPF_XDP = 37`

## Decisions Made

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Use aya for maps, bypass for XDP prog load | `Ebpf::load()` creates maps lazily; `aya_obj::Function::instructions` is pub - avoids forking aya | N/A |
| Read module BTF via BTF ID enumeration syscall | No `bpf(BPF_BTF_GET_FD_BY_NAME)` in all kernels; enumeration works on 6.5+ | N/A |
| Set `insn->off = 1` not 0 | `off=0` uses vmlinux BTF only; module kfuncs are in relay_module.ko BTF, require off != 0 | N/A |
| Use `raw_create_xdp_link` (`BPF_LINK_CREATE`) not legacy ioctl | `target_ifindex` (u32) at offset 4 in attr - no sysfs fd open required | N/A |
| Do NOT fork aya | `aya_obj::Function::instructions` is already `pub`; two-phase parse avoids need for fork | N/A |
| Bypass `relocate_maps` with `patch_elf_map_fds` | `relocate_maps` API requires `aya_obj::Map` references - bypassing via raw ELF byte patching is simpler and cleaner | N/A |
| Filter kfuncs by name not by sym kind | `bpf_xdp_adjust_*` also have `NOTYPE GLOBAL UND` encoding - must filter by explicit name list (`RELAY_MODULE_KFUNCS`) | N/A |
| Use ordering correspondence for kfunc-to-insn mapping | After `relocate_calls`, Nth src_reg=2 insn corresponds to Nth sorted kfunc offset from original ELF - ordering preserved because `relocate_calls` never reorders non-call instructions | N/A |

## Tests Added/Modified

| Test Class | Method | Type | Status |
|------------|--------|------|--------|
| `kfunc::tests` | `test_btf_kind_extra_bytes` | Unit | PASS |
| `kfunc::tests` | `test_patch_elf_skip_kfuncs_with_real_elf` | Integration (uses relay_xdp_rust.o) | PASS |

## Issues Encountered

| Issue | Resolution | Blocking |
|-------|------------|----------|
| aya git HEAD has no kfunc support | Confirmed - neither aya nor aya-obj on any release supports kfuncs | Resolved (different approach) |
| `Ebpf::load()` + `program.load()` coupled for both map and prog | `program.load()` is lazy - only called explicitly; we skip it | Resolved |
| `ProgramData.obj` is `pub(crate)` in aya | Use `aya_obj::Object::parse()` + direct `Function::instructions` access instead | Resolved |
| Module kfuncs need `fd_array` - aya's `bpf_load_program` does not set it | Call raw `bpf_prog_load` syscall ourselves with `fd_array` set | Resolved |
| `.text` inlining must still happen | `aya_obj::Object::relocate_calls()` handles it after kfunc bypass; use result's `Function::instructions` | Resolved |
| `bpf_insn` path in aya_obj 0.2.1 | Correct path: `aya_obj::generated::bpf_insn` (NOT `linux_bpf::bpf_insn`) | Resolved |
| `relocate_maps` API too complex to call externally | `patch_elf_map_fds()` patches map FDs directly into ELF bytes pre-parse, removing need for `relocate_maps` | Resolved |
| Plan claimed 3 kfunc offsets; actual count is 14 | `collect_kfunc_offsets` handles all R_BPF_64_32 kfunc sites by name; count verified via readelf | Resolved |
| `bpf_xdp_adjust_*` cannot be patched to src_reg=2 | Filter excludes non-module kfuncs by name via `RELAY_MODULE_KFUNCS` constant | Resolved |
| `Array::map()` resolves to `Iterator::map()` not `&MapData` accessor | `map()` is from `IterableMap` trait - must `use aya::maps::IterableMap` to bring it in scope | Resolved |
| `bpf.rs` included in both lib and bin crates via separate `mod` declarations | Added `mod kfunc;` to `src/main.rs` so bin crate resolves `crate::kfunc` used in `bpf.rs` | Resolved |

## Next Steps

1. ~~**High:** Create `relay-xdp/src/kfunc.rs`~~ **DONE** - 884 lines, builds clean, 2 tests pass.

2. ~~**High:** Modify `relay-xdp/src/bpf.rs`~~ **DONE** - Full 10-step kfunc flow, Drop impl, IterableMap, 21/21 tests pass, release build clean.

3. ~~**High:** Add `aya-obj = "0.2"` as direct dependency~~ **DONE**
   - Also added `object = { version = "0.36", features = ["read"] }` as direct dep.

4. ~~**High:** Add `pub mod kfunc;` to `relay-xdp/src/lib.rs`~~ **DONE**

5. ~~**High:** Build + test~~ **DONE** - `cargo build --release` clean, 21/21 tests pass.

6. **High:** Tag `v0.1.0-alpha.5`, push, deploy to staging, verify `bpftool prog list`
   shows `relay_xdp` and module kfuncs resolve.

7. ~~**Medium:** `Drop` impl for `BpfContext`~~ **DONE** - closes `link_fd` then `prog_fd`.

8. ~~**Low:** Add unit test for `patch_elf_skip_kfuncs`~~ **DONE** - `test_patch_elf_skip_kfuncs_with_real_elf` verifies against actual ELF.

## Files Changed

| Status | File | Notes |
|--------|------|-------|
| A | `relay-xdp/src/kfunc.rs` | Created, 884 lines, clean build |
| M | `relay-xdp/src/bpf.rs` | Done - full kfunc loader, Drop impl, removed aya XDP attach |
| M | `relay-xdp/src/lib.rs` | Done - added `pub mod kfunc;` |
| M | `relay-xdp/src/main.rs` | Done - added `mod kfunc;` for bin crate resolution |
| M | `relay-xdp/Cargo.toml` | Done - added `aya-obj = "0.2"`, `object = "0.36"` |
| M | `ansible/playbooks/group_vars/all.yml` | Pending - bump `relay_version` to `v0.1.0-alpha.5` |
