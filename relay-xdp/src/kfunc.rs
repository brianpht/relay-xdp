//! kfunc loader - patches module kfunc relocations in BPF ELF, loads XDP program
//! via raw BPF syscall with fd_array for module BTF resolution.
//!
//! Background: bpf-linker emits module kfunc calls as BPF_PSEUDO_CALL (src_reg=1)
//! with imm=-1 and an R_BPF_64_32 ELF relocation. aya-obj does not understand these
//! and fails in relocate_calls(). Standard BPF helpers (bpf_xdp_adjust_head/tail)
//! are also emitted the same way and fail for the same reason. This module:
//!   1. Patches the ELF to mark kfunc call sites as BPF_PSEUDO_KFUNC_CALL (src_reg=2)
//!      so aya-obj skips them in relocate_calls().
//!   2. Patches the ELF to resolve standard BPF helper calls: src_reg=0, imm=helper_id.
//!      With src_reg=0, insn_is_call() returns false and aya-obj skips them too.
//!   3. Applies actual map FD values directly into the ELF bytes before the second
//!      aya_obj parse, avoiding the need to call relocate_maps().
//!   4. Calls aya_obj::Object::relocate_calls() to inline .text helpers (memset).
//!   5. Patches kfunc instructions with the correct BTF type IDs from the kernel module.
//!   6. Loads via raw BPF_PROG_LOAD syscall with fd_array pointing to module BTF FD.
//!   7. Attaches via raw BPF_LINK_CREATE syscall.

use anyhow::{anyhow, bail, Context, Result};
use aya_obj::Object as AyaObj;
use object::{Object as ElfTrait, ObjectSection, ObjectSymbol};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// ELF relocation type constants (BPF-specific)
// ---------------------------------------------------------------------------

/// R_BPF_64_32 - used for kfunc calls and BPF helper calls.
const R_BPF_64_32: u32 = 10;

/// R_BPF_64_64 - used for BPF map loads (BPF_LD_IMM64).
const R_BPF_64_64: u32 = 1;

// ---------------------------------------------------------------------------
// BPF instruction constants
// ---------------------------------------------------------------------------

/// BPF_PSEUDO_KFUNC_CALL src_reg value - signals a kernel module kfunc call.
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

/// BPF_JMP | BPF_CALL opcode (0x85) - identifies call instructions.
const BPF_CALL_OPCODE: u8 = 0x85;

/// BPF_LD | BPF_IMM | BPF_DW opcode (0x18) - identifies 64-bit immediate loads (map FDs).
const BPF_LD_IMM64_OPCODE: u8 = 0x18;

/// BPF_PSEUDO_MAP_FD src_reg - marks map FD load instructions pre-relocation (used in verification).
#[allow(dead_code)]
const BPF_PSEUDO_MAP_FD: u8 = 1;

/// BPF instruction size in bytes.
const BPF_INSN_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// BPF syscall command numbers (x86_64 Linux)
// ---------------------------------------------------------------------------

const SYS_BPF: i64 = 321;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_BTF_GET_FD_BY_ID: u32 = 19;
const BPF_BTF_GET_NEXT_ID: u32 = 23;
const BPF_LINK_CREATE: u32 = 28;

// ---------------------------------------------------------------------------
// BPF program / attach types
// ---------------------------------------------------------------------------

const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_XDP: u32 = 37;

// ---------------------------------------------------------------------------
// Step 1: collect kfunc relocation offsets from ELF
// ---------------------------------------------------------------------------

/// Parses `.relxdp` section in the BPF ELF and returns a map of
/// `xdp_section_byte_offset -> kfunc_name` for all R_BPF_64_32 relocations
/// whose symbol name is in `kfunc_names`.
///
/// Only entries with symbol names matching `kfunc_names` are returned.
/// Standard BPF helpers (bpf_xdp_adjust_head etc.) are intentionally excluded
/// because they are NOT in kfunc_names and aya-obj handles them separately.
pub fn collect_kfunc_offsets(elf: &[u8], kfunc_names: &[&str]) -> Result<HashMap<u64, String>> {
    let file = object::File::parse(elf).context("ELF parse failed in collect_kfunc_offsets")?;

    // Build symbol-index -> name map, limited to names we care about.
    let mut sym_index_to_name: HashMap<usize, String> = HashMap::new();
    for sym in file.symbols() {
        if let Ok(name) = sym.name() {
            if kfunc_names.contains(&name) {
                sym_index_to_name.insert(sym.index().0, name.to_owned());
            }
        }
    }

    // Parse .relxdp raw bytes as SHT_REL entries (16 bytes each):
    //   r_offset: u64 (little-endian) - byte offset within xdp section
    //   r_info:   u64 (little-endian) - high 32 bits = sym index, low 32 bits = reloc type
    let relxdp = file
        .section_by_name(".relxdp")
        .context(".relxdp section not found in BPF ELF")?;
    let data = relxdp.data().context("failed to read .relxdp data")?;

    let entry_count = data.len() / 16;
    let mut result = HashMap::new();

    for i in 0..entry_count {
        let base = i * 16;
        let r_offset = u64::from_le_bytes(data[base..base + 8].try_into().expect("8 bytes"));
        let r_info = u64::from_le_bytes(data[base + 8..base + 16].try_into().expect("8 bytes"));
        let r_type = (r_info & 0xffff_ffff) as u32;
        let r_sym = (r_info >> 32) as usize;

        if r_type != R_BPF_64_32 {
            continue;
        }

        if let Some(name) = sym_index_to_name.get(&r_sym) {
            result.insert(r_offset, name.clone());
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Step 2: patch ELF kfunc call sites (src_reg 1 -> 2)
// ---------------------------------------------------------------------------

/// Patches kfunc call instructions in the `xdp` section of the ELF bytes.
///
/// For each byte offset in `kfunc_offsets`, changes the `src_reg` nibble of
/// the BPF instruction from 1 (BPF_PSEUDO_CALL) to 2 (BPF_PSEUDO_KFUNC_CALL).
/// After this patch, aya-obj's `relocate_calls()` will SKIP these instructions
/// (it only inlines src_reg=1 calls).
///
/// BPF instruction byte layout:
///   byte 0: opcode
///   byte 1: dst_reg (low nibble) | src_reg (high nibble)
///   bytes 2-3: offset (i16)
///   bytes 4-7: imm (i32)
pub fn patch_elf_skip_kfuncs(elf: &[u8], kfunc_offsets: &HashMap<u64, String>) -> Result<Vec<u8>> {
    let mut patched = elf.to_vec();

    let file = object::File::parse(elf).context("ELF parse failed in patch_elf_skip_kfuncs")?;
    let xdp_section = file
        .section_by_name("xdp")
        .context("xdp section not found in BPF ELF")?;
    let (xdp_file_offset, _xdp_size) = xdp_section
        .file_range()
        .context("xdp section has no file range")?;
    let xdp_file_offset = xdp_file_offset as usize;

    for (insn_offset, name) in kfunc_offsets {
        // byte 1 of the instruction = regs byte
        let regs_file_pos = xdp_file_offset + *insn_offset as usize + 1;
        if regs_file_pos >= patched.len() {
            bail!("kfunc {} offset 0x{:x} out of bounds", name, insn_offset);
        }

        let regs_byte = patched[regs_file_pos];
        // Verify opcode at byte 0
        let opcode = patched[xdp_file_offset + *insn_offset as usize];
        if opcode != BPF_CALL_OPCODE {
            bail!(
                "kfunc {} at offset 0x{:x}: expected call opcode 0x{:02x}, got 0x{:02x}",
                name,
                insn_offset,
                BPF_CALL_OPCODE,
                opcode
            );
        }
        // Verify src_reg is currently 1 (high nibble of regs_byte = 0x10)
        let src_reg = (regs_byte >> 4) & 0x0f;
        if src_reg != 1 {
            bail!(
                "kfunc {} at 0x{:x}: expected src_reg=1, got src_reg={}",
                name,
                insn_offset,
                src_reg
            );
        }
        // Change src_reg nibble from 1 to 2: 0x10 -> 0x20, 0x11 -> 0x21, etc.
        patched[regs_file_pos] = (regs_byte & 0x0f) | (BPF_PSEUDO_KFUNC_CALL << 4);
    }

    Ok(patched)
}

// ---------------------------------------------------------------------------
// Step 3: patch ELF map FD values directly (avoids needing relocate_maps)
// ---------------------------------------------------------------------------

/// Applies real BPF map FD values into BPF_LD_IMM64 instructions in the ELF bytes.
///
/// Parses R_BPF_64_64 entries from `.relxdp` to find map load instruction positions,
/// then writes the actual FD value into the imm field of each instruction.
///
/// This replaces `aya_obj::Object::relocate_maps()` - by patching the raw ELF bytes
/// before the second `aya_obj::Object::parse()`, we avoid having to call
/// `relocate_maps()` with its complex signature.
///
/// BPF_LD_IMM64 encoding (16 bytes = 2 instructions):
///   insn[0]: { code=0x18, regs=(dst<<0 | BPF_PSEUDO_MAP_FD<<4), off=0, imm=fd }
///   insn[1]: { code=0x00, regs=0, off=0, imm=0 }
pub fn patch_elf_map_fds(elf: &[u8], map_fds: &HashMap<String, i32>) -> Result<Vec<u8>> {
    let mut patched = elf.to_vec();

    let file = object::File::parse(elf).context("ELF parse failed in patch_elf_map_fds")?;

    // Build symbol-index -> map_name map.
    let mut sym_index_to_map: HashMap<usize, String> = HashMap::new();
    for sym in file.symbols() {
        if let Ok(name) = sym.name() {
            if map_fds.contains_key(name) {
                sym_index_to_map.insert(sym.index().0, name.to_owned());
            }
        }
    }

    let xdp_section = file
        .section_by_name("xdp")
        .context("xdp section not found")?;
    let (xdp_file_offset, _) = xdp_section
        .file_range()
        .context("xdp section has no file range")?;
    let xdp_file_offset = xdp_file_offset as usize;

    let relxdp = file
        .section_by_name(".relxdp")
        .context(".relxdp section not found")?;
    let data = relxdp.data().context("failed to read .relxdp")?;

    let entry_count = data.len() / 16;

    for i in 0..entry_count {
        let base = i * 16;
        let r_offset =
            u64::from_le_bytes(data[base..base + 8].try_into().expect("8 bytes")) as usize;
        let r_info = u64::from_le_bytes(data[base + 8..base + 16].try_into().expect("8 bytes"));
        let r_type = (r_info & 0xffff_ffff) as u32;
        let r_sym = (r_info >> 32) as usize;

        if r_type != R_BPF_64_64 {
            continue;
        }

        let map_name = match sym_index_to_map.get(&r_sym) {
            Some(n) => n,
            None => continue, // not a map we know about
        };

        let fd = match map_fds.get(map_name.as_str()) {
            Some(&fd) => fd,
            None => bail!("no FD found for map '{}'", map_name),
        };

        // Verify opcode at instruction start in the xdp section
        let insn_file_pos = xdp_file_offset + r_offset;
        if insn_file_pos + BPF_INSN_SIZE > patched.len() {
            bail!(
                "map reloc for {} at offset 0x{:x} out of bounds",
                map_name,
                r_offset
            );
        }
        let opcode = patched[insn_file_pos];
        if opcode != BPF_LD_IMM64_OPCODE {
            bail!(
                "map {} at 0x{:x}: expected BPF_LD_IMM64 opcode 0x18, got 0x{:02x}",
                map_name,
                r_offset,
                opcode
            );
        }

        // Write FD as little-endian i32 into bytes 4-7 (imm field of first insn)
        let imm_pos = insn_file_pos + 4;
        patched[imm_pos..imm_pos + 4].copy_from_slice(&fd.to_le_bytes());

        // Zero the imm of the second instruction (bytes 12-15, i.e. +8+4)
        let imm2_pos = insn_file_pos + BPF_INSN_SIZE + 4;
        if imm2_pos + 4 <= patched.len() {
            patched[imm2_pos..imm2_pos + 4].copy_from_slice(&0i32.to_le_bytes());
        }
    }

    Ok(patched)
}

// ---------------------------------------------------------------------------
// Step 3b: patch standard BPF helper calls (src_reg 1->0, imm -> helper ID)
// ---------------------------------------------------------------------------

/// BPF helper function IDs for helpers used in the relay XDP program.
/// Values from Linux kernel `include/uapi/linux/bpf.h` (stable, append-only ABI).
static BPF_HELPER_IDS: &[(&str, i32)] = &[("bpf_xdp_adjust_head", 44), ("bpf_xdp_adjust_tail", 65)];

/// Patches standard BPF helper call instructions in the `xdp` section.
///
/// bpf-linker emits helper calls (e.g., `bpf_xdp_adjust_head`) as
/// BPF_PSEUDO_CALL (src_reg=1, imm=-1) with an R_BPF_64_32 ELF relocation
/// against the helper name as an UNDEF (section=0) symbol.
///
/// aya-obj's `relocate_calls()` ONLY handles Text-section callees. UNDEF symbols
/// are filtered out, causing `relocate_calls()` to fall through to the pc-relative
/// callee branch, which computes `callee_address = instruction_offset` (a
/// self-reference that is not in `obj.functions`), and fails with
/// `UnknownFunction`.
///
/// After this patch:
/// - `src_reg = 0` (direct helper call, not BPF_PSEUDO_CALL=1)
/// - `imm = <kernel helper ID>` (stable Linux BPF helper number)
///
/// With `src_reg=0`, `insn_is_call()` in aya-obj returns false (it requires
/// `src_reg == BPF_PSEUDO_CALL == 1`). Combined with the UNDEF symbol's reloc
/// being filtered to `rel=None`, the condition `!is_call && rel.is_none()` is
/// true and aya-obj SKIPS these instructions entirely in `relocate_calls()`.
///
/// The kernel BPF verifier resolves `src_reg=0` calls via the imm (helper ID)
/// directly - no further patching needed.
pub fn patch_elf_bpf_helpers(elf: &[u8]) -> Result<Vec<u8>> {
    let mut patched = elf.to_vec();
    let file = object::File::parse(elf).context("ELF parse in patch_elf_bpf_helpers")?;

    // Build symbol-index -> helper_id map for known BPF helpers.
    let mut sym_to_helper_id: HashMap<usize, i32> = HashMap::new();
    for sym in file.symbols() {
        if let Ok(name) = sym.name() {
            for &(helper_name, helper_id) in BPF_HELPER_IDS {
                if name == helper_name {
                    sym_to_helper_id.insert(sym.index().0, helper_id);
                }
            }
        }
    }

    if sym_to_helper_id.is_empty() {
        return Ok(patched); // no known helpers referenced in this ELF
    }

    let xdp_section = file
        .section_by_name("xdp")
        .context("xdp section not found in patch_elf_bpf_helpers")?;
    let (xdp_file_offset, _) = xdp_section
        .file_range()
        .context("xdp section has no file range")?;
    let xdp_file_offset = xdp_file_offset as usize;

    let relxdp = file
        .section_by_name(".relxdp")
        .context(".relxdp section not found in patch_elf_bpf_helpers")?;
    let data = relxdp.data().context("failed to read .relxdp data")?;
    let entry_count = data.len() / 16;

    let mut patched_count = 0usize;

    for i in 0..entry_count {
        let base = i * 16;
        let r_offset =
            u64::from_le_bytes(data[base..base + 8].try_into().expect("8 bytes")) as usize;
        let r_info = u64::from_le_bytes(data[base + 8..base + 16].try_into().expect("8 bytes"));
        let r_type = (r_info & 0xffff_ffff) as u32;
        let r_sym = (r_info >> 32) as usize;

        if r_type != R_BPF_64_32 {
            continue;
        }

        let helper_id = match sym_to_helper_id.get(&r_sym) {
            Some(&id) => id,
            None => continue,
        };

        let insn_file_pos = xdp_file_offset + r_offset;
        if insn_file_pos + BPF_INSN_SIZE > patched.len() {
            bail!("BPF helper call at xdp+0x{:x} is out of bounds", r_offset);
        }

        // Verify BPF_CALL opcode at byte 0 of the instruction.
        let opcode = patched[insn_file_pos];
        if opcode != BPF_CALL_OPCODE {
            bail!(
                "expected BPF_CALL (0x85) at helper offset 0x{:x}, got 0x{:02x}",
                r_offset,
                opcode
            );
        }

        // Verify src_reg=1 (BPF_PSEUDO_CALL) - it should not have been patched yet.
        let regs_byte = patched[insn_file_pos + 1];
        let src_reg = (regs_byte >> 4) & 0x0f;
        if src_reg != 1 {
            bail!(
                "BPF helper at 0x{:x}: expected src_reg=1, got {}",
                r_offset,
                src_reg
            );
        }

        // Patch src_reg: clear high nibble of regs byte (dst_reg stays in low nibble).
        // src_reg=0 = direct helper call (not BPF_PSEUDO_CALL).
        patched[insn_file_pos + 1] = regs_byte & 0x0f;

        // Patch imm: write helper ID as little-endian i32 at bytes 4-7.
        patched[insn_file_pos + 4..insn_file_pos + 8].copy_from_slice(&helper_id.to_le_bytes());

        patched_count += 1;
    }

    log::debug!(
        "patch_elf_bpf_helpers: patched {} BPF helper call site(s)",
        patched_count
    );

    Ok(patched)
}

// ---------------------------------------------------------------------------
// Step 4: extract instructions via aya_obj (relocate_calls only)
// ---------------------------------------------------------------------------

/// Parses the fully-patched ELF (kfunc src_reg=2, map FDs applied) with
/// `aya_obj::Object`, runs `relocate_calls()` to inline .text helper functions
/// and resolve BPF helper IDs, then returns the flat instruction array for the
/// "relay_xdp" program.
///
/// kfunc instructions (src_reg=2) are skipped by aya_obj's relocate_calls.
/// Map FD instructions already have correct values from previous patches.
pub fn get_xdp_instructions(elf_patched: &[u8]) -> Result<Vec<aya_obj::generated::bpf_insn>> {
    let mut obj =
        AyaObj::parse(elf_patched).map_err(|e| anyhow!("aya_obj::Object::parse failed: {}", e))?;

    // Compute text_sections: section indices whose names start with ".text"
    // These are inlined BPF subroutines (e.g., memset in .text section).
    let text_sections: HashSet<usize> = {
        let elf_file = object::File::parse(elf_patched)
            .context("ELF parse for text_sections detection failed")?;
        elf_file
            .sections()
            .filter(|s| {
                s.name()
                    .map(|n| n == ".text" || n.starts_with(".text."))
                    .unwrap_or(false)
            })
            .map(|s| s.index().0)
            .collect()
    };

    // relocate_calls() inlines .text subroutines, resolves BPF helper IDs,
    // and skips src_reg=2 instructions (our kfunc placeholders).
    obj.relocate_calls(&text_sections)
        .map_err(|e| anyhow!("aya_obj::Object::relocate_calls failed: {}", e))?;

    // Find the relay_xdp program entry to locate its function key.
    let prog = obj
        .programs
        .get("relay_xdp")
        .context("relay_xdp program not found in BPF object after relocate_calls")?;
    let func_key = prog.function_key();

    // Extract the fully flattened instruction array.
    let func = obj
        .functions
        .get(&func_key)
        .context("relay_xdp function not found in functions map")?;

    Ok(func.instructions.clone())
}

// ---------------------------------------------------------------------------
// Step 5: patch kfunc instructions (src_reg=2 stubs -> real BTF type IDs)
// ---------------------------------------------------------------------------

/// Patches kfunc placeholder instructions in the instruction array.
///
/// After `get_xdp_instructions()`, kfunc calls have:
///   src_reg=2, imm=-1 (placeholder), off=0
///
/// After this function, they have:
///   src_reg=2, imm=<btf_type_id>, off=<fd_array_idx>
///
/// Uses relative ordering: the Nth src_reg=2 instruction in the flattened
/// array corresponds to the Nth kfunc offset (sorted ascending by byte offset)
/// in the original xdp section. This is valid because:
/// - relocate_calls() only expands src_reg=1 BPF-to-BPF call sites
/// - src_reg=2 instructions pass through unmodified in relative order
pub fn patch_kfunc_instructions(
    insns: &mut [aya_obj::generated::bpf_insn],
    kfunc_offsets: &HashMap<u64, String>,
    btf_ids: &HashMap<String, u32>,
    fd_array_idx: u16,
) -> Result<()> {
    // Sort kfunc sites by byte offset to get stable ordering.
    let mut sorted_kfuncs: Vec<(u64, &str)> = kfunc_offsets
        .iter()
        .map(|(off, name)| (*off, name.as_str()))
        .collect();
    sorted_kfuncs.sort_by_key(|(off, _)| *off);

    // Collect indices of all src_reg=2 instructions in the flat array.
    let kfunc_insn_indices: Vec<usize> = insns
        .iter()
        .enumerate()
        .filter(|(_, insn)| insn.code == BPF_CALL_OPCODE && insn.src_reg() == BPF_PSEUDO_KFUNC_CALL)
        .map(|(i, _)| i)
        .collect();

    if kfunc_insn_indices.len() != sorted_kfuncs.len() {
        bail!(
            "kfunc count mismatch: ELF has {} kfunc relocs, flat insn array has {} src_reg=2 call sites",
            sorted_kfuncs.len(),
            kfunc_insn_indices.len()
        );
    }

    for (insn_idx, (_byte_offset, kfunc_name)) in
        kfunc_insn_indices.iter().zip(sorted_kfuncs.iter())
    {
        let btf_id = btf_ids.get(*kfunc_name).copied().ok_or_else(|| {
            anyhow!(
                "BTF type ID not found for kfunc '{}' - is relay_module.ko loaded?",
                kfunc_name
            )
        })?;

        let insn = &mut insns[*insn_idx];
        // src_reg=2 already set from patch_elf_skip_kfuncs, preserved through parse+relocate
        insn.off = fd_array_idx as i16;
        insn.imm = btf_id as i32;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6: find module BTF object by name
// ---------------------------------------------------------------------------

/// Finds the BTF object for the named kernel module by enumerating all loaded
/// BTF objects via BPF syscalls.
///
/// Returns `(btf_fd, raw_btf_bytes)` where:
/// - `btf_fd`: a file descriptor for the module's BTF object (caller must close)
/// - `raw_btf_bytes`: the raw BTF data section (for parsing kfunc type IDs)
///
/// Requires kernel 6.5+ with relay_module.ko loaded.
pub fn find_module_btf(module_name: &str) -> Result<(i32, Vec<u8>)> {
    let mut start_id: u32 = 0;

    loop {
        // BPF_BTF_GET_NEXT_ID: enumerate loaded BTF objects
        // bpf_attr layout: { start_id: u32, next_id: u32, open_flags: u32 }
        let mut attr = [0u32; 4];
        attr[0] = start_id; // start_id

        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_BTF_GET_NEXT_ID,
                attr.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of_val(&attr) as u32,
            )
        };

        if ret < 0 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::ENOENT {
                // No more BTF objects
                bail!(
                    "module BTF '{}' not found - is relay_module.ko loaded?",
                    module_name
                );
            }
            bail!("BPF_BTF_GET_NEXT_ID failed: errno {}", err);
        }

        let next_id = attr[1]; // next_id populated by kernel

        // BPF_BTF_GET_FD_BY_ID: get fd for this BTF object
        // bpf_attr layout: { btf_id: u32 }
        let mut fd_attr = [0u32; 4];
        fd_attr[0] = next_id;

        let btf_fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_BTF_GET_FD_BY_ID,
                fd_attr.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of_val(&fd_attr) as u32,
            )
        } as i32;

        if btf_fd < 0 {
            // FD gone between iterations - continue
            start_id = next_id;
            continue;
        }

        // BPF_OBJ_GET_INFO_BY_FD: get BTF name and data size
        // First call: btf=0, btf_size=0, name=ptr, name_len=64 -> fills name and btf_size
        let mut name_buf = [0u8; 64];
        let btf_size = get_btf_info(btf_fd, &mut name_buf)?;

        let found_name = std::ffi::CStr::from_bytes_until_nul(&name_buf)
            .unwrap_or_default()
            .to_string_lossy();

        if found_name != module_name {
            unsafe { libc::close(btf_fd) };
            start_id = next_id;
            continue;
        }

        // Found the module - fetch the raw BTF bytes
        log::info!(
            "find_module_btf: found '{}' BTF id={} btf_size={} bytes",
            found_name,
            next_id,
            btf_size
        );
        if btf_size == 0 {
            bail!(
                "module BTF '{}' has btf_size=0 - module may not have BTF compiled in (missing CONFIG_DEBUG_INFO_BTF_MODULES or pahole)",
                module_name
            );
        }
        let mut btf_data = vec![0u8; btf_size as usize];
        get_btf_data(btf_fd, &mut btf_data)?;

        return Ok((btf_fd, btf_data));
    }
}

/// Helper: calls BPF_OBJ_GET_INFO_BY_FD to retrieve BTF name and data size.
/// Populates `name_buf` with the module short name (C string, null-terminated).
/// Returns the reported BTF data size in bytes.
fn get_btf_info(btf_fd: i32, name_buf: &mut [u8; 64]) -> Result<u32> {
    // bpf_btf_info layout:
    //   btf:      u64 (0)   - pointer to BTF data buffer (0 = don't fetch data yet)
    //   btf_size: u32 (8)   - on input: buf size; on output: actual BTF data size
    //   id:       u32 (12)
    //   name:     u64 (16)  - pointer to name buffer
    //   name_len: u32 (24)  - on input: buf size; on output: actual name length
    //   kernel_btf: u32 (28)
    let mut info = [0u8; 32];
    let name_ptr = name_buf.as_mut_ptr() as u64;
    info[16..24].copy_from_slice(&name_ptr.to_le_bytes()); // name ptr
    info[24..28].copy_from_slice(&(name_buf.len() as u32).to_le_bytes()); // name_len

    // bpf_attr for BPF_OBJ_GET_INFO_BY_FD:
    //   bpf_fd:   u32 (0)
    //   info_len: u32 (4)
    //   info:     u64 (8)  - pointer to info struct
    let mut attr = [0u8; 16];
    attr[0..4].copy_from_slice(&(btf_fd as u32).to_le_bytes());
    attr[4..8].copy_from_slice(&(info.len() as u32).to_le_bytes());
    let info_ptr = info.as_mut_ptr() as u64;
    attr[8..16].copy_from_slice(&info_ptr.to_le_bytes());

    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_GET_INFO_BY_FD,
            attr.as_mut_ptr() as *mut libc::c_void,
            attr.len() as u32,
        )
    };

    if ret < 0 {
        let err = unsafe { *libc::__errno_location() };
        bail!("BPF_OBJ_GET_INFO_BY_FD (name query) failed: errno {}", err);
    }

    let btf_size = u32::from_le_bytes(info[8..12].try_into().expect("4 bytes"));
    Ok(btf_size)
}

/// Helper: calls BPF_OBJ_GET_INFO_BY_FD to retrieve raw BTF data bytes.
fn get_btf_data(btf_fd: i32, buf: &mut Vec<u8>) -> Result<()> {
    let mut info = [0u8; 32];
    let btf_ptr = buf.as_mut_ptr() as u64;
    info[0..8].copy_from_slice(&btf_ptr.to_le_bytes()); // btf data ptr
    info[8..12].copy_from_slice(&(buf.len() as u32).to_le_bytes()); // btf_size (in = capacity)

    let mut attr = [0u8; 16];
    attr[0..4].copy_from_slice(&(btf_fd as u32).to_le_bytes());
    attr[4..8].copy_from_slice(&(info.len() as u32).to_le_bytes());
    let info_ptr = info.as_mut_ptr() as u64;
    attr[8..16].copy_from_slice(&info_ptr.to_le_bytes());

    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_GET_INFO_BY_FD,
            attr.as_mut_ptr() as *mut libc::c_void,
            attr.len() as u32,
        )
    };

    if ret < 0 {
        let err = unsafe { *libc::__errno_location() };
        bail!("BPF_OBJ_GET_INFO_BY_FD (data query) failed: errno {}", err);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7: parse BTF to find kfunc type IDs
// ---------------------------------------------------------------------------

/// Parses raw BTF bytes to find BTF_KIND_FUNC type IDs for the named functions.
///
/// Returns a map of `function_name -> btf_type_id` (1-based, sequential).
///
/// BTF format:
///   Header: magic(2) version(1) flags(1) hdr_len(4) type_off(4) type_len(4)
///           str_off(4) str_len(4)  = 24 bytes total
///   Type entries follow at offset hdr_len + type_off.
///   Each type base: name_off(4), info(4), size_or_type(4) = 12 bytes
///     kind = (info >> 24) & 0x1f
///     vlen = info & 0xffff
///   BTF_KIND_FUNC (kind=12) has 0 extra bytes - name_off indexes the string section.
pub fn parse_btf_func_ids(btf: &[u8], names: &[&str]) -> Result<HashMap<String, u32>> {
    if btf.len() < 24 {
        bail!("BTF data too short: {} bytes", btf.len());
    }

    let magic = u16::from_le_bytes(btf[0..2].try_into().expect("2 bytes"));
    if magic != 0xeb9f {
        bail!("BTF magic mismatch: expected 0xeb9f, got 0x{:04x}", magic);
    }

    let hdr_len = u32::from_le_bytes(btf[4..8].try_into().expect("4 bytes")) as usize;
    let type_off = u32::from_le_bytes(btf[8..12].try_into().expect("4 bytes")) as usize;
    let type_len = u32::from_le_bytes(btf[12..16].try_into().expect("4 bytes")) as usize;
    let str_off = u32::from_le_bytes(btf[16..20].try_into().expect("4 bytes")) as usize;
    let str_len = u32::from_le_bytes(btf[20..24].try_into().expect("4 bytes")) as usize;

    log::info!(
        "parse_btf_func_ids: btf_len={} hdr_len={} type_off={} type_len={} str_off={} str_len={}",
        btf.len(),
        hdr_len,
        type_off,
        type_len,
        str_off,
        str_len
    );

    let type_section_start = hdr_len + type_off;
    let type_section_end = type_section_start + type_len;
    let str_section_start = hdr_len + str_off;
    let str_section_end = str_section_start + str_len;

    if type_section_end > btf.len() || str_section_end > btf.len() {
        bail!(
            "BTF type/string section out of bounds: btf_len={} type={}..{} str={}..{}",
            btf.len(),
            type_section_start,
            type_section_end,
            str_section_start,
            str_section_end
        );
    }

    let type_bytes = &btf[type_section_start..type_section_end];
    let str_bytes = &btf[str_section_start..str_section_end];

    // Module BTF is split BTF (kernel 5.13+).  The raw bytes returned by
    // BPF_OBJ_GET_INFO_BY_FD contain only the module-local type and string
    // sections.  HOWEVER, name_off values in module type entries are indices
    // into the COMBINED string table (vmlinux strings || module strings), not
    // into the module-local string section alone.  Similarly, type IDs must be
    // the global IDs (vmlinux_nr_types + local_type_id) for the BPF verifier.
    //
    // We read /sys/kernel/btf/vmlinux to obtain:
    //   base_nr_types - number of types in vmlinux (type ID offset)
    //   base_str_len  - size of vmlinux string section (name_off adjustment)
    //   base_strings  - vmlinux string bytes (for resolving names from vmlinux)
    let (base_nr_types, base_str_len, base_strings) = load_vmlinux_btf_info().unwrap_or_else(|e| {
        log::warn!(
            "failed to load vmlinux BTF ({}); kfunc type IDs and string offsets may be wrong",
            e
        );
        (0, 0, Vec::new())
    });
    log::info!(
        "parse_btf_func_ids: vmlinux base_nr_types={} base_str_len={} -> module IDs start at {}",
        base_nr_types,
        base_str_len,
        base_nr_types + 1
    );

    let mut result = HashMap::new();
    let mut pos: usize = 0;
    let mut local_type_id: u32 = 1; // 1-based within this module's type section
    let mut func_count: u32 = 0;

    while pos + 12 <= type_bytes.len() {
        let raw_name_off =
            u32::from_le_bytes(type_bytes[pos..pos + 4].try_into().expect("4")) as usize;
        let info = u32::from_le_bytes(type_bytes[pos + 4..pos + 8].try_into().expect("4"));
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;

        // BTF_KIND_FUNC = 12 - function declaration (no extra bytes)
        if kind == 12 {
            func_count += 1;
            let global_type_id = base_nr_types + local_type_id;

            // Resolve the name from the appropriate string section.
            // name_off is a global offset into (vmlinux_strings || module_strings).
            let name_opt = if raw_name_off < base_str_len {
                // Name is in the vmlinux string section
                if raw_name_off < base_strings.len() {
                    std::ffi::CStr::from_bytes_until_nul(&base_strings[raw_name_off..])
                        .ok()
                        .map(|c| c.to_string_lossy().into_owned())
                } else {
                    None
                }
            } else {
                // Name is in the module-local string section
                let local_off = raw_name_off - base_str_len;
                if local_off < str_bytes.len() {
                    std::ffi::CStr::from_bytes_until_nul(&str_bytes[local_off..])
                        .ok()
                        .map(|c| c.to_string_lossy().into_owned())
                } else {
                    log::warn!(
                        "parse_btf_func_ids: FUNC local_id={} raw_name_off={} local_off={} out of str_bytes (len={}), base_str_len={}",
                        local_type_id, raw_name_off, local_off, str_bytes.len(), base_str_len
                    );
                    None
                }
            };

            if let Some(name) = name_opt {
                log::info!(
                    "parse_btf_func_ids: FUNC local_id={} global_id={} name='{}'",
                    local_type_id,
                    global_type_id,
                    name
                );
                if names.contains(&name.as_str()) {
                    result.insert(name, global_type_id);
                }
            }
        }

        let extra = btf_kind_extra_bytes(kind, vlen);
        log::debug!(
            "parse_btf_func_ids: pos={} kind={} vlen={} extra={} local_id={}",
            pos,
            kind,
            vlen,
            extra,
            local_type_id
        );
        pos += 12 + extra;
        local_type_id += 1;
    }

    log::info!(
        "parse_btf_func_ids: iterated {} types, found {} FUNC entries, matched {}/{}",
        local_type_id - 1,
        func_count,
        result.len(),
        names.len()
    );

    for name in names {
        if !result.contains_key(*name) {
            bail!(
                "BTF func '{}' not found in module BTF (base_nr_types={} base_str_len={} {} types {} FUNCs) - module may need rebuild",
                name, base_nr_types, base_str_len, local_type_id - 1, func_count
            );
        }
    }

    Ok(result)
}

/// Parses /sys/kernel/btf/vmlinux and returns:
///   (nr_types, str_len, str_bytes)
/// nr_types  - total number of types (used as base offset for module type IDs)
/// str_len   - total length of vmlinux string section (used as base offset for module name_off)
/// str_bytes - vmlinux string section bytes (for resolving names that live in vmlinux)
fn load_vmlinux_btf_info() -> Result<(u32, usize, Vec<u8>)> {
    let btf = std::fs::read("/sys/kernel/btf/vmlinux")
        .context("failed to read /sys/kernel/btf/vmlinux")?;

    if btf.len() < 24 {
        bail!("vmlinux BTF too short ({} bytes)", btf.len());
    }

    let hdr_len = u32::from_le_bytes(btf[4..8].try_into().expect("4")) as usize;
    let type_off = u32::from_le_bytes(btf[8..12].try_into().expect("4")) as usize;
    let type_len = u32::from_le_bytes(btf[12..16].try_into().expect("4")) as usize;
    let str_off = u32::from_le_bytes(btf[16..20].try_into().expect("4")) as usize;
    let str_len = u32::from_le_bytes(btf[20..24].try_into().expect("4")) as usize;

    let type_start = hdr_len + type_off;
    let type_end = type_start + type_len;
    let str_start = hdr_len + str_off;
    let str_end = str_start + str_len;

    if type_end > btf.len() || str_end > btf.len() {
        bail!("vmlinux BTF sections out of bounds (btf_len={})", btf.len());
    }

    let type_bytes = &btf[type_start..type_end];
    let str_bytes = btf[str_start..str_end].to_vec();

    // Count types by iterating the type section
    let mut pos = 0usize;
    let mut nr_types: u32 = 0;
    while pos + 12 <= type_bytes.len() {
        let info = u32::from_le_bytes(type_bytes[pos + 4..pos + 8].try_into().expect("4"));
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let extra = btf_kind_extra_bytes(kind, vlen);
        pos += 12 + extra;
        nr_types += 1;
    }

    Ok((nr_types, str_len, str_bytes))
}

/// Returns extra bytes after the 12-byte type base depending on BTF kind.
fn btf_kind_extra_bytes(kind: u32, vlen: usize) -> usize {
    match kind {
        1 => 4,             // BTF_KIND_INT: +4 bytes
        3 => 12,            // BTF_KIND_ARRAY: +12 bytes
        4 | 5 => vlen * 12, // BTF_KIND_STRUCT / UNION: +vlen*12
        6 => vlen * 8,      // BTF_KIND_ENUM: +vlen*8
        12 => 0,            // BTF_KIND_FUNC: +0
        13 => vlen * 8,     // BTF_KIND_FUNC_PROTO: +vlen*8
        14 => 4,            // BTF_KIND_VAR: +4
        15 => vlen * 12,    // BTF_KIND_DATASEC: +vlen*12
        17 => 4,            // BTF_KIND_DECL_TAG: +4
        19 => vlen * 12,    // BTF_KIND_ENUM64: +vlen*12
        _ => 0,             // all other kinds: no extra bytes
    }
}

// ---------------------------------------------------------------------------
// Step 8: load XDP program via raw BPF_PROG_LOAD syscall
// ---------------------------------------------------------------------------

/// Loads the XDP program via raw `bpf_prog_load` syscall, passing `fd_array`
/// pointing to `module_btf_fd` so the kernel can resolve module kfunc BTF IDs.
///
/// Returns the raw program file descriptor on success.
/// Caller is responsible for closing the fd when no longer needed.
///
/// `bpf_attr` fields used (from kernel union bpf_attr, BPF_PROG_LOAD variant):
///   offset  0: prog_type  (u32) = BPF_PROG_TYPE_XDP = 6
///   offset  4: insn_cnt   (u32)
///   offset  8: insns      (u64) = ptr to instruction array
///   offset 16: license    (u64) = ptr to "GPL\0"
///   offset 48: prog_name  ([u8;16]) (optional, for bpftool display)
///   offset 120: fd_array  (u64) = ptr to [module_btf_fd as u32]
pub fn raw_load_xdp(insns: &[aya_obj::generated::bpf_insn], module_btf_fd: i32) -> Result<i32> {
    // --- Debug: verify btf_fd is still valid right before the syscall ---
    let fcntl_check = unsafe { libc::fcntl(module_btf_fd, libc::F_GETFD) };
    log::info!(
        "raw_load_xdp: module_btf_fd={} fcntl(F_GETFD)={} (>=0 means valid)",
        module_btf_fd,
        fcntl_check
    );
    if fcntl_check < 0 {
        let e = unsafe { *libc::__errno_location() };
        log::error!(
            "raw_load_xdp: btf_fd {} is INVALID before BPF_PROG_LOAD! errno={}",
            module_btf_fd,
            e
        );
    }

    // Read kernel version to correlate with BPF ABI
    if let Ok(ver) = std::fs::read_to_string("/proc/version") {
        log::info!("raw_load_xdp: kernel = {}", ver.trim());
    }

    // Check what /proc/self/fd/<btf_fd> actually points to.
    // For a real BTF fd this should be "anon_inode:[btf]".
    // If it shows something different, the fd type is the root cause.
    let fd_link = std::fs::read_link(format!("/proc/self/fd/{}", module_btf_fd));
    log::info!(
        "raw_load_xdp: /proc/self/fd/{} -> {:?}",
        module_btf_fd,
        fd_link
    );

    // --- Debug: log instruction[0] and all src_reg=2 kfunc instructions ---
    if let Some(insn0) = insns.first() {
        log::info!(
            "raw_load_xdp: insns[0] code=0x{:02x} src_reg={} dst_reg={} off={} imm={}",
            insn0.code,
            insn0.src_reg(),
            insn0.dst_reg(),
            insn0.off,
            insn0.imm,
        );
    }
    let kfunc_insns: Vec<(usize, i16, i32)> = insns
        .iter()
        .enumerate()
        .filter(|(_, i)| i.code == BPF_CALL_OPCODE && i.src_reg() == BPF_PSEUDO_KFUNC_CALL)
        .map(|(idx, i)| (idx, i.off, i.imm))
        .collect();
    log::info!(
        "raw_load_xdp: {} kfunc instructions (src_reg=2): {:?}",
        kfunc_insns.len(),
        kfunc_insns
    );

    // --- Debug: enumerate open fds in /proc/self/fd ---
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        let fds: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        log::info!("raw_load_xdp: open fds = {:?}", fds);
    }

    // Build fd_array: single entry pointing to the module BTF fd.
    // Kernel interprets fd_array[insn.off - 1] as the BTF object fd.
    // For off=1 (our kfunc insns), kernel uses fd_array[0].
    let fd_array: [u32; 1] = [module_btf_fd as u32];
    log::info!(
        "raw_load_xdp: fd_array[0]={} (u32), addr=0x{:x}",
        fd_array[0],
        fd_array.as_ptr() as u64
    );

    let license = b"GPL\0";

    // Log buffer for verifier output (helps diagnose load failures).
    let mut log_buf = vec![0u8; 256 * 1024];

    // bpf_attr for BPF_PROG_LOAD - 152 bytes (padded to 8-byte boundary).
    // Fields written at byte offsets matching kernel struct layout.
    let mut attr = [0u8; 152];

    // prog_type: u32 at offset 0
    attr[0..4].copy_from_slice(&BPF_PROG_TYPE_XDP.to_le_bytes());
    // insn_cnt: u32 at offset 4
    attr[4..8].copy_from_slice(&(insns.len() as u32).to_le_bytes());
    // insns: u64 at offset 8
    attr[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_le_bytes());
    // license: u64 at offset 16
    attr[16..24].copy_from_slice(&(license.as_ptr() as u64).to_le_bytes());
    // log_level: u32 at offset 24 (1 = LOG_LEVEL_STATS)
    attr[24..28].copy_from_slice(&1u32.to_le_bytes());
    // log_size: u32 at offset 28
    attr[28..32].copy_from_slice(&(log_buf.len() as u32).to_le_bytes());
    // log_buf: u64 at offset 32
    attr[32..40].copy_from_slice(&(log_buf.as_mut_ptr() as u64).to_le_bytes());
    // prog_name: [u8;16] at offset 48 - "relay_xdp\0" for bpftool display
    let prog_name = b"relay_xdp\0";
    attr[48..48 + prog_name.len()].copy_from_slice(prog_name);
    // fd_array: u64 at offset 120 - pointer to our [module_btf_fd as u32] array
    attr[120..128].copy_from_slice(&(fd_array.as_ptr() as u64).to_le_bytes());

    let prog_fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_LOAD,
            attr.as_mut_ptr() as *mut libc::c_void,
            attr.len() as u32,
        )
    } as i32;

    if prog_fd < 0 {
        let err_no = unsafe { *libc::__errno_location() };
        // Retrieve verifier log for diagnostics
        let log_str = std::str::from_utf8(&log_buf)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim();
        if !log_str.is_empty() {
            bail!(
                "BPF_PROG_LOAD failed: errno {} - verifier log:\n{}",
                err_no,
                log_str
            );
        } else {
            bail!("BPF_PROG_LOAD failed: errno {}", err_no);
        }
    }

    Ok(prog_fd)
}

// ---------------------------------------------------------------------------
// Step 9: attach XDP program via raw BPF_LINK_CREATE syscall
// ---------------------------------------------------------------------------

/// XDP_FLAGS_SKB_MODE - use kernel generic (SKB-based) XDP instead of native
/// driver mode. Required for drivers that do not support native XDP
/// (e.g., ENA on t3.medium AWS instances).
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

/// Attaches the loaded XDP program to a network interface using `BPF_LINK_CREATE`.
///
/// Returns the link file descriptor. Closing this fd detaches the XDP program
/// from the interface. Keep it alive for the lifetime of the XDP attachment.
///
/// Tries native mode (flags=0) first. If the driver does not support native XDP
/// (EOPNOTSUPP), automatically retries with SKB (generic) mode.
/// This handles staging instances (t3.medium/ENA) that only support generic XDP.
///
/// `bpf_attr` for BPF_LINK_CREATE (XDP):
///   offset 0: prog_fd        (u32)
///   offset 4: target_ifindex (u32) - network interface index
///   offset 8: attach_type    (u32) = BPF_XDP = 37
///   offset 12: flags         (u32) = 0 (native) or XDP_FLAGS_SKB_MODE (2)
pub fn raw_create_xdp_link(prog_fd: i32, ifindex: u32) -> Result<i32> {
    for &flags in &[0u32, XDP_FLAGS_SKB_MODE] {
        let mut attr = [0u8; 64];

        // prog_fd at offset 0
        attr[0..4].copy_from_slice(&(prog_fd as u32).to_le_bytes());
        // target_ifindex at offset 4
        attr[4..8].copy_from_slice(&ifindex.to_le_bytes());
        // attach_type at offset 8
        attr[8..12].copy_from_slice(&BPF_XDP.to_le_bytes());
        // flags at offset 12
        attr[12..16].copy_from_slice(&flags.to_le_bytes());

        let link_fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_LINK_CREATE,
                attr.as_mut_ptr() as *mut libc::c_void,
                attr.len() as u32,
            )
        } as i32;

        if link_fd >= 0 {
            if flags == XDP_FLAGS_SKB_MODE {
                log::info!(
                    "XDP attached in SKB (generic) mode - native mode not supported by driver"
                );
            }
            return Ok(link_fd);
        }

        let err_no = unsafe { *libc::__errno_location() };

        // EOPNOTSUPP: driver has ndo_bpf but XDP native setup failed (e.g., ENA on
        // t3.medium). Fall through to retry with SKB mode.
        if flags == 0 && err_no == libc::EOPNOTSUPP {
            log::warn!(
                "Native XDP mode not supported (EOPNOTSUPP), retrying with SKB (generic) mode"
            );
            continue;
        }

        bail!(
            "BPF_LINK_CREATE (XDP) failed for ifindex {} flags={}: errno {}",
            ifindex,
            flags,
            err_no
        );
    }

    unreachable!("BPF_LINK_CREATE loop exhausted");
}

// ---------------------------------------------------------------------------
// Module kfunc constant: list of kfunc names exported by relay_module.ko
// ---------------------------------------------------------------------------

/// kfunc names exported by relay_module.ko.
/// These are the only extern calls that require module BTF ID resolution.
pub const RELAY_MODULE_KFUNCS: &[&str] =
    &["bpf_relay_sha256", "bpf_relay_xchacha20poly1305_decrypt"];

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btf_kind_extra_bytes() {
        assert_eq!(btf_kind_extra_bytes(1, 0), 4); // INT
        assert_eq!(btf_kind_extra_bytes(3, 0), 12); // ARRAY
        assert_eq!(btf_kind_extra_bytes(4, 3), 36); // STRUCT, vlen=3 -> 3*12
        assert_eq!(btf_kind_extra_bytes(6, 4), 32); // ENUM, vlen=4 -> 4*8
        assert_eq!(btf_kind_extra_bytes(12, 0), 0); // FUNC - our target
        assert_eq!(btf_kind_extra_bytes(13, 2), 16); // FUNC_PROTO, vlen=2 -> 2*8
        assert_eq!(btf_kind_extra_bytes(17, 0), 4); // DECL_TAG
    }

    #[test]
    fn test_patch_elf_skip_kfuncs_with_real_elf() {
        // Use the actual relay_xdp_rust.o in workspace root if present.
        let elf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../relay_xdp_rust.o");
        let elf = match std::fs::read(elf_path) {
            Ok(b) => b,
            Err(_) => return, // skip test if ELF not present
        };

        let kfunc_offsets =
            collect_kfunc_offsets(&elf, RELAY_MODULE_KFUNCS).expect("collect_kfunc_offsets failed");
        assert!(!kfunc_offsets.is_empty(), "no kfunc offsets found");

        // All entries should be bpf_relay_* names
        for name in kfunc_offsets.values() {
            assert!(
                RELAY_MODULE_KFUNCS.contains(&name.as_str()),
                "unexpected kfunc name: {}",
                name
            );
        }

        let patched =
            patch_elf_skip_kfuncs(&elf, &kfunc_offsets).expect("patch_elf_skip_kfuncs failed");

        // Verify patched bytes: at each kfunc offset, byte 1 should have src_reg nibble = 2
        let file = object::File::parse(elf.as_slice()).unwrap();
        let xdp = file.section_by_name("xdp").unwrap();
        let (xdp_offset, _) = xdp.file_range().unwrap();
        let xdp_offset = xdp_offset as usize;

        for (offset, _name) in &kfunc_offsets {
            let regs_pos = xdp_offset + *offset as usize + 1;
            let src_reg = (patched[regs_pos] >> 4) & 0x0f;
            assert_eq!(src_reg, 2, "expected src_reg=2 at offset 0x{:x}", offset);
        }
    }
}
