//! BPF loader - load/attach XDP program, manage BPF maps.
//! Port of `relay_bpf.c`.
//!
//! Loading flow:
//!
//! 1. Read ELF bytes from disk.
//! 2. Patch kfunc call sites: src_reg 1->2 so aya-obj skips them.
//! 3. Patch BPF helper calls: src_reg 1->0, imm -> kernel helper ID
//!    (aya-obj filters UNDEF-symbol relocations and falls through to a
//!    pc-relative lookup that fails with UnknownFunction without this).
//! 4. Ebpf::load(patched) to create all 6 maps (aya manages map FDs).
//! 5. Extract raw map FDs via typed-map API.
//! 6. Patch map FD values directly into ELF bytes (bypass relocate_maps).
//! 7. aya_obj second parse + relocate_calls => flat instruction Vec.
//! 8. Find relay_module.ko BTF, parse kfunc BTF type IDs.
//! 9. Patch kfunc instructions with BTF IDs and fd_array index.
//! 10. raw BPF_PROG_LOAD with fd_array -> prog_fd.
//! 11. raw BPF_LINK_CREATE -> link_fd (holds XDP attachment for NIC lifetime).

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, IterableMap, MapData, PerCpuArray};
use aya::Ebpf;
use log::info;
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

use relay_xdp_common::*;

use crate::kfunc::{
    collect_kfunc_offsets, find_module_btf, get_xdp_instructions, parse_btf_func_ids,
    patch_elf_bpf_helpers, patch_elf_map_fds, patch_elf_skip_kfuncs, patch_kfunc_instructions,
    raw_create_xdp_link, raw_load_xdp, RELAY_MODULE_KFUNCS,
};

/// Holds the loaded BPF program and map handles.
///
/// `bpf` owns all 6 map FDs (via aya).
/// `prog_fd` and `link_fd` are raw kernel FDs from the manual load path.
/// Dropping `BpfContext` closes `link_fd` first (detaches XDP from NIC),
/// then `prog_fd`. `bpf` is dropped last, closing map FDs.
pub struct BpfContext {
    pub bpf: Ebpf,
    prog_fd: i32,
    link_fd: i32,
    /// Stored for future Prometheus /metrics exposure.
    #[allow(dead_code)]
    pub interface_index: u32,
}

impl Drop for BpfContext {
    fn drop(&mut self) {
        // Close link_fd first: this detaches the XDP program from the NIC.
        // Then close prog_fd. Map FDs are closed when `bpf` is dropped.
        if self.link_fd >= 0 {
            unsafe { libc::close(self.link_fd) };
        }
        if self.prog_fd >= 0 {
            unsafe { libc::close(self.prog_fd) };
        }
    }
}

impl BpfContext {
    /// Find the network interface matching the relay address.
    fn find_interface(
        relay_public_address: u32,
        relay_internal_address: u32,
    ) -> Result<(String, u32)> {
        let addrs = nix_ifaddrs()?;
        for (name, addr) in &addrs {
            if *addr == relay_public_address || *addr == relay_internal_address {
                let idx = interface_name_to_index(name)?;
                return Ok((name.clone(), idx));
            }
        }
        anyhow::bail!(
            "could not find network interface matching relay address {}",
            crate::platform::format_address(relay_public_address, 0)
        );
    }

    /// Load the XDP program from an ELF object file and attach to the NIC.
    ///
    /// Implements the full kfunc loader flow described in the module doc.
    /// Requires root and relay_module.ko to be loaded.
    pub fn init(
        xdp_obj_path: &Path,
        relay_public_address: u32,
        relay_internal_address: u32,
    ) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("this program must be run as root");
        }

        let (iface_name, iface_index) =
            Self::find_interface(relay_public_address, relay_internal_address)?;
        info!("Found network interface: '{iface_name}' (index {iface_index})");

        cleanup_existing_xdp(&iface_name);
        cleanup_bpf_pins();

        // --- Step 1: Read ELF ---
        info!("Loading relay_xdp from {}", xdp_obj_path.display());
        let elf_bytes = std::fs::read(xdp_obj_path)
            .with_context(|| format!("failed to read BPF ELF from {}", xdp_obj_path.display()))?;

        // --- Step 2: Patch kfunc call sites in all code sections (xdp + .text*) ---
        // src_reg 1 -> 2 and encode kfunc index in imm. Walks .relxdp + .rel.text*
        // because BPF subroutines marked #[inline(never)] (e.g. verify_ping_token)
        // live in .text and contain kfunc calls of their own.
        let kfunc_sites = collect_kfunc_offsets(&elf_bytes, RELAY_MODULE_KFUNCS)
            .context("failed to collect kfunc offsets from ELF")?;
        info!(
            "Found {} kfunc call sites in ELF for {:?}",
            kfunc_sites.len(),
            RELAY_MODULE_KFUNCS
        );
        let patched_v1 = patch_elf_skip_kfuncs(&elf_bytes, RELAY_MODULE_KFUNCS)
            .context("failed to patch kfunc src_reg in ELF")?;

        // --- Step 2b: Patch standard BPF helper calls (src_reg 1->0, imm -> helper ID) ---
        // bpf-linker emits bpf_xdp_adjust_head/tail as BPF_PSEUDO_CALL (src_reg=1, imm=-1)
        // with R_BPF_64_32 relocations against UNDEF symbols.  aya-obj's relocate_calls()
        // filters UNDEF-symbol relocations and then tries a self-referential pc-relative
        // lookup that fails with UnknownFunction.  Pre-patching to src_reg=0 makes
        // insn_is_call() return false, so aya-obj skips them entirely.
        let patched_v1 = patch_elf_bpf_helpers(&patched_v1)
            .context("failed to patch BPF helper calls in ELF")?;

        // --- Step 3: Ebpf::load creates all 6 maps ---
        let mut bpf = Ebpf::load(&patched_v1).with_context(|| {
            "Ebpf::load failed - kfunc helpers should be skipped now".to_string()
        })?;

        // --- Step 4: Extract raw map FDs via typed-map API ---
        let map_fds = collect_map_fds(&mut bpf)?;
        info!("Collected {} map FDs from aya", map_fds.len());

        // --- Step 5: Patch map FD values into ELF bytes ---
        let patched_v2 =
            patch_elf_map_fds(&patched_v1, &map_fds).context("failed to patch map FDs into ELF")?;

        // --- Step 6: Second parse + relocate_calls -> flat instruction Vec ---
        let mut insns =
            get_xdp_instructions(&patched_v2).context("failed to get XDP instructions")?;
        info!("XDP program: {} instructions after relocation", insns.len());

        // --- Step 7: Find relay_module.ko BTF and parse kfunc type IDs ---
        let (btf_fd, btf_bytes) =
            find_module_btf("relay_module").context("relay_module BTF not found")?;
        info!("Found relay_module BTF (fd={})", btf_fd);

        let btf_ids = parse_btf_func_ids(&btf_bytes, RELAY_MODULE_KFUNCS)
            .context("failed to parse BTF func IDs")?;
        info!("BTF type IDs: {:?}", btf_ids);

        // --- Step 8: Patch kfunc instructions with BTF IDs ---
        // Identifies each src_reg=2 call by reading the kfunc index encoded in
        // imm during step 2 - robust against aya's relocation reordering.
        patch_kfunc_instructions(
            &mut insns,
            RELAY_MODULE_KFUNCS,
            &btf_ids,
            1, // fd_array index 1: kernel reads fd_array[off] = fd_array[1] = btf_fd
        )
        .context("failed to patch kfunc instructions")?;

        // --- Step 9: BPF_PROG_LOAD with fd_array ---
        let prog_fd = raw_load_xdp(&insns, btf_fd).context("BPF_PROG_LOAD failed")?;
        info!("Loaded XDP program (prog_fd={})", prog_fd);

        // btf_fd no longer needed after prog is loaded
        unsafe { libc::close(btf_fd) };

        // --- Step 10: BPF_LINK_CREATE to attach XDP to NIC ---
        let link_fd =
            raw_create_xdp_link(prog_fd, iface_index).context("BPF_LINK_CREATE (XDP) failed")?;
        info!(
            "Attached XDP program to '{}' (link_fd={})",
            iface_name, link_fd
        );

        Ok(Self {
            bpf,
            prog_fd,
            link_fd,
            interface_index: iface_index,
        })
    }

    /// Get the config_map as a writable Array.
    pub fn config_map(&mut self) -> Result<Array<&mut MapData, RelayConfig>> {
        let map = self
            .bpf
            .map_mut("config_map")
            .context("config_map not found")?;
        Array::try_from(map).context("config_map is not an Array")
    }

    /// Get the state_map as a writable Array.
    pub fn state_map(&mut self) -> Result<Array<&mut MapData, RelayState>> {
        let map = self
            .bpf
            .map_mut("state_map")
            .context("state_map not found")?;
        Array::try_from(map).context("state_map is not an Array")
    }

    /// Get the stats_map as a PerCpuArray.
    pub fn stats_map(&mut self) -> Result<PerCpuArray<&mut MapData, RelayStats>> {
        let map = self
            .bpf
            .map_mut("stats_map")
            .context("stats_map not found")?;
        PerCpuArray::try_from(map).context("stats_map is not a PerCpuArray")
    }

    /// Get the relay_map as a writable HashMap.
    pub fn relay_map(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u64>> {
        let map = self
            .bpf
            .map_mut("relay_map")
            .context("relay_map not found")?;
        AyaHashMap::try_from(map).context("relay_map is not a HashMap")
    }

    /// Get the session_map as a writable HashMap.
    pub fn session_map(&mut self) -> Result<AyaHashMap<&mut MapData, SessionKey, SessionData>> {
        let map = self
            .bpf
            .map_mut("session_map")
            .context("session_map not found")?;
        AyaHashMap::try_from(map).context("session_map is not a HashMap")
    }

    /// Get the whitelist_map as a writable HashMap.
    pub fn whitelist_map(
        &mut self,
    ) -> Result<AyaHashMap<&mut MapData, WhitelistKey, WhitelistValue>> {
        let map = self
            .bpf
            .map_mut("whitelist_map")
            .context("whitelist_map not found")?;
        AyaHashMap::try_from(map).context("whitelist_map is not a HashMap")
    }
}

// ---------------------------------------------------------------------------
// Map FD extraction helper
// ---------------------------------------------------------------------------

/// Extracts raw file descriptor integers for all 6 BPF maps from aya.
///
/// Uses the typed-map API (Array/PerCpuArray/HashMap) to convert each `&mut Map`
/// to a typed wrapper, then accesses `.map().fd()` to get the raw fd integer.
/// Each typed-map borrow is immediately dropped, so the borrows do not overlap.
fn collect_map_fds(bpf: &mut Ebpf) -> Result<HashMap<String, i32>> {
    let mut fds = HashMap::new();

    // config_map - Array<_, RelayConfig>
    {
        let arr: Array<&mut MapData, RelayConfig> =
            Array::try_from(bpf.map_mut("config_map").context("config_map not found")?)
                .context("config_map type error")?;
        fds.insert("config_map".to_string(), arr.map().fd().as_fd().as_raw_fd());
    }

    // state_map - Array<_, RelayState>
    {
        let arr: Array<&mut MapData, RelayState> =
            Array::try_from(bpf.map_mut("state_map").context("state_map not found")?)
                .context("state_map type error")?;
        fds.insert("state_map".to_string(), arr.map().fd().as_fd().as_raw_fd());
    }

    // stats_map - PerCpuArray<_, RelayStats>
    {
        let arr: PerCpuArray<&mut MapData, RelayStats> =
            PerCpuArray::try_from(bpf.map_mut("stats_map").context("stats_map not found")?)
                .context("stats_map type error")?;
        fds.insert("stats_map".to_string(), arr.map().fd().as_fd().as_raw_fd());
    }

    // relay_map - HashMap<_, u64, u64>
    {
        let hm: AyaHashMap<&mut MapData, u64, u64> =
            AyaHashMap::try_from(bpf.map_mut("relay_map").context("relay_map not found")?)
                .context("relay_map type error")?;
        fds.insert("relay_map".to_string(), hm.map().fd().as_fd().as_raw_fd());
    }

    // session_map - HashMap<_, SessionKey, SessionData>
    {
        let hm: AyaHashMap<&mut MapData, SessionKey, SessionData> = AyaHashMap::try_from(
            bpf.map_mut("session_map")
                .context("session_map not found")?,
        )
        .context("session_map type error")?;
        fds.insert("session_map".to_string(), hm.map().fd().as_fd().as_raw_fd());
    }

    // whitelist_map - HashMap<_, WhitelistKey, WhitelistValue>
    {
        let hm: AyaHashMap<&mut MapData, WhitelistKey, WhitelistValue> = AyaHashMap::try_from(
            bpf.map_mut("whitelist_map")
                .context("whitelist_map not found")?,
        )
        .context("whitelist_map type error")?;
        fds.insert(
            "whitelist_map".to_string(),
            hm.map().fd().as_fd().as_raw_fd(),
        );
    }

    Ok(fds)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Enumerate IPv4 interfaces and their host-order addresses.
fn nix_ifaddrs() -> Result<Vec<(String, u32)>> {
    let mut results = Vec::new();

    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            anyhow::bail!("getifaddrs failed");
        }

        let mut current = addrs;
        while !current.is_null() {
            let iface = &*current;
            if !iface.ifa_addr.is_null() && (*iface.ifa_addr).sa_family == libc::AF_INET as u16 {
                let sa = iface.ifa_addr as *const libc::sockaddr_in;
                let addr = u32::from_be((*sa).sin_addr.s_addr);
                let name = std::ffi::CStr::from_ptr(iface.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                results.push((name, addr));
            }
            current = iface.ifa_next;
        }

        libc::freeifaddrs(addrs);
    }

    Ok(results)
}

fn interface_name_to_index(name: &str) -> Result<u32> {
    let c_name = std::ffi::CString::new(name).context("invalid interface name")?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("if_nametoindex failed for '{name}'");
    }
    Ok(idx)
}

fn cleanup_existing_xdp(iface: &str) {
    let _ = std::process::Command::new("xdp-loader")
        .args(["unload", iface, "--all"])
        .output();
}

fn cleanup_bpf_pins() {
    for name in &[
        "config_map",
        "state_map",
        "stats_map",
        "relay_map",
        "session_map",
        "whitelist_map",
    ] {
        let path = format!("/sys/fs/bpf/{name}");
        let _ = std::fs::remove_file(&path);
    }
}
