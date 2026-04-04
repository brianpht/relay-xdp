//! BPF loader - load/attach XDP program, manage BPF maps.
//! Port of `relay_bpf.c`.

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use log::info;
use std::path::Path;

use relay_xdp_common::*;

/// Holds the loaded BPF program and map handles.
#[allow(dead_code)]
pub struct BpfContext {
    pub bpf: Ebpf,
    pub interface_index: u32,
    pub attached_mode: Option<XdpFlags>,
}

impl BpfContext {
    /// Find the network interface matching the relay address.
    fn find_interface(relay_public_address: u32, relay_internal_address: u32) -> Result<(String, u32)> {
        // Use nix to enumerate interfaces, or fall back to parsing /proc
        // For simplicity, iterate over interfaces using libc getifaddrs

        let addrs = nix_ifaddrs()?;
        for (name, addr) in &addrs {
            if *addr == relay_public_address || *addr == relay_internal_address {
                let idx = interface_name_to_index(name)?;
                return Ok((name.clone(), idx));
            }
        }

        bail!(
            "could not find network interface matching relay address {}",
            crate::platform::format_address(relay_public_address, 0)
        );
    }

    /// Load the XDP program from an ELF object file and attach to the NIC.
    pub fn init(
        xdp_obj_path: &Path,
        relay_public_address: u32,
        relay_internal_address: u32,
    ) -> Result<Self> {
        // Must be root
        if unsafe { libc::geteuid() } != 0 {
            bail!("this program must be run as root");
        }

        let (iface_name, iface_index) =
            Self::find_interface(relay_public_address, relay_internal_address)?;
        info!("Found network interface: '{iface_name}' (index {iface_index})");

        // Clean up any existing XDP programs
        cleanup_existing_xdp(&iface_name);
        cleanup_bpf_pins();

        // Load BPF program
        info!("Loading relay_xdp from {}", xdp_obj_path.display());
        let mut bpf = Ebpf::load_file(xdp_obj_path)
            .with_context(|| format!("failed to load BPF program from {}", xdp_obj_path.display()))?;

        // Attach XDP program
        let program: &mut Xdp = bpf
            .program_mut("relay_xdp")
            .context("relay_xdp program not found in BPF object")?
            .try_into()
            .context("program is not XDP")?;

        program.load().context("failed to load XDP program")?;

        // Try native mode first, fall back to SKB
        let attached_mode = match program.attach(&iface_name, XdpFlags::default()) {
            Ok(_link_id) => {
                info!("Attached XDP program in native mode");
                Some(XdpFlags::default())
            }
            Err(e) => {
                info!("Native mode failed ({e}), falling back to SKB mode...");
                match program.attach(&iface_name, XdpFlags::SKB_MODE) {
                    Ok(_link_id) => {
                        info!("Attached XDP program in SKB mode");
                        Some(XdpFlags::SKB_MODE)
                    }
                    Err(e2) => {
                        bail!("failed to attach XDP program: native={e}, skb={e2}");
                    }
                }
            }
        };

        Ok(Self {
            bpf,
            interface_index: iface_index,
            attached_mode,
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
// Helper functions
// ---------------------------------------------------------------------------

/// Enumerate IPv4 interfaces and their host-order addresses.
fn nix_ifaddrs() -> Result<Vec<(String, u32)>> {
    let mut results = Vec::new();

    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            bail!("getifaddrs failed");
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
        bail!("if_nametoindex failed for '{name}'");
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

