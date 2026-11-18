//! `probe` — self-service diagnostic report.
//!
//! Collects device identity, USB/HID descriptors, device-database match status,
//! and raw protocol responses into a GitHub-ready Markdown report so users with
//! unsupported or partially-working keyboards can paste enough information for us
//! to add support or debug. Every query is wrapped so a failure appends a
//! `timeout/error` line and the report still completes.

use super::{
    CmdCtx, CommandResult, RawHidEntry, collect_raw_hid_entries, is_non_path_selector,
    open_preferred_transport, resolve_device,
};
use iot_driver::protocol::patch_info;
use monsgeek_keyboard::settings::FirmwareVersion;
use monsgeek_transport::protocol::ProtocolFamily;
use monsgeek_transport::protocol::cmd;
use monsgeek_transport::{
    ChecksumType, FlowControlTransport, HidDiscovery, InterfaceKind, InterfaceVerdict,
    RejectReason, Transport, classify_interface, read_sysfs_report_descriptor,
};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format bytes as space-separated lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Append one query's raw response (or error) as a Markdown bullet line.
fn query_line(out: &mut String, transport: &FlowControlTransport, label: &str, cmd_byte: u8) {
    match transport.query_command(cmd_byte, &[], ChecksumType::Bit7) {
        Ok(resp) => {
            let _ = writeln!(out, "- {label} (0x{cmd_byte:02X}): `{}`", hex(&resp));
        }
        Err(e) => {
            let _ = writeln!(out, "- {label} (0x{cmd_byte:02X}): timeout/error ({e})");
        }
    }
}

/// Environment / driver header.
fn section_env(out: &mut String) {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(out, "## Environment");
    let _ = writeln!(out, "- driver: iot_driver v{}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(
        out,
        "- host: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out, "- timestamp: {epoch} (unix epoch seconds, UTC)");
    let _ = writeln!(out);
}

/// All discovered HID devices (shows unsupported/unresponsive devices too).
fn section_devices(out: &mut String) {
    let _ = writeln!(out, "## Discovered devices");
    let discovery = HidDiscovery::new();
    match discovery.probe_devices() {
        Ok(probed) if !probed.is_empty() => {
            let _ = writeln!(
                out,
                "| transport | vid:pid | responsive | device id | fw | path |"
            );
            let _ = writeln!(out, "|---|---|---|---|---|---|");
            for p in &probed {
                let info = &p.device.info;
                let id = p
                    .device_id
                    .map(|v| format!("{v} (0x{v:04X})"))
                    .unwrap_or_else(|| "-".into());
                let ver = p
                    .version
                    .map(|v| format!("0x{v:04X}"))
                    .unwrap_or_else(|| "-".into());
                let _ = writeln!(
                    out,
                    "| {:?} | {:04X}:{:04X} | {} | {} | {} | `{}` |",
                    info.transport_type,
                    info.vid,
                    info.pid,
                    p.responsive,
                    id,
                    ver,
                    info.device_path,
                );
            }
        }
        Ok(_) => {
            let _ = writeln!(out, "_No supported devices found._");
        }
        Err(e) => {
            let _ = writeln!(out, "_Device enumeration failed: {e}_");
        }
    }
    let _ = writeln!(out);
    section_candidate_interfaces(out);
}

fn format_candidate_interfaces_table_with<F, M>(
    entries: &[RawHidEntry],
    classify_fn: F,
    model_fn: M,
) -> Option<String>
where
    F: Fn(
        &monsgeek_transport::HidCandidateInfo,
        Option<&monsgeek_transport::HidDescriptorSummary>,
    ) -> InterfaceVerdict,
    M: Fn(u16, u16) -> Option<String>,
{
    let mut rows: Vec<(&RawHidEntry, InterfaceVerdict)> = entries
        .iter()
        .filter_map(|e| {
            let verdict = classify_fn(&e.candidate, e.descriptor.as_ref());
            if matches!(
                verdict,
                InterfaceVerdict::Rejected(RejectReason::NotCandidateVidPid)
            ) {
                None
            } else {
                Some((e, verdict))
            }
        })
        .collect();

    if rows.is_empty() {
        return None;
    }

    rows.sort_by(|(a, _), (b, _)| {
        (
            a.candidate.vid,
            a.candidate.pid,
            a.candidate.interface_number,
            &a.path,
            a.candidate.usage_page,
            a.candidate.usage,
        )
            .cmp(&(
                b.candidate.vid,
                b.candidate.pid,
                b.candidate.interface_number,
                &b.path,
                b.candidate.usage_page,
                b.candidate.usage,
            ))
    });

    let mut out = String::new();
    let _ = writeln!(out, "## Candidate HID interfaces");
    let _ = writeln!(
        out,
        "Every HID collection belonging to a MonsGeek (`0x3151`) or database-listed \
         device, evaluated from enumeration and the kernel-cached report descriptor."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| path | vid:pid | model | interface | usage | status | detail |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|");

    let mut unsupported_oems: Vec<(&'static str, &'static str)> = Vec::new();
    for (entry, verdict) in rows {
        let mut model = model_fn(entry.candidate.vid, entry.candidate.pid)
            .or_else(|| entry.product_name.clone())
            .unwrap_or_else(|| "-".into());
        if let Some(mfg) = entry.manufacturer_name.as_deref() {
            let mfg = mfg.trim();
            if !mfg.is_empty() && model == "-" {
                model = mfg.to_string();
            } else if !mfg.is_empty()
                && !model
                    .to_ascii_lowercase()
                    .contains(&mfg.to_ascii_lowercase())
            {
                model = format!("{model} (USB: {mfg})");
            }
        }
        let model = model.replace('|', "/");
        let (status, detail) = match verdict {
            InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                via_custom_rule: false,
            }) => {
                let d = if entry.descriptor.is_some() {
                    "default vendor Feature interface (64B ID 0)"
                } else {
                    "default vendor Feature interface"
                };
                ("accepted", d.to_string())
            }
            InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                via_custom_rule: true,
            }) => (
                "accepted",
                "database interface override (64B ID 0)".to_string(),
            ),
            InterfaceVerdict::Accepted(InterfaceKind::BluetoothVendor) => (
                "accepted",
                "Bluetooth vendor interface (0xFF55:0x0202)".to_string(),
            ),
            InterfaceVerdict::Rejected(ref reason) => {
                if let RejectReason::UnsupportedOemProtocol { oem, web_url, .. } = reason
                    && !unsupported_oems.contains(&(*oem, *web_url))
                {
                    unsupported_oems.push((*oem, *web_url));
                }
                ("rejected", reason.to_string().replace('|', "/"))
            }
        };
        let _ = writeln!(
            out,
            "| `{}` | {:04X}:{:04X} | {} | {} | 0x{:04X}:0x{:04X} | {} | {} |",
            entry.path,
            entry.candidate.vid,
            entry.candidate.pid,
            model,
            entry.candidate.interface_number,
            entry.candidate.usage_page,
            entry.candidate.usage,
            status,
            detail,
        );
    }
    let _ = writeln!(out);
    for (oem, web_url) in unsupported_oems {
        let _ = writeln!(
            out,
            "> **Note:** Some Akko USB `VID:PID` pairs (such as `38EE:0016`, listed as `RAID 75 HE` in `devices.json` and also used by `TAC75 HE` batches) are shared across incompatible OEMs. Units running {oem} firmware are not supported by `iot_driver` (which speaks the RongYuan protocol only); after installing udev permissions (`sudo make install-udev`), configure them in a Chromium-based browser via WebHID at {web_url}."
        );
        let _ = writeln!(out);
    }
    Some(out)
}

/// Evaluate every HID interface belonging to a candidate VID:PID from enumeration
/// and sysfs report descriptor alone; nothing is opened.
fn section_candidate_interfaces(out: &mut String) {
    let entries = collect_raw_hid_entries();
    if let Some(table) =
        format_candidate_interfaces_table_with(&entries, classify_interface, |vid, pid| {
            iot_driver::devices::get_device_info(vid, pid).map(|d| d.display_name)
        })
    {
        out.push_str(&table);
    }
}

/// Decode the 0xE7 patch-info response (both response framings), like `query::info`.
fn append_patch_info(out: &mut String, transport: &FlowControlTransport) {
    match transport.query_raw(patch_info::CMD, &[], ChecksumType::Bit7) {
        Ok(resp) => {
            let _ = writeln!(out, "- patch query (0xE7) raw: `{}`", hex(&resp));
            let offsets = if resp.len() >= 6
                && resp[0] == patch_info::MAGIC_HI
                && resp[1] == patch_info::MAGIC_LO
            {
                Some((2usize, 3usize, 5usize)) // payload only
            } else if resp.len() >= 7
                && resp[1] == patch_info::MAGIC_HI
                && resp[2] == patch_info::MAGIC_LO
            {
                Some((3, 4, 6)) // echo + payload
            } else {
                None
            };
            match offsets {
                Some((ver_off, caps_off, name_off)) => {
                    let patch_ver = resp[ver_off];
                    let caps = u16::from_le_bytes([resp[caps_off], resp[caps_off + 1]]);
                    let name_end = resp.len().min(name_off + 9);
                    let name_bytes = &resp[name_off..name_end];
                    let name_len = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    let name = String::from_utf8_lossy(&name_bytes[..name_len]);
                    let caps_list = patch_info::capability_names(caps);
                    let caps_str = if caps_list.is_empty() {
                        "none".to_string()
                    } else {
                        caps_list.join(", ")
                    };
                    let _ = writeln!(out, "- patch: {name} v{patch_ver} [{caps_str}]");
                }
                None => {
                    let _ = writeln!(out, "- patch: stock firmware (no patch magic)");
                }
            }
        }
        Err(_) => {
            let _ = writeln!(out, "- patch: stock firmware (0xE7 timeout/error)");
        }
    }
}

/// Target device deep-dive: identity, raw protocol responses, DB match, dongle heuristic.
fn section_target(out: &mut String, ctx: &CmdCtx) {
    let _ = writeln!(out, "## Target device");
    let transport = match open_preferred_transport(ctx) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(out, "_No target device opened: {e}_");
            let _ = writeln!(out);
            return;
        }
    };

    let dev = transport.device_info();
    let (vid, pid) = (dev.vid, dev.pid);
    if let Some(name) = &dev.product_name {
        let _ = writeln!(out, "- product: {name}");
    }
    let _ = writeln!(
        out,
        "- vid:pid: {vid:04X}:{pid:04X}  transport: {:?}",
        dev.transport_type
    );

    // Firmware identity (for the DB lookup below).
    let mut device_id: Option<u32> = None;
    match transport.query_command(cmd::GET_USB_VERSION, &[], ChecksumType::Bit7) {
        Ok(resp) if resp.len() >= 9 => {
            let id = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
            let version = u16::from_le_bytes([resp[7], resp[8]]);
            device_id = Some(id);
            let _ = writeln!(out, "- device id: {id} (0x{id:08X})");
            let _ = writeln!(
                out,
                "- firmware: {} (raw 0x{version:04X}, dec {version})",
                FirmwareVersion::new(version).format()
            );
            let _ = writeln!(out, "- GET_USB_VERSION (0x8F): `{}`", hex(&resp));
        }
        Ok(resp) => {
            let _ = writeln!(
                out,
                "- GET_USB_VERSION (0x8F): short response `{}`",
                hex(&resp)
            );
        }
        Err(e) => {
            let _ = writeln!(out, "- GET_USB_VERSION (0x8F): timeout/error ({e})");
        }
    }

    let db_info =
        iot_driver::devices::get_device_info_with_id(device_id.map(|v| v as i32), vid, pid);
    let family = ProtocolFamily::detect(db_info.as_ref().map(|d| d.name.as_str()), pid);
    let _ = writeln!(out, "- protocol family: {family}");

    // Raw protocol capability dump (for reverse engineering unknown devices).
    let _ = writeln!(out, "\n### Raw protocol responses");
    query_line(out, &transport, "GET_FEATURE_LIST", cmd::GET_FEATURE_LIST);
    query_line(out, &transport, "GET_KBOPTION", cmd::GET_KBOPTION);
    query_line(out, &transport, "GET_PROFILE", cmd::GET_PROFILE);
    query_line(out, &transport, "GET_LEDPARAM", cmd::GET_LEDPARAM);
    query_line(out, &transport, "GET_DEBOUNCE", cmd::GET_DEBOUNCE);
    append_patch_info(out, &transport);

    // Dongle-local probe: a GET_DONGLE_INFO response means this is a receiver.
    if let Ok(Some(di)) = transport.query_dongle_info() {
        let _ = writeln!(
            out,
            "\n### Dongle detected\n- GET_DONGLE_INFO: proto v{} max_pkt {} fw {}",
            di.protocol_version, di.max_packet_size, di.firmware_version
        );
        if !monsgeek_transport::is_dongle_pid(pid) {
            let _ = writeln!(
                out,
                "- ⚠ This dongle responds on an **unrecognized PID 0x{pid:04X}**. \
                 Please report this so it can be added to the known dongle list."
            );
        }
    }

    // Device-database match — the prominent symptom report.
    let _ = writeln!(out, "\n## Device database");
    match &db_info {
        Some(info) => {
            let _ = writeln!(out, "✅ **FOUND**");
            let _ = writeln!(out, "- display name: {}", info.display_name);
            if let Some(company) = &info.company {
                let _ = writeln!(out, "- company: {company}");
            }
            let _ = writeln!(out, "- key count: {}", info.key_count);
            let _ = writeln!(out, "- magnetism: {}", info.has_magnetism);
            let _ = writeln!(out, "- side light: {}", info.has_sidelight);
            if let Some(layers) = info.layer_count {
                let _ = writeln!(out, "- layers: {layers}");
            }
            if let Some(id) = device_id
                && let Some(def) = iot_driver::profile_registry().get_device_info_by_id(id as i32)
            {
                if let Some(layout) = &def.key_layout_name {
                    let _ = writeln!(out, "- key layout: {layout}");
                }
                if let Some(chip) = &def.chip_family {
                    let _ = writeln!(out, "- chip family: {chip}");
                }
            }
        }
        None => {
            let _ = writeln!(out, "❌ **NOT FOUND**");
            let id_str = device_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into());
            let _ = writeln!(
                out,
                "> Device id {id_str} (vid {vid:04X} pid {pid:04X}) is not in the device \
                 database. This is why key count is 0 / settings reset / most features are \
                 unavailable. Please paste this report into a GitHub issue so the device can \
                 be added."
            );
        }
    }
    let _ = writeln!(out);
}

/// Dump the raw HID report descriptor of the target device (RE-critical).
///
/// Prefers the kernel-cached sysfs descriptor (zero hidraw open/reads),
/// falling back to `get_report_descriptor` only when sysfs is unavailable on a
/// resolved device. When no supported transport resolved, dumps descriptors for
/// `--device` or unmatched candidate interfaces via sysfs.
fn section_report_descriptor(out: &mut String, ctx: &CmdCtx) {
    let _ = writeln!(out, "## HID report descriptor");
    let discovery = HidDiscovery::new();
    match resolve_device(&discovery, ctx.device_selector()) {
        Ok(device) => {
            let sysfs_desc =
                read_sysfs_report_descriptor(&device.info.device_path).map(|raw| hex(&raw));
            let result: Result<String, Box<dyn std::error::Error>> = match sysfs_desc {
                Some(desc) => Ok(desc),
                None => (|| -> Result<String, Box<dyn std::error::Error>> {
                    let api = hidapi::HidApi::new()?;
                    let cpath = std::ffi::CString::new(device.info.device_path.as_bytes())?;
                    let hid = api.open_path(cpath.as_c_str())?;
                    let mut buf = vec![0u8; 4096];
                    let n = hid.get_report_descriptor(&mut buf)?;
                    Ok(hex(&buf[..n]))
                })(),
            };

            match result {
                Ok(desc) if !desc.is_empty() => {
                    let _ = writeln!(out, "- interface: `{}`", device.info.device_path);
                    let _ = writeln!(out, "\n```\n{desc}\n```");
                }
                Ok(_) => {
                    let _ = writeln!(out, "_Report descriptor was empty._");
                }
                Err(e) => {
                    let _ = writeln!(out, "_Report descriptor unavailable: {e}_");
                }
            }
            let _ = writeln!(out);
        }
        Err(e) => {
            let entries = collect_raw_hid_entries();
            let mut candidates: Vec<&RawHidEntry> =
                if let Some(sel) = ctx.device_selector().filter(|s| !is_non_path_selector(s)) {
                    entries.iter().filter(|d| d.path.contains(sel)).collect()
                } else {
                    entries
                        .iter()
                        .filter(|d| {
                            !matches!(
                                classify_interface(&d.candidate, d.descriptor.as_ref()),
                                InterfaceVerdict::Rejected(RejectReason::NotCandidateVidPid)
                            )
                        })
                        .collect()
                };
            candidates.sort_by_key(|d| {
                (
                    d.candidate.vid,
                    d.candidate.pid,
                    d.candidate.interface_number,
                    &d.path,
                )
            });

            let mut seen_paths = HashSet::new();
            let mut dumped = false;
            for entry in candidates {
                if !seen_paths.insert(entry.path.as_str()) {
                    continue;
                }
                if let Some(raw) = read_sysfs_report_descriptor(&entry.path)
                    && !raw.is_empty()
                {
                    let _ = writeln!(
                        out,
                        "- interface: `{}` ({:04X}:{:04X}, IF{})",
                        entry.path,
                        entry.candidate.vid,
                        entry.candidate.pid,
                        entry.candidate.interface_number,
                    );
                    let _ = writeln!(out, "\n```\n{}\n```\n", hex(&raw));
                    dumped = true;
                }
            }

            if !dumped {
                let _ = writeln!(out, "_Could not resolve target device: {e}_");
                let _ = writeln!(out);
            }
        }
    }
}

/// Generate the diagnostic report.
pub fn run(ctx: &CmdCtx, output: Option<&Path>) -> CommandResult {
    let mut out = String::new();
    out.push_str("# MonsGeek/Akko Linux driver — diagnostic report\n\n");
    section_env(&mut out);
    section_devices(&mut out);
    section_target(&mut out, ctx);
    section_report_descriptor(&mut out, ctx);

    print!("{out}");

    if let Some(path) = output {
        std::fs::write(path, &out)?;
        eprintln!("Report written to {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use monsgeek_transport::{
        HidCandidateInfo, HidDescriptorSummary, UsbInterfaceRule, classify_interface_with,
    };

    const M1_V5_IF2_DESC: &[u8] = &[
        0x06, 0xFF, 0xFF, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x02, 0x15, 0x80, 0x25, 0x7F, 0x95, 0x40,
        0x75, 0x08, 0xB1, 0x02, 0xC0,
    ];

    const RAID75_IF0_DESC: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x05, 0x08,
        0x19, 0x01, 0x29, 0x05, 0x95, 0x05, 0x75, 0x01, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x05, 0x07, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x95, 0x06,
        0x75, 0x08, 0x81, 0x00, 0xC0,
    ];

    const RAID75_IF2_DESC: &[u8] = &[
        0x06, 0x60, 0xFF, 0x09, 0x61, 0xA1, 0x01, 0x85, 0x09, 0x09, 0x62, 0x15, 0x00, 0x26, 0xFF,
        0x00, 0x95, 0x3F, 0x75, 0x08, 0x81, 0x02, 0x09, 0x63, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x95,
        0x3F, 0x75, 0x08, 0x91, 0x02, 0xC0, 0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x03,
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x19, 0x01, 0x29, 0x02, 0x75, 0x08, 0x95, 0x3F, 0xB1, 0x02,
        0xC0,
    ];

    #[test]
    fn candidate_interfaces_table_explains_accepted_and_rejected_entries() {
        let known: HashSet<(u16, u16)> = [(0x38EE, 0x0016)].into_iter().collect();
        let rules = [UsbInterfaceRule {
            vid: 0x38EE,
            pid: 0x0016,
            interface_number: Some(2),
            usage_page: 0xFF60,
            usage: 0x0061,
        }];
        let entries = vec![
            RawHidEntry {
                path: "/dev/hidraw0".into(),
                manufacturer_name: None,
                product_name: Some("Razer Mamba".into()),
                candidate: HidCandidateInfo {
                    vid: 0x1532,
                    pid: 0x0046,
                    interface_number: 0,
                    usage_page: 0x0001,
                    usage: 0x0002,
                    is_bluetooth: false,
                },
                descriptor: None,
            },
            RawHidEntry {
                path: "/dev/hidraw6".into(),
                manufacturer_name: None,
                product_name: Some("MonsGeek M1 V5 HE".into()),
                candidate: HidCandidateInfo {
                    vid: 0x3151,
                    pid: 0x5030,
                    interface_number: 2,
                    usage_page: 0xFFFF,
                    usage: 0x0002,
                    is_bluetooth: false,
                },
                descriptor: Some(HidDescriptorSummary::parse(M1_V5_IF2_DESC)),
            },
            RawHidEntry {
                path: "/dev/hidraw9".into(),
                manufacturer_name: Some("BY Tech".into()),
                product_name: Some("Akko Keyboard".into()),
                candidate: HidCandidateInfo {
                    vid: 0x38EE,
                    pid: 0x0016,
                    interface_number: 0,
                    usage_page: 0x0001,
                    usage: 0x0006,
                    is_bluetooth: false,
                },
                descriptor: Some(HidDescriptorSummary::parse(RAID75_IF0_DESC)),
            },
            RawHidEntry {
                path: "/dev/hidraw11".into(),
                manufacturer_name: Some("BY Tech".into()),
                product_name: Some("Akko Keyboard".into()),
                candidate: HidCandidateInfo {
                    vid: 0x38EE,
                    pid: 0x0016,
                    interface_number: 2,
                    usage_page: 0xFF60,
                    usage: 0x0061,
                    is_bluetooth: false,
                },
                descriptor: Some(HidDescriptorSummary::parse(RAID75_IF2_DESC)),
            },
        ];

        let table = format_candidate_interfaces_table_with(
            &entries,
            |c, d| classify_interface_with(c, d, Some(&known), &rules),
            |vid, pid| match (vid, pid) {
                (0x3151, 0x5030) => Some("M1 V5 HE".into()),
                (0x38EE, 0x0016) => Some("RAID 75 HE".into()),
                _ => None,
            },
        )
        .unwrap();

        assert!(!table.contains("1532:0046"));
        assert!(
            table.contains(
                "| `/dev/hidraw6` | 3151:5030 | M1 V5 HE | 2 | 0xFFFF:0x0002 | accepted |"
            )
        );
        assert!(table.contains(
            "| `/dev/hidraw9` | 38EE:0016 | RAID 75 HE (USB: BY Tech) | 0 | 0x0001:0x0006 | rejected | standard HID keyboard interface |"
        ));
        assert!(table.contains(
            "| `/dev/hidraw11` | 38EE:0016 | RAID 75 HE (USB: BY Tech) | 2 | 0xFF60:0x0061 | rejected | unsupported Shenzhen Beiying (BY Tech / HubX) firmware (ID 0x09 In 63B, ID 0x09 Out 63B, ID 0x03 Feature 63B)"
        ));
        assert!(table.contains("> **Note:**"));
        assert!(table.contains("https://demo.hubx.pro/keyboard/"));
    }
}
