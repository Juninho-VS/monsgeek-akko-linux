//! Disassembly-verified Shenzhen Beiying `Report ID 0x09` USB HID protocol layer.
//!
//! Every command byte, report length, checksum rule, and LED encoding path is verified
//! directly from `WebEnfTool.exe` (`0x469090`, `0x46e0e0..0x471700`, `0x4af620`, `0x4b4960..0x4bd7f0`).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hidapi::{HidApi, HidDevice};

use crate::ini_config::DeviceIniConfig;

pub const REPORT_ID: u8 = 0x09;
pub const WIRED_REPORT_LEN: usize = 64;
pub const WIRELESS_REPORT_LEN: usize = 20;
pub const MAX_CHUNK_PAYLOAD: usize = 56; // 0x38

/// Read-only HID report descriptor summary confirming Beiying Report ID `0x09` support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report09Capability {
    pub vendor_usage_page: u16,
    pub input_report_bytes: usize,
    pub output_report_bytes: usize,
}

/// Result of opening and probing a Beiying HID interface.
#[derive(Debug, Clone)]
pub struct HidSessionInfo {
    pub path: String,
    pub vid: u16,
    pub pid: u16,
    pub report_len: usize,
    pub uuid: String,
    pub led_proto_flags: u16,
    pub lighting_status: Option<u8>,
}

/// Telemetry payload packed into command `0x0B` (`0x469090`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelemetryPacketData {
    pub volume: u8,
    pub cpu_load: u8,
    pub mem_usage: u8,
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub weekday: u8,
    pub cpu_temp: u8,
    pub weather_code: u8,
    pub weather_temp: i8,
}

/// Transport abstraction so `--dry-run` and tests never touch `/dev/hidraw*`.
pub trait BeiyingTransport: Send + Sync {
    fn session_info(&self) -> &HidSessionInfo;
    fn send_keyboard_frame(
        &self,
        cfg: &DeviceIniConfig,
        keys: &[(u16, [u8; 3])],
    ) -> Result<(), String>;
    fn send_lightbar_frame(&self, leds: &[(u8, [u8; 3])]) -> Result<(), String>;
    fn send_telemetry(&self, data: &TelemetryPacketData) -> Result<(), String>;
    fn populate_led_beads(&self, _cfg: &mut DeviceIniConfig) {}
}

/// Parse a raw USB HID report descriptor and verify it exposes a top-level vendor
/// collection (`>= 0xFF00`) containing **Report ID `0x09`** for both Input and Output.
///
/// Matches TAC75 HE (`Usage Page 0xFF00`, `Report ID 0x09`, `Report Count 63`, Input & Output = 64B)
/// and wireless `0x09` (20B) while rejecting standard boot keyboard/mouse and Rongyuan `0xFFFF` Feature-only paths.
pub fn parse_beiying_report09_descriptor(desc: &[u8]) -> Option<Report09Capability> {
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut usage_page: u32 = 0;
    let mut top_vendor_page: Option<u16> = None;
    let mut active_top_vendor = false;
    let mut report_id: u32 = 0;
    let mut report_size: u32 = 0;
    let mut report_count: u32 = 0;
    let mut input_bytes: Option<usize> = None;
    let mut output_bytes: Option<usize> = None;

    while i < desc.len() {
        let prefix = desc[i];
        i += 1;

        // Long item (`0xFE`)
        if prefix == 0xFE {
            if i + 2 > desc.len() {
                break;
            }
            let data_len = desc[i] as usize;
            i += 2 + data_len;
            continue;
        }

        let size_code = prefix & 0x03;
        let item_len = match size_code {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };
        if i + item_len > desc.len() {
            break;
        }
        let val = match item_len {
            0 => 0,
            1 => desc[i] as u32,
            2 => u16::from_le_bytes([desc[i], desc[i + 1]]) as u32,
            4 => u32::from_le_bytes([desc[i], desc[i + 1], desc[i + 2], desc[i + 3]]),
            _ => unreachable!(),
        };
        i += item_len;

        let item_type = (prefix >> 2) & 0x03;
        let tag = (prefix >> 4) & 0x0F;

        match (item_type, tag) {
            // Global: Usage Page (0x1, 0x0)
            (1, 0x0) => usage_page = val,
            // Global: Report Size (0x1, 0x7)
            (1, 0x7) => report_size = val,
            // Global: Report ID (0x1, 0x8)
            (1, 0x8) => report_id = val,
            // Global: Report Count (0x1, 0x9)
            (1, 0x9) => report_count = val,
            // Main: Collection (0x0, 0xA)
            (0, 0xA) => {
                if depth == 0 && usage_page >= 0xFF00 {
                    active_top_vendor = true;
                    top_vendor_page = Some(usage_page as u16);
                }
                depth += 1;
            }
            // Main: End Collection (0x0, 0xC)
            (0, 0xC) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    active_top_vendor = false;
                }
            }
            // Main: Input (0x0, 0x8) or Output (0x0, 0x9)
            (0, 0x8) | (0, 0x9) if active_top_vendor && report_id == REPORT_ID as u32 => {
                let total_bits = report_size.saturating_mul(report_count);
                let total_bytes = 1usize + (total_bits as usize).div_ceil(8);
                if tag == 0x8 {
                    input_bytes = Some(total_bytes);
                } else {
                    output_bytes = Some(total_bytes);
                }
            }
            _ => {}
        }
    }

    let in_len = input_bytes?;
    let out_len = output_bytes?;
    let vendor_usage_page = top_vendor_page?;
    if (in_len == WIRED_REPORT_LEN || in_len == WIRELESS_REPORT_LEN) && in_len == out_len {
        Some(Report09Capability {
            vendor_usage_page,
            input_report_bytes: in_len,
            output_report_bytes: out_len,
        })
    } else {
        None
    }
}

/// Apply Beiying 1-byte checksum: `pkt[63] = !sum(pkt[0..63])` (`0x4bca90` & `0x4b4960`).
pub fn apply_checksum_64(pkt: &mut [u8; WIRED_REPORT_LEN]) {
    let sum = pkt[0..63].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    pkt[63] = !sum;
}

/// Build command `0x82 0x01` query packet to read the 12-hex-char device UUID (`0x4b53f0`).
///
/// Exact verified bytes: `[0x09, 0x82, 0x01, 0x00, 0x01, 0x00, 0x06, 0..., 0x6C]`.
pub fn build_query_uuid_packet() -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    pkt[0] = REPORT_ID;
    pkt[1] = 0x82;
    pkt[2] = 0x01;
    pkt[3] = 0x00;
    pkt[4] = 0x01;
    pkt[5] = 0x00;
    pkt[6] = 0x06;
    apply_checksum_64(&mut pkt);
    pkt
}

/// Parse 12-hex-char uppercase UUID from `0x82 0x01` response (`rx[7..13]`, `rx[7] != 0`).
pub fn parse_uuid_response(rx: &[u8]) -> Option<String> {
    if rx.len() < 13 || rx[0] != REPORT_ID || rx[1] != 0x82 || rx[2] != 0x01 || rx[7] == 0 {
        return None;
    }
    Some(format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        rx[7], rx[8], rx[9], rx[10], rx[11], rx[12]
    ))
}

/// Build command `0x87` query packet to read current lighting status (`0x4b49f0`).
///
/// Exact verified bytes: `[0x09, 0x87, 0x00, 0x00, 0x01, 0..., 0x6E]`.
pub fn build_query_lighting_status_packet() -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    pkt[0] = REPORT_ID;
    pkt[1] = 0x87;
    pkt[4] = 0x01;
    apply_checksum_64(&mut pkt);
    pkt
}

/// Build command `0x82 0x0F` query packet to read LED protocol capability flags (`0x46f0e0`).
///
/// Exact verified bytes: `[0x09, 0x82, 0x0F, 0x00, 0x01, 0x34, 0..., 0x30]`.
pub fn build_query_led_caps_packet() -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    pkt[0] = REPORT_ID;
    pkt[1] = 0x82;
    pkt[2] = 0x0F;
    pkt[4] = 0x01;
    pkt[5] = 0x34;
    apply_checksum_64(&mut pkt);
    pkt
}

/// Parse `[dev + 0x52]` LED capability flags (`rx[16]`), defaulting to `0xFFFF` if `0` or invalid.
pub fn parse_led_caps_response(rx: &[u8]) -> Option<u16> {
    if rx.len() > 16 && rx[0] == REPORT_ID && rx[1] == 0x82 && rx[2] == 0x0F {
        let cap = rx[16];
        if cap == 0 {
            Some(0xFFFF)
        } else {
            Some(cap as u16)
        }
    } else {
        None
    }
}

/// Encode `[R, G, B]` into big-endian RGB565 (`[hi, lo]`) as at `0x46f3e7` / `0x470043`.
pub fn rgb_to_rgb565_be(rgb: [u8; 3]) -> [u8; 2] {
    let r = (rgb[0] as u16 & 0xF8) << 8;
    let g = (rgb[1] as u16 & 0xFC) << 3;
    let b = (rgb[2] as u16) >> 3;
    (r | g | b).to_be_bytes()
}

/// Helper to build a single off/clear packet (`subcmd = 0x02`, payload `[0, 0, 0]`).
fn build_off_packet_64(cmd: u8) -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    pkt[0] = REPORT_ID;
    pkt[1] = cmd;
    pkt[2] = 0x02;
    pkt[3] = 0x00;
    pkt[4] = 0x01;
    pkt[5] = 0x00;
    pkt[6] = 0x03;
    apply_checksum_64(&mut pkt);
    pkt
}

/// Chunk an arbitrary byte stream into 56-byte wired HID packets with `(cmd, subcmd)`.
fn chunk_stream_to_packets_64(cmd: u8, subcmd: u8, payload: &[u8]) -> Vec<[u8; WIRED_REPORT_LEN]> {
    if payload.is_empty() {
        return vec![build_off_packet_64(cmd)];
    }
    let total_pkts = payload.len().div_ceil(MAX_CHUNK_PAYLOAD);
    let mut out = Vec::with_capacity(total_pkts);
    for (idx, chunk) in payload.chunks(MAX_CHUNK_PAYLOAD).enumerate() {
        let mut pkt = [0u8; WIRED_REPORT_LEN];
        pkt[0] = REPORT_ID;
        pkt[1] = cmd;
        pkt[2] = subcmd;
        pkt[3] = 0x00;
        pkt[4] = total_pkts as u8;
        pkt[5] = idx as u8;
        pkt[6] = chunk.len() as u8;
        pkt[7..7 + chunk.len()].copy_from_slice(chunk);
        apply_checksum_64(&mut pkt);
        out.push(pkt);
    }
    out
}

/// Encode per-key RGB colors according to firmware capability flags `[dev + 0x52]` (`0x46e22f`).
pub fn encode_keyboard_led_packets(
    cfg: &DeviceIniConfig,
    led_proto_flags: u16,
    keys: &[(u16, [u8; 3])],
) -> Vec<[u8; WIRED_REPORT_LEN]> {
    // Protocol B: Dense RGB565 matrix (`flags & 0x04` and Keymaps populated) (`0x46f350`)
    if led_proto_flags != 0xFFFF
        && (led_proto_flags & 0x04) != 0
        && !cfg.dense_matrix_slots.is_empty()
    {
        let mut by_key: BTreeMap<u16, [u8; 3]> = BTreeMap::new();
        for &(k, rgb) in keys {
            by_key.insert(k, rgb);
        }
        let mut payload = Vec::with_capacity(cfg.dense_matrix_slots.len() * 2);
        for slot in &cfg.dense_matrix_slots {
            let rgb = by_key.get(&slot.key_id).copied().unwrap_or([0, 0, 0]);
            let be = rgb_to_rgb565_be(rgb);
            payload.extend_from_slice(&be);
        }
        return chunk_stream_to_packets_64(0x08, 0x03, &payload);
    }

    // Protocol C: Color-grouped RGB565 (`flags & 0x08` and Keymaps populated) (`0x46fa30`)
    if led_proto_flags != 0xFFFF
        && (led_proto_flags & 0x08) != 0
        && !cfg.grouped_rgb565_addrs.is_empty()
    {
        let mut groups: BTreeMap<[u8; 2], Vec<u8>> = BTreeMap::new();
        for &(k, rgb) in keys {
            if rgb == [0, 0, 0] {
                continue;
            }
            let c565 = rgb_to_rgb565_be(rgb);
            if c565 == [0, 0] {
                continue;
            }
            if let Some(addrs) = cfg.grouped_rgb565_addrs.get(&k) {
                groups.entry(c565).or_default().extend_from_slice(addrs);
            }
        }
        if groups.is_empty() {
            return vec![build_off_packet_64(0x08)];
        }
        let mut payload = Vec::new();
        for (c565, addrs) in groups {
            for slice in addrs.chunks(255) {
                payload.extend_from_slice(&c565);
                payload.push(slice.len() as u8);
                payload.extend_from_slice(slice);
            }
        }
        return chunk_stream_to_packets_64(0x08, 0x04, &payload);
    }

    // Protocol A: Default color-grouped RGB888 (`0x470a60` / `0x4bc520`)
    let mut groups: BTreeMap<[u8; 3], Vec<u8>> = BTreeMap::new();
    for &(k, rgb) in keys {
        if rgb != [0, 0, 0] {
            groups.entry(rgb).or_default().push(k as u8);
        }
    }
    if groups.is_empty() {
        return vec![build_off_packet_64(0x08)];
    }
    let mut payload = Vec::new();
    for (rgb, ids) in groups {
        for slice in ids.chunks(255) {
            payload.extend_from_slice(&rgb);
            payload.push(slice.len() as u8);
            payload.extend_from_slice(slice);
        }
    }
    chunk_stream_to_packets_64(0x08, 0x01, &payload)
}

/// Encode side lightbar (`Tape_Count`) packets using command `0x0E` (`0x4af620` & `0x4bc520`).
pub fn encode_lightbar_packets(leds: &[(u8, [u8; 3])]) -> Vec<[u8; WIRED_REPORT_LEN]> {
    let mut groups: BTreeMap<[u8; 3], Vec<u8>> = BTreeMap::new();
    for &(idx, rgb) in leds {
        if rgb != [0, 0, 0] {
            groups.entry(rgb).or_default().push(idx);
        }
    }
    if groups.is_empty() {
        return vec![build_off_packet_64(0x0E)];
    }
    let mut payload = Vec::new();
    for (rgb, ids) in groups {
        for slice in ids.chunks(255) {
            payload.extend_from_slice(&rgb);
            payload.push(slice.len() as u8);
            payload.extend_from_slice(slice);
        }
    }
    chunk_stream_to_packets_64(0x0E, 0x01, &payload)
}

/// Encode hardware status & clock sync packet (`0x0B`, `0x469090`).
pub fn encode_telemetry_0x0b_packet(d: &TelemetryPacketData) -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    pkt[0] = REPORT_ID;
    pkt[1] = 0x0B;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4] = 0x01;
    pkt[5] = 0x00;
    pkt[6] = 0x0E;
    pkt[7] = d.volume;
    pkt[8] = d.cpu_load;
    pkt[9] = d.mem_usage;
    let [y_lo, y_hi] = d.year.to_le_bytes();
    pkt[10] = y_lo;
    pkt[11] = y_hi;
    pkt[12] = d.month;
    pkt[13] = d.day;
    pkt[14] = d.hour;
    pkt[15] = d.minute;
    pkt[16] = d.second;
    pkt[17] = d.weekday;
    pkt[18] = d.cpu_temp;
    pkt[19] = d.weather_code;
    pkt[20] = d.weather_temp as u8;
    apply_checksum_64(&mut pkt);
    pkt
}

/// Pack active per-key colors for `Push:ColorData` (`0x45b5a4`).
///
/// Format: flat `[R, G, B, count, key1, ..., keyN, R2, G2, B2, count2, ...]` (zeros omitted).
pub fn encode_push_color_data(keys: &[(u16, [u8; 3])]) -> Vec<i32> {
    let mut groups: BTreeMap<[u8; 3], Vec<i32>> = BTreeMap::new();
    for &(k, rgb) in keys {
        if rgb != [0, 0, 0] {
            groups.entry(rgb).or_default().push(k as i32);
        }
    }
    let mut out = Vec::new();
    for (rgb, ids) in groups {
        out.push(rgb[0] as i32);
        out.push(rgb[1] as i32);
        out.push(rgb[2] as i32);
        out.push(ids.len() as i32);
        out.extend_from_slice(&ids);
    }
    out
}

/// Safe dry-run transport (never touches `/dev/hidraw*`).
pub struct DryRunTransport {
    info: HidSessionInfo,
}

impl DryRunTransport {
    pub fn new(vid: u16, pid: u16, uuid: &str) -> Self {
        Self {
            info: HidSessionInfo {
                path: "<dry-run>".to_string(),
                vid,
                pid,
                report_len: WIRED_REPORT_LEN,
                uuid: uuid.to_string(),
                led_proto_flags: 0xFFFF,
                lighting_status: Some(0),
            },
        }
    }
}

impl BeiyingTransport for DryRunTransport {
    fn session_info(&self) -> &HidSessionInfo {
        &self.info
    }

    fn send_keyboard_frame(
        &self,
        cfg: &DeviceIniConfig,
        keys: &[(u16, [u8; 3])],
    ) -> Result<(), String> {
        let pkts = encode_keyboard_led_packets(cfg, self.info.led_proto_flags, keys);
        tracing::trace!(
            packets = pkts.len(),
            lit_keys = keys.iter().filter(|(_, c)| *c != [0, 0, 0]).count(),
            "dry-run TX keyboard frame"
        );
        Ok(())
    }

    fn send_lightbar_frame(&self, leds: &[(u8, [u8; 3])]) -> Result<(), String> {
        let pkts = encode_lightbar_packets(leds);
        tracing::trace!(packets = pkts.len(), "dry-run TX lightbar frame");
        Ok(())
    }

    fn send_telemetry(&self, data: &TelemetryPacketData) -> Result<(), String> {
        let _pkt = encode_telemetry_0x0b_packet(data);
        tracing::trace!(
            cpu = data.cpu_load,
            mem = data.mem_usage,
            "dry-run TX telemetry 0x0B"
        );
        Ok(())
    }
}

/// Real USB HID transport using `hidapi`, gated by sysfs descriptor verification.
pub struct RealHidTransport {
    info: HidSessionInfo,
    device: Arc<Mutex<HidDevice>>,
}

impl RealHidTransport {
    /// Discover, descriptor-verify, open, and handshake a Beiying HID device matching `(vid, pid)`
    /// and optional non-empty `expected_uuid`.
    pub fn open(vid: u16, pid: u16, expected_uuid: Option<&str>) -> Result<Self, String> {
        let api = HidApi::new().map_err(|e| format!("HidApi::new failed: {e}"))?;
        let mut candidates = Vec::new();

        for dev_info in api.device_list() {
            if dev_info.vendor_id() != vid || dev_info.product_id() != pid {
                continue;
            }
            let path_str = dev_info.path().to_string_lossy().into_owned();
            if let Some(cap) = read_sysfs_report_descriptor(&path_str)
                .and_then(|d| parse_beiying_report09_descriptor(&d))
            {
                candidates.push((dev_info.path().to_owned(), path_str, cap));
            } else if dev_info.usage_page() >= 0xFF00 {
                // Fallback when sysfs descriptor lookup fails on non-hidraw path names:
                // still verify via `HidDevice::get_report_descriptor()` after opening.
                candidates.push((
                    dev_info.path().to_owned(),
                    path_str,
                    Report09Capability {
                        vendor_usage_page: dev_info.usage_page(),
                        input_report_bytes: 0,
                        output_report_bytes: 0,
                    },
                ));
            }
        }

        if candidates.is_empty() {
            return Err(format!(
                "No Beiying Report ID 0x09 HID interface found for {:04X}:{:04X}",
                vid, pid
            ));
        }

        let single_candidate = candidates.len() == 1;
        let expected_valid = expected_uuid.filter(|u| !u.is_empty() && *u != "000000000000");

        let mut last_err = String::new();
        for (c_path, path_str, pre_cap) in candidates {
            let dev = match api.open_path(&c_path) {
                Ok(d) => d,
                Err(e) => {
                    last_err = format!("{path_str}: open_path failed ({e})");
                    continue;
                }
            };

            let cap = if pre_cap.input_report_bytes == 0 {
                let mut desc = [0u8; 4096];
                let n = dev
                    .get_report_descriptor(&mut desc)
                    .map_err(|e| format!("{path_str}: get_report_descriptor failed: {e}"))?;
                match parse_beiying_report09_descriptor(&desc[..n]) {
                    Some(c) => c,
                    None => continue,
                }
            } else {
                pre_cap
            };

            let uuid = if single_candidate && expected_valid.is_some() {
                expected_valid.unwrap_or_default().to_string()
            } else {
                let queried = query_uuid(&dev).unwrap_or_default();
                if let Some(want) = expected_valid
                    && !queried.is_empty()
                    && !queried.eq_ignore_ascii_case(want)
                {
                    last_err = format!("{path_str}: UUID mismatch (device={queried}, want={want})");
                    continue;
                }
                queried
            };

            let led_proto_flags = query_led_caps(&dev).unwrap_or(0xFFFF);
            let lighting_status = query_lighting_status(&dev);

            let info = HidSessionInfo {
                path: path_str,
                vid,
                pid,
                report_len: cap.output_report_bytes,
                uuid: if uuid.is_empty() {
                    expected_uuid.unwrap_or("000000000000").to_string()
                } else {
                    uuid
                },
                led_proto_flags,
                lighting_status,
            };

            tracing::info!(
                path = %info.path,
                vid = format_args!("{:04X}", info.vid),
                pid = format_args!("{:04X}", info.pid),
                uuid = %info.uuid,
                led_proto_flags = format_args!("0x{:04X}", info.led_proto_flags),
                lighting_status = ?info.lighting_status,
                "Opened Beiying HID Report ID 0x09 device"
            );

            return Ok(Self {
                info,
                device: Arc::new(Mutex::new(dev)),
            });
        }

        Err(if last_err.is_empty() {
            format!(
                "No verified Beiying Report ID 0x09 interface could be opened for {:04X}:{:04X}",
                vid, pid
            )
        } else {
            last_err
        })
    }

    fn write_packets(&self, packets: &[[u8; WIRED_REPORT_LEN]]) -> Result<(), String> {
        let guard = self
            .device
            .lock()
            .map_err(|_| "HID mutex poisoned".to_string())?;
        for pkt in packets {
            let written = guard
                .write(pkt)
                .map_err(|e| format!("HID write failed: {e}"))?;
            if written != pkt.len() {
                return Err(format!("Short HID write: {written}/{}", pkt.len()));
            }
        }
        Ok(())
    }
}

impl BeiyingTransport for RealHidTransport {
    fn session_info(&self) -> &HidSessionInfo {
        &self.info
    }

    fn send_keyboard_frame(
        &self,
        cfg: &DeviceIniConfig,
        keys: &[(u16, [u8; 3])],
    ) -> Result<(), String> {
        let pkts = encode_keyboard_led_packets(cfg, self.info.led_proto_flags, keys);
        self.write_packets(&pkts)
    }

    fn send_lightbar_frame(&self, leds: &[(u8, [u8; 3])]) -> Result<(), String> {
        let pkts = encode_lightbar_packets(leds);
        self.write_packets(&pkts)
    }

    fn send_telemetry(&self, data: &TelemetryPacketData) -> Result<(), String> {
        let pkt = encode_telemetry_0x0b_packet(data);
        self.write_packets(&[pkt])
    }

    fn populate_led_beads(&self, cfg: &mut DeviceIniConfig) {
        if !cfg.keymaps.is_empty()
            || self.info.led_proto_flags == 0xFFFF
            || (self.info.led_proto_flags & 0x0C) == 0
        {
            return;
        }
        let ids: Vec<u16> = cfg.all_keys.iter().map(|k| k.key_id).collect();
        if ids.is_empty() {
            return;
        }
        let Ok(guard) = self.device.lock() else {
            return;
        };
        let keymaps = query_led_beads_0xa1(&guard, &ids);
        if !keymaps.is_empty() {
            tracing::info!(
                beads = keymaps.len(),
                flags = format_args!("0x{:X}", self.info.led_proto_flags),
                "Populated LED bead matrix via firmware 0xA1"
            );
            cfg.set_keymaps_from_beads(keymaps);
        }
    }
}

/// Read `/sys/class/hidraw/<name>/device/report_descriptor` passively without opening `/dev/hidraw*`.
fn read_sysfs_report_descriptor(hidraw_path: &str) -> Option<Vec<u8>> {
    let dev_name = Path::new(hidraw_path).file_name()?.to_str()?;
    if !dev_name.starts_with("hidraw") {
        return None;
    }
    let sys_path = Path::new("/sys/class/hidraw")
        .join(dev_name)
        .join("device/report_descriptor");
    fs::read(sys_path).ok()
}

fn drain_rx(dev: &HidDevice) {
    let mut scratch = [0u8; WIRED_REPORT_LEN];
    for _ in 0..8 {
        match dev.read_timeout(&mut scratch, 1) {
            Ok(n) if n > 0 => continue,
            _ => break,
        }
    }
}

fn query_uuid(dev: &HidDevice) -> Option<String> {
    drain_rx(dev);
    let tx = build_query_uuid_packet();
    dev.write(&tx).ok()?;
    std::thread::sleep(Duration::from_millis(20));
    let mut rx = [0u8; WIRED_REPORT_LEN];
    for _ in 0..10 {
        if let Ok(n) = dev.read_timeout(&mut rx, 20)
            && n >= 13
            && let Some(uuid) = parse_uuid_response(&rx[..n])
        {
            return Some(uuid);
        }
    }
    None
}

fn query_led_caps(dev: &HidDevice) -> Option<u16> {
    drain_rx(dev);
    let tx = build_query_led_caps_packet();
    dev.write(&tx).ok()?;
    let mut rx = [0u8; WIRED_REPORT_LEN];
    for _ in 0..8 {
        if let Ok(n) = dev.read_timeout(&mut rx, 20)
            && n > 16
            && let Some(caps) = parse_led_caps_response(&rx[..n])
        {
            return Some(caps);
        }
    }
    None
}

fn query_lighting_status(dev: &HidDevice) -> Option<u8> {
    drain_rx(dev);
    let tx = build_query_lighting_status_packet();
    dev.write(&tx).ok()?;
    std::thread::sleep(Duration::from_millis(20));
    let mut rx = [0u8; WIRED_REPORT_LEN];
    for _ in 0..10 {
        if let Ok(n) = dev.read_timeout(&mut rx, 20)
            && n > 7
            && rx[0] == REPORT_ID
            && rx[1] == 0x87
        {
            return Some(rx[7]);
        }
    }
    None
}

fn query_led_beads_0xa1(dev: &HidDevice, key_ids: &[u16]) -> Vec<(u16, Vec<u16>)> {
    let mut out = Vec::new();
    for chunk in key_ids.chunks(10) {
        drain_rx(dev);
        let mut pkt = [0u8; WIRED_REPORT_LEN];
        pkt[0] = REPORT_ID;
        pkt[1] = 0xA1;
        pkt[4] = 0x01;
        pkt[6] = (chunk.len() * 2) as u8;
        for (i, &id) in chunk.iter().enumerate() {
            let [hi, lo] = id.to_be_bytes();
            pkt[7 + i * 2] = hi;
            pkt[7 + i * 2 + 1] = lo;
        }
        apply_checksum_64(&mut pkt);
        if dev.write(&pkt).is_err() {
            continue;
        }
        let mut rx = [0u8; WIRED_REPORT_LEN];
        for _ in 0..8 {
            if let Ok(n) = dev.read_timeout(&mut rx, 20)
                && n >= 10
                && rx[0] == REPORT_ID
                && rx[1] == 0xA1
            {
                let data_end = (7 + (rx[6] as usize).min(MAX_CHUNK_PAYLOAD)).min(n);
                let mut pos = 7;
                while pos + 3 <= data_end {
                    let id = u16::from_be_bytes([rx[pos], rx[pos + 1]]);
                    let cnt = rx[pos + 2] as usize;
                    pos += 3;
                    let end = (pos + cnt).min(data_end);
                    if cnt > 0 && end > pos {
                        let addrs = rx[pos..end].iter().map(|&a| a as u16).collect();
                        out.push((id, addrs));
                    }
                    pos = end;
                }
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_packets_match_disassembly_checksums() {
        let q_uuid = build_query_uuid_packet();
        assert_eq!(&q_uuid[..7], &[0x09, 0x82, 0x01, 0x00, 0x01, 0x00, 0x06]);
        assert_eq!(q_uuid[63], 0x6C);

        let q_status = build_query_lighting_status_packet();
        assert_eq!(&q_status[..5], &[0x09, 0x87, 0x00, 0x00, 0x01]);
        assert_eq!(q_status[63], 0x6E);

        let q_caps = build_query_led_caps_packet();
        assert_eq!(&q_caps[..6], &[0x09, 0x82, 0x0F, 0x00, 0x01, 0x34]);
        assert_eq!(q_caps[63], 0x30);
    }

    #[test]
    fn descriptor_accepts_tac75_and_rejects_boot_or_rongyuan() {
        // Akko TAC75 HE (`38ee:0016`) exact Beiying Report ID 0x09 vendor descriptor:
        // Usage Page (0xFF00), Usage (0x01), Collection (Application), Report ID (9),
        // Logical Min(0), Logical Max(255), Report Size(8), Report Count(63), Input(Data,Var,Abs), Output(Data,Var,Abs), End Collection
        let tac75_desc = [
            0x06, 0x00, 0xFF, // Usage Page (0xFF00)
            0x09, 0x01, // Usage (1)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x09, // Report ID (9)
            0x15, 0x00, // Logical Min (0)
            0x26, 0xFF, 0x00, // Logical Max (255)
            0x75, 0x08, // Report Size (8)
            0x95, 0x3F, // Report Count (63)
            0x09, 0x01, // Usage (1)
            0x81, 0x02, // Input (Data,Var,Abs)
            0x09, 0x02, // Usage (2)
            0x91, 0x02, // Output (Data,Var,Abs)
            0xC0, // End Collection
        ];
        assert_eq!(
            parse_beiying_report09_descriptor(&tac75_desc),
            Some(Report09Capability {
                vendor_usage_page: 0xFF00,
                input_report_bytes: 64,
                output_report_bytes: 64,
            })
        );

        // Rongyuan / MonsGeek Feature-only 0xFFFF descriptor must be rejected:
        let rongyuan_desc = [
            0x06, 0xFF, 0xFF, // Usage Page (0xFFFF)
            0x09, 0x01, 0xA1, 0x01, 0x75, 0x08, 0x95, 0x40, 0xB1,
            0x02, // Feature (not Report ID 0x09 In/Out)
            0xC0,
        ];
        assert_eq!(parse_beiying_report09_descriptor(&rongyuan_desc), None);
    }

    #[test]
    fn all_three_led_protocols_encode_and_checksum() {
        let ini = "\
            [DeviceConfig]\nAudionTyp=168|180\n\
            [Keymaps]\n0=0x00\n1=0x08\n";
        let cfg = DeviceIniConfig::parse("010203040506", ini);
        let frame = [(0u16, [0xFFu8, 0x00, 0x00]), (1u16, [0x00, 0xFF, 0x00])];

        // Case 1: RGB888 color-grouped (flags = 0xFFFF)
        let p_a = encode_keyboard_led_packets(&cfg, 0xFFFF, &frame);
        assert_eq!(p_a[0][1], 0x08);
        assert_eq!(p_a[0][2], 0x01);
        assert_eq!(p_a[0][4], 1);
        assert_eq!(p_a[0][6], 10); // 2 colors * (3 RGB + 1 count + 1 id) = 10 bytes
        let chk_a = !p_a[0][..63].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(p_a[0][63], chk_a);

        // Case 2: Dense RGB565 matrix (flags = 0x04)
        let p_b = encode_keyboard_led_packets(&cfg, 0x04, &frame);
        assert_eq!(p_b[0][1..7], [0x08, 0x03, 0x00, 1, 0, 4]);
        // Red RGB565 = 0xF800, Green RGB565 = 0x07E0
        assert_eq!(&p_b[0][7..11], &[0xF8, 0x00, 0x07, 0xE0]);

        // Case 3: Color-grouped RGB565 (flags = 0x08)
        let p_c = encode_keyboard_led_packets(&cfg, 0x08, &frame);
        assert_eq!(p_c[0][1..7], [0x08, 0x04, 0x00, 1, 0, 8]);
        assert_eq!(&p_c[0][7..15], &[0x07, 0xE0, 1, 0x08, 0xF8, 0x00, 1, 0x00]);

        // Off packet (empty frame)
        let p_off = encode_keyboard_led_packets(&cfg, 0xFFFF, &[]);
        assert_eq!(
            &p_off[0][..10],
            &[0x09, 0x08, 0x02, 0x00, 0x01, 0x00, 0x03, 0, 0, 0]
        );

        // Lightbar packet (command 0x0E)
        let p_lb = encode_lightbar_packets(&[(0, [0x10, 0x20, 0x30]), (1, [0x10, 0x20, 0x30])]);
        assert_eq!(
            &p_lb[0][..13],
            &[0x09, 0x0E, 0x01, 0x00, 1, 0, 6, 0x10, 0x20, 0x30, 2, 0, 1]
        );
    }
}
