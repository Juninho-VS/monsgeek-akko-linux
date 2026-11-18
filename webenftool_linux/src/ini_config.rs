//! Parser, cache resolver, and HTTP downloader for Beiying `<Uuid>.ini` device configs.
//!
//! Verified against `WebEnfTool.exe` (`0x47bba0`, `0x47d2e0`, `0x4b94f0`, `0x4ba650`, `0x46e2b0`).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Remote HTTP config host hardcoded in `WebEnfTool.exe`.
const REMOTE_INI_HOST: &str = "120.79.152.79:80";
const REMOTE_INI_HOST_HEADER: &str = "120.79.152.79";

/// Normalized 2D coordinate and ID of a keyboard key for spatial effects.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyPos {
    pub key_id: u16,
    pub row: usize,
    pub col: usize,
    /// Normalized horizontal position in `[0.0, 1.0]`.
    pub x_norm: f32,
    /// Normalized vertical position in `[0.0, 1.0]`.
    pub y_norm: f32,
}

/// Dense RGB565 matrix slot used when firmware reports capability bit `0x04` (`0x46f350`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenseMatrixSlot {
    pub slot_index: usize,
    pub key_id: u16,
    pub led_addr: u16,
    pub col: u16,
    pub row: u16,
}

/// Complete device audio/lighting layout parsed from `<Uuid>.ini`.
#[derive(Debug, Clone)]
pub struct DeviceIniConfig {
    pub uuid: String,
    pub version: Option<String>,
    pub supported_modes: Vec<i32>,
    pub tape_count: usize,
    pub hardware_open: bool,
    pub audion_edge_rows: Vec<Vec<u16>>,
    pub key_rows: Vec<Vec<u16>>,
    pub key_columns: Vec<Vec<u16>>,
    /// Raw `[Keymaps]` entries in INI order: `(key_id, led_addresses)`.
    pub keymaps: Vec<(u16, Vec<u16>)>,
    /// Precomputed `(col, row, addr, key_id)` dense RGB565 slots for capability `0x04`.
    pub dense_matrix_slots: Vec<DenseMatrixSlot>,
    /// Precomputed `key_id -> Vec<u8>` LED addresses for capability `0x08`.
    pub grouped_rgb565_addrs: HashMap<u16, Vec<u8>>,
    /// Unified deduplicated 2D key matrix derived from `key_rows` / `key_columns` / `keymaps`.
    pub all_keys: Vec<KeyPos>,
    pub num_rows: usize,
    pub num_cols: usize,
}

/// Normalize a UUID string identically to `0x4b8b80`:
/// strip optional `"0x"`/`"0X"` prefix, keep up to 12 hex characters, uppercase.
pub fn normalize_uuid(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let filtered: String = stripped
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(12)
        .collect();
    filtered.to_ascii_uppercase()
}

/// Parse a decimal or `0x`-prefixed integer string (`QString::toInt(&ok, 0)` behavior at `0x47d4cb`).
pub fn parse_int_auto(s: &str) -> Option<i32> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).ok()
    } else if let Some(rest) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
        i32::from_str_radix(rest, 16).ok().map(|v| -v)
    } else {
        t.parse::<i32>().ok()
    }
}

/// Parse an INI text blob into `(section_lowercase -> BTreeMap<key_lowercase, (orig_key, value)>)`.
fn parse_raw_ini(text: &str) -> BTreeMap<String, Vec<(String, String)>> {
    let clean = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut sections: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut current_section = String::new();

    for raw_line in clean.lines() {
        let line = raw_line.split(';').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            sections.entry(current_section.clone()).or_default();
            continue;
        }
        if let Some((k, v_raw)) = line.split_once('=') {
            let v_unquoted = strip_matching_quotes(v_raw.trim());
            sections
                .entry(current_section.clone())
                .or_default()
                .push((k.trim().to_string(), v_unquoted.to_string()));
        }
    }
    sections
}

fn strip_matching_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn get_section_val<'a>(
    sections: &'a BTreeMap<String, Vec<(String, String)>>,
    section_names: &[&str],
    key: &str,
) -> Option<&'a str> {
    for &sec in section_names {
        if let Some(entries) = sections.get(&sec.to_ascii_lowercase()) {
            for (k, v) in entries {
                if k.eq_ignore_ascii_case(key) {
                    return Some(v.as_str());
                }
            }
        }
    }
    None
}

/// Parse `Index_numble` + `RowButton_1..=N` via comma splitting (`0x47bba0` & `0x47d2e0`).
fn parse_row_buttons_section(
    sections: &BTreeMap<String, Vec<(String, String)>>,
    section_candidates: &[&str],
    gap_as_ffff: bool,
) -> Vec<Vec<u16>> {
    let Some(count_str) = get_section_val(sections, section_candidates, "Index_numble") else {
        return Vec::new();
    };
    let Some(count) = parse_int_auto(count_str).filter(|&c| c > 0 && c <= 255) else {
        return Vec::new();
    };

    let mut rows = Vec::with_capacity(count as usize);
    for idx in 1..=count {
        let key = format!("RowButton_{idx}");
        let val = get_section_val(sections, section_candidates, &key).unwrap_or("");
        let mut parsed_row = Vec::new();
        for tok in val.split(',') {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                if gap_as_ffff {
                    parsed_row.push(0xFFFF);
                }
                continue;
            }
            if let Some(num) = parse_int_auto(trimmed) {
                if num >= 0 {
                    parsed_row.push(num as u16);
                } else if gap_as_ffff && num == -1 {
                    parsed_row.push(0xFFFF);
                }
            }
        }
        rows.push(parsed_row);
    }
    rows
}

fn transpose_rows_to_cols(rows: &[Vec<u16>]) -> Vec<Vec<u16>> {
    let max_cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut cols = vec![Vec::new(); max_cols];
    for row in rows {
        for (c, &key_id) in row.iter().enumerate() {
            if key_id != 0xFFFF {
                cols[c].push(key_id);
            }
        }
    }
    cols.retain(|c| !c.is_empty());
    cols
}

fn build_dense_matrix_slots(keymaps: &[(u16, Vec<u16>)]) -> Vec<DenseMatrixSlot> {
    // Matches `0x46e8c3`..`0x46ef50` and comparator `0x46d8d0`:
    // tuple = (col, row, addr, key_id), keep col < 6, sort by (col, row, addr, key_id), deduplicate addr.
    let mut tuples: Vec<(u16, u16, u16, u16)> = Vec::new();
    for &(key_id, ref addrs) in keymaps {
        for &addr in addrs {
            let col = addr & 0x7;
            let row = addr >> 3;
            if col < 6 {
                tuples.push((col, row, addr, key_id));
            }
        }
    }
    tuples.sort_unstable();

    let mut seen_addrs = std::collections::HashSet::new();
    let mut slots = Vec::new();
    for (col, row, addr, key_id) in tuples {
        if seen_addrs.insert(addr) {
            let slot_index = slots.len();
            slots.push(DenseMatrixSlot {
                slot_index,
                key_id,
                led_addr: addr,
                col,
                row,
            });
        }
    }
    slots
}

fn build_key_positions(
    key_rows: &[Vec<u16>],
    key_columns: &[Vec<u16>],
    keymaps: &[(u16, Vec<u16>)],
) -> (Vec<KeyPos>, usize, usize) {
    let mut positions: Vec<KeyPos> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if !key_rows.is_empty() {
        let num_rows = key_rows.len();
        let num_cols = key_rows.iter().map(Vec::len).max().unwrap_or(1).max(1);
        for (r, row) in key_rows.iter().enumerate() {
            for (c, &key_id) in row.iter().enumerate() {
                if key_id != 0xFFFF && seen.insert(key_id) {
                    positions.push(KeyPos {
                        key_id,
                        row: r,
                        col: c,
                        x_norm: if num_cols > 1 {
                            c as f32 / (num_cols - 1) as f32
                        } else {
                            0.5
                        },
                        y_norm: if num_rows > 1 {
                            r as f32 / (num_rows - 1) as f32
                        } else {
                            0.5
                        },
                    });
                }
            }
        }
        return (positions, num_rows, num_cols);
    }

    if !key_columns.is_empty() {
        let num_cols = key_columns.len();
        let num_rows = key_columns.iter().map(Vec::len).max().unwrap_or(1).max(1);
        for (c, col) in key_columns.iter().enumerate() {
            for (r, &key_id) in col.iter().enumerate() {
                if key_id != 0xFFFF && seen.insert(key_id) {
                    positions.push(KeyPos {
                        key_id,
                        row: r,
                        col: c,
                        x_norm: if num_cols > 1 {
                            c as f32 / (num_cols - 1) as f32
                        } else {
                            0.5
                        },
                        y_norm: if num_rows > 1 {
                            r as f32 / (num_rows - 1) as f32
                        } else {
                            0.5
                        },
                    });
                }
            }
        }
        return (positions, num_rows, num_cols);
    }

    if !keymaps.is_empty() {
        let cols = 16usize;
        let rows = keymaps.len().div_ceil(cols).max(1);
        for (idx, &(key_id, _)) in keymaps.iter().enumerate() {
            if seen.insert(key_id) {
                let r = idx / cols;
                let c = idx % cols;
                positions.push(KeyPos {
                    key_id,
                    row: r,
                    col: c,
                    x_norm: c as f32 / (cols - 1) as f32,
                    y_norm: if rows > 1 {
                        r as f32 / (rows - 1) as f32
                    } else {
                        0.5
                    },
                });
            }
        }
        return (positions, rows, cols);
    }

    // Fallback default 6x16 grid
    let default = DeviceIniConfig::default_75_percent("000000000000");
    (default.all_keys, default.num_rows, default.num_cols)
}

impl DeviceIniConfig {
    /// Parse a `<Uuid>.ini` file from string contents.
    pub fn parse(uuid: &str, text: &str) -> Self {
        let sections = parse_raw_ini(text);
        let uuid_norm = normalize_uuid(uuid);

        let version = get_section_val(&sections, &["DeviceConfig"], "Version")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut supported_modes: Vec<i32> =
            get_section_val(&sections, &["DeviceConfig"], "AudionTyp")
                .unwrap_or("")
                .split('|')
                .filter_map(parse_int_auto)
                .collect();
        if supported_modes.is_empty() {
            supported_modes = vec![168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 428, 180];
        }
        // `0x4b94f0` / GetSupportedEffects ensures 180 (Back Off) and 500 (LightBar Off if lightbar exists)
        if supported_modes.iter().any(|&m| m < 500) && !supported_modes.contains(&180) {
            supported_modes.push(180);
        }
        if supported_modes.iter().any(|&m| m >= 500) && !supported_modes.contains(&500) {
            supported_modes.push(500);
        }

        let raw_tape = get_section_val(&sections, &["DeviceConfig"], "Tape_Count")
            .and_then(parse_int_auto)
            .unwrap_or(0);
        let tape_count = if (1..=255).contains(&raw_tape) {
            raw_tape as usize
        } else {
            0
        };

        let audion_edge_rows = if raw_tape == 9999 || sections.contains_key("audionedge") {
            parse_row_buttons_section(&sections, &["AudionEdge"], true)
        } else {
            Vec::new()
        };

        let hardware_open = get_section_val(&sections, &["Hardware"], "OPen")
            .map(|v| v.eq_ignore_ascii_case("true") || parse_int_auto(v).unwrap_or(0) != 0)
            .unwrap_or(false);

        let key_rows =
            parse_row_buttons_section(&sections, &["Key_Rows", "The_gurgling_stream"], true);
        let mut key_columns = parse_row_buttons_section(
            &sections,
            &[
                "Key_Columns",
                "Dynamic_Spectrum",
                "Clouds_Rise_and_snow_fly",
            ],
            true,
        );
        if key_columns.is_empty() && !key_rows.is_empty() {
            key_columns = transpose_rows_to_cols(&key_rows);
        }

        let mut keymaps: Vec<(u16, Vec<u16>)> = Vec::new();
        let mut grouped_rgb565_addrs: HashMap<u16, Vec<u8>> = HashMap::new();
        if let Some(entries) = sections.get("keymaps") {
            for (k, v) in entries {
                if let Some(key_id) = parse_int_auto(k).filter(|&n| n >= 0) {
                    let addrs: Vec<u16> = v
                        .split(',')
                        .filter_map(parse_int_auto)
                        .filter(|&a| a >= 0)
                        .map(|a| a as u16)
                        .collect();
                    if !addrs.is_empty() {
                        let u8_addrs: Vec<u8> = addrs.iter().map(|&a| a as u8).collect();
                        grouped_rgb565_addrs.insert(key_id as u16, u8_addrs);
                        keymaps.push((key_id as u16, addrs));
                    }
                }
            }
        }

        let dense_matrix_slots = build_dense_matrix_slots(&keymaps);
        let (all_keys, num_rows, num_cols) = build_key_positions(&key_rows, &key_columns, &keymaps);

        Self {
            uuid: uuid_norm,
            version,
            supported_modes,
            tape_count,
            hardware_open,
            audion_edge_rows,
            key_rows,
            key_columns,
            keymaps,
            dense_matrix_slots,
            grouped_rgb565_addrs,
            all_keys,
            num_rows,
            num_cols,
        }
    }

    /// Update `keymaps`, `grouped_rgb565_addrs`, and `dense_matrix_slots` from firmware `0xA1` bead addresses.
    pub fn set_keymaps_from_beads(&mut self, keymaps: Vec<(u16, Vec<u16>)>) {
        if keymaps.is_empty() {
            return;
        }
        let mut grouped_rgb565_addrs = HashMap::with_capacity(keymaps.len());
        for (key_id, addrs) in &keymaps {
            if !addrs.is_empty() {
                grouped_rgb565_addrs.insert(*key_id, addrs.iter().map(|&a| a as u8).collect());
            }
        }
        self.grouped_rgb565_addrs = grouped_rgb565_addrs;
        self.keymaps = keymaps;
        self.dense_matrix_slots = build_dense_matrix_slots(&self.keymaps);
    }

    /// Fallback 6x16 ANSI 75% key layout (TAC75 HE / ATC75 83-key IDs) when `<Uuid>.ini` is not cached locally yet.
    pub fn default_75_percent(uuid: &str) -> Self {
        let key_rows = vec![
            vec![
                0x01, 0xFFFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                0x0D, 0x63, 0x62,
            ],
            vec![
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0xFFFF, 0x64,
            ],
            vec![
                0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0xFFFF, 0x66,
            ],
            vec![
                0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0xFFFF,
                0x36, 0xFFFF, 0x67,
            ],
            vec![
                0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0xFFFF,
                0xFFFF, 0x4A, 0x65,
            ],
            vec![
                0x43, 0x44, 0x45, 0xFFFF, 0x46, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x47, 0x48, 0x49,
                0xFFFF, 0x4C, 0x4B, 0x4D,
            ],
        ];
        let key_columns = transpose_rows_to_cols(&key_rows);
        let keymaps: Vec<(u16, Vec<u16>)> = Vec::new();
        let (all_keys, num_rows, num_cols) = build_key_positions(&key_rows, &key_columns, &keymaps);
        Self {
            uuid: normalize_uuid(uuid),
            version: Some("1.0".to_string()),
            supported_modes: vec![168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 428, 180],
            tape_count: 0,
            hardware_open: false,
            audion_edge_rows: Vec::new(),
            key_rows,
            key_columns,
            keymaps,
            dense_matrix_slots: Vec::new(),
            grouped_rgb565_addrs: HashMap::new(),
            all_keys,
            num_rows,
            num_cols,
        }
    }

    /// Return `(back_modes, lightbar_modes)` split at `< 500` / `>= 500` (`GetSupportedEffects`).
    pub fn split_effects(&self) -> (Vec<i32>, Vec<i32>) {
        let mut back: Vec<i32> = self
            .supported_modes
            .iter()
            .copied()
            .filter(|&m| m < 500)
            .collect();
        let mut lightbar: Vec<i32> = self
            .supported_modes
            .iter()
            .copied()
            .filter(|&m| m >= 500)
            .collect();
        if !back.contains(&180) {
            back.push(180);
        }
        if !lightbar.is_empty() && !lightbar.contains(&500) {
            lightbar.push(500);
        }
        (back, lightbar)
    }

    pub fn supports_mode(&self, mode: i32) -> bool {
        self.supported_modes.contains(&mode)
            || (mode == 180 && self.supported_modes.iter().any(|&m| m < 500))
            || (mode == 500 && self.supported_modes.iter().any(|&m| m >= 500))
    }
}

/// Default cache directory (`$XDG_CONFIG_HOME/webenftool-linux/Audion_Configs`).
pub fn default_config_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg)
            .join("webenftool-linux")
            .join("Audion_Configs");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home)
            .join(".config")
            .join("webenftool-linux")
            .join("Audion_Configs");
    }
    PathBuf::from("Audion_Configs")
}

/// Look for `<Uuid>.ini` case-insensitively inside `dir`.
fn find_ini_case_insensitive(dir: &Path, uuid_norm: &str) -> Option<PathBuf> {
    let target = format!("{uuid_norm}.ini");
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && s.eq_ignore_ascii_case(&target)
        {
            return Some(entry.path());
        }
    }
    None
}

/// Download `http://120.79.152.79/Audio_Config/<Uuid>.ini` using raw async HTTP/1.1.
pub async fn download_remote_ini(uuid: &str) -> Result<String, String> {
    let uuid_norm = normalize_uuid(uuid);
    if uuid_norm.is_empty() {
        return Err("Empty UUID".into());
    }
    let path = format!("/Audio_Config/{uuid_norm}.ini");
    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(REMOTE_INI_HOST))
        .await
        .map_err(|_| format!("Timed out connecting to {REMOTE_INI_HOST}"))?
        .map_err(|e| format!("TCP connect to {REMOTE_INI_HOST} failed: {e}"))?;

    fetch_http_get(stream, REMOTE_INI_HOST_HEADER, &path).await
}

async fn fetch_http_get(mut stream: TcpStream, host: &str, path: &str) -> Result<String, String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WebEnfToolLinux/2.2.1.25\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("HTTP write failed: {e}"))?;

    let mut raw = Vec::with_capacity(8192);
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut raw))
        .await
        .map_err(|_| "Timed out reading HTTP response".to_string())?
        .map_err(|e| format!("HTTP read failed: {e}"))?;

    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("Malformed HTTP response (no header terminator)".into());
    };
    let head = String::from_utf8_lossy(&raw[..hdr_end]);
    let status_ok = head.lines().next().is_some_and(|l| l.contains(" 200 "));
    if !status_ok {
        let first_line = head.lines().next().unwrap_or("<empty>");
        return Err(format!("Remote INI returned HTTP status: {first_line}"));
    }

    let body = &raw[hdr_end + 4..];
    let text = String::from_utf8_lossy(body).into_owned();
    if !text.contains('[') {
        return Err("Downloaded payload does not look like an INI file".into());
    }
    Ok(text)
}

/// Resolve `<Uuid>.ini` from explicit `--ini`, `./Audion_Configs/`, cache dir, or remote HTTP.
pub async fn resolve_device_ini(
    uuid: &str,
    explicit_ini: Option<&Path>,
    allow_http: bool,
) -> Result<(DeviceIniConfig, Option<PathBuf>), String> {
    let uuid_norm = normalize_uuid(uuid);

    if let Some(p) = explicit_ini {
        let content = fs::read_to_string(p)
            .map_err(|e| format!("Failed to read INI {}: {e}", p.display()))?;
        return Ok((
            DeviceIniConfig::parse(&uuid_norm, &content),
            Some(p.to_path_buf()),
        ));
    }

    let local_dir = Path::new("Audion_Configs");
    if let Some(found) = find_ini_case_insensitive(local_dir, &uuid_norm)
        && let Ok(content) = fs::read_to_string(&found)
    {
        return Ok((DeviceIniConfig::parse(&uuid_norm, &content), Some(found)));
    }

    let cache_dir = default_config_cache_dir();
    if let Some(found) = find_ini_case_insensitive(&cache_dir, &uuid_norm)
        && let Ok(content) = fs::read_to_string(&found)
    {
        return Ok((DeviceIniConfig::parse(&uuid_norm, &content), Some(found)));
    }

    if allow_http && !uuid_norm.is_empty() && uuid_norm != "000000000000" {
        match download_remote_ini(&uuid_norm).await {
            Ok(content) => {
                if fs::create_dir_all(&cache_dir).is_ok() {
                    let target = cache_dir.join(format!("{uuid_norm}.ini"));
                    let _ = fs::write(&target, content.as_bytes());
                    return Ok((DeviceIniConfig::parse(&uuid_norm, &content), Some(target)));
                }
                return Ok((DeviceIniConfig::parse(&uuid_norm, &content), None));
            }
            Err(e) => {
                tracing::warn!(uuid = %uuid_norm, error = %e, "Remote INI fetch failed");
            }
        }
    }

    Err(format!("No <Uuid>.ini found for UUID '{uuid_norm}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_uuid_handles_prefix_and_truncation() {
        assert_eq!(normalize_uuid("0xabcdef1234567890"), "ABCDEF123456");
        assert_eq!(normalize_uuid("  010203aabbcc "), "010203AABBCC");
    }

    #[test]
    fn parse_sample_beiying_ini() {
        let sample = "\u{feff}[DeviceConfig] ; device header\r\n\
            Version = 1.02\r\n\
            AudionTyp = 168|169|177|428\r\n\
            Tape_Count = 12\r\n\
            [Hardware]\r\n\
            OPen = 1\r\n\
            [Key_Rows]\r\n\
            Index_numble = 2\r\n\
            RowButton_1 = 0,1,-1,0x02\r\n\
            RowButton_2 = 16,17,18,\r\n\
            [Keymaps]\r\n\
            0 = 0x00\r\n\
            1 = 0x08\r\n\
            2 = 0x01,0x09\r\n";

        let cfg = DeviceIniConfig::parse("0x010203040506", sample);
        assert_eq!(cfg.uuid, "010203040506");
        assert_eq!(cfg.version.as_deref(), Some("1.02"));
        assert!(cfg.hardware_open);
        assert_eq!(cfg.tape_count, 12);
        assert!(cfg.supported_modes.contains(&180));
        assert_eq!(cfg.key_rows[0], vec![0, 1, 0xFFFF, 2]);
        assert_eq!(cfg.key_rows[1], vec![16, 17, 18, 0xFFFF]);
        // Column-major dense slots sort: (col 0, row 0, addr 0), (col 0, row 1, addr 8), (col 1, row 0, addr 1), (col 1, row 1, addr 9)
        let addrs: Vec<u16> = cfg.dense_matrix_slots.iter().map(|s| s.led_addr).collect();
        assert_eq!(addrs, vec![0x00, 0x08, 0x01, 0x09]);
        assert_eq!(cfg.grouped_rgb565_addrs.get(&2).unwrap(), &vec![1u8, 9u8]);
    }
}
