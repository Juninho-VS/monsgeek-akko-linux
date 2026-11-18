//! Shenzhen Beiying / BYTech (`Report ID 0x09`) USB HID protocol transport.
//!
//! Covers devices such as Akko TAC75 HE (`VID 0x38EE`, `PID 0x0016`, `Usage Page 0xFF00`,
//! `Report ID 0x09`, 64-byte Input/Output reports). Every command ID, packet offset,
//! aligned multi-packet chunking rule, and LED encoding path matches the verified BYTech
//! SDK and hardware descriptor.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use hidapi::{HidApi, HidDevice};
use tokio::sync::broadcast;
use tracing::{debug, trace};

use crate::Transport;
use crate::error::TransportError;
use crate::types::{ChecksumType, TimestampedEvent, TransportDeviceInfo, VendorEvent};

pub const BEIYING_REPORT_ID: u8 = 0x09;
pub const WIRED_REPORT_LEN: usize = 64;
pub const WIRELESS_REPORT_LEN: usize = 20;
pub const MAX_CHUNK_PAYLOAD: usize = 56;
pub const TAC75_KEY_COUNT: usize = 83;
pub const TAC75_NUM_ROWS: usize = 6;
pub const TAC75_NUM_COLS: usize = 16;

/// Verified BYTech `0x84`/`0x04` system parameter IDs.
pub mod param {
    pub const MAIN_LED: u8 = 1;
    pub const SIDE_LED: u8 = 6;
    pub const OS_MODE: u8 = 17;
    pub const SLEEP_TIME_S: u8 = 19;
    pub const WIN_LOCK: u8 = 21;
    pub const POLLING_RATE: u8 = 23;
    pub const ADAPTIVE_CAL: u8 = 25;
    pub const DEBOUNCE_MODE: u8 = 29;
    pub const DEBOUNCE_MS: u8 = 30;
    pub const LOW_POWER: u8 = 32;
    pub const WASD_SWAP: u8 = 33;
    pub const SIDE_SYNC: u8 = 34;
}

/// Verified BYTech `0x11` reset targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BeiyingResetTarget {
    Full = 0,
    Keymap = 1,
    Lighting = 2,
    Usb = 3,
}

/// Read-only HID report descriptor summary confirming Beiying Report ID `0x09` support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report09Capability {
    pub vendor_usage_page: u16,
    pub input_report_bytes: usize,
    pub output_report_bytes: usize,
}

/// Physical slot definition for a BYTech matrix key (`TAC75 HE` / `ATC75` 83-key ANSI 75%).
#[derive(Debug, Clone, Copy)]
pub struct BeiyingKeySlot {
    pub slot_index: usize,
    pub key_id: u16,
    pub hid_usage: u8,
    pub name: &'static str,
    pub row: u8,
    pub col: u8,
    pub x_norm: f32,
    pub y_norm: f32,
}

/// Verified 83-key Akko TAC75 HE (`UUID 0x11000000004D`) layout in row-major visual order.
#[rustfmt::skip]
pub static TAC75_SLOTS: &[BeiyingKeySlot] = &[
    // Row 0 (15 keys, col 1 intentionally blank between Esc and F1)
    BeiyingKeySlot { slot_index: 0,  key_id: 0x01, hid_usage: 0x29, name: "Esc",       row: 0, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 1,  key_id: 0x02, hid_usage: 0x3A, name: "F1",        row: 0, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 2,  key_id: 0x03, hid_usage: 0x3B, name: "F2",        row: 0, col: 3,  x_norm: 3.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 3,  key_id: 0x04, hid_usage: 0x3C, name: "F3",        row: 0, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 4,  key_id: 0x05, hid_usage: 0x3D, name: "F4",        row: 0, col: 5,  x_norm: 5.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 5,  key_id: 0x06, hid_usage: 0x3E, name: "F5",        row: 0, col: 6,  x_norm: 6.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 6,  key_id: 0x07, hid_usage: 0x3F, name: "F6",        row: 0, col: 7,  x_norm: 7.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 7,  key_id: 0x08, hid_usage: 0x40, name: "F7",        row: 0, col: 8,  x_norm: 8.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 8,  key_id: 0x09, hid_usage: 0x41, name: "F8",        row: 0, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 9,  key_id: 0x0A, hid_usage: 0x42, name: "F9",        row: 0, col: 10, x_norm: 10.0 / 15.0, y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 10, key_id: 0x0B, hid_usage: 0x43, name: "F10",       row: 0, col: 11, x_norm: 11.0 / 15.0, y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 11, key_id: 0x0C, hid_usage: 0x44, name: "F11",       row: 0, col: 12, x_norm: 12.0 / 15.0, y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 12, key_id: 0x0D, hid_usage: 0x45, name: "F12",       row: 0, col: 13, x_norm: 13.0 / 15.0, y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 13, key_id: 0x63, hid_usage: 0x4C, name: "Del",       row: 0, col: 14, x_norm: 14.0 / 15.0, y_norm: 0.0 },
    BeiyingKeySlot { slot_index: 14, key_id: 0x62, hid_usage: 0x49, name: "Ins",       row: 0, col: 15, x_norm: 1.0,         y_norm: 0.0 },
    // Row 1 (15 keys)
    BeiyingKeySlot { slot_index: 15, key_id: 0x0E, hid_usage: 0x35, name: "`",         row: 1, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 16, key_id: 0x0F, hid_usage: 0x1E, name: "1",         row: 1, col: 1,  x_norm: 1.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 17, key_id: 0x10, hid_usage: 0x1F, name: "2",         row: 1, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 18, key_id: 0x11, hid_usage: 0x20, name: "3",         row: 1, col: 3,  x_norm: 3.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 19, key_id: 0x12, hid_usage: 0x21, name: "4",         row: 1, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 20, key_id: 0x13, hid_usage: 0x22, name: "5",         row: 1, col: 5,  x_norm: 5.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 21, key_id: 0x14, hid_usage: 0x23, name: "6",         row: 1, col: 6,  x_norm: 6.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 22, key_id: 0x15, hid_usage: 0x24, name: "7",         row: 1, col: 7,  x_norm: 7.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 23, key_id: 0x16, hid_usage: 0x25, name: "8",         row: 1, col: 8,  x_norm: 8.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 24, key_id: 0x17, hid_usage: 0x26, name: "9",         row: 1, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 25, key_id: 0x18, hid_usage: 0x27, name: "0",         row: 1, col: 10, x_norm: 10.0 / 15.0, y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 26, key_id: 0x19, hid_usage: 0x2D, name: "-",         row: 1, col: 11, x_norm: 11.0 / 15.0, y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 27, key_id: 0x1A, hid_usage: 0x2E, name: "=",         row: 1, col: 12, x_norm: 12.0 / 15.0, y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 28, key_id: 0x1B, hid_usage: 0x2A, name: "Backspace", row: 1, col: 13, x_norm: 13.0 / 15.0, y_norm: 0.2 },
    BeiyingKeySlot { slot_index: 29, key_id: 0x64, hid_usage: 0x4A, name: "Home",      row: 1, col: 15, x_norm: 1.0,         y_norm: 0.2 },
    // Row 2 (15 keys)
    BeiyingKeySlot { slot_index: 30, key_id: 0x1C, hid_usage: 0x2B, name: "Tab",       row: 2, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 31, key_id: 0x1D, hid_usage: 0x14, name: "Q",         row: 2, col: 1,  x_norm: 1.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 32, key_id: 0x1E, hid_usage: 0x1A, name: "W",         row: 2, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 33, key_id: 0x1F, hid_usage: 0x08, name: "E",         row: 2, col: 3,  x_norm: 3.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 34, key_id: 0x20, hid_usage: 0x15, name: "R",         row: 2, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 35, key_id: 0x21, hid_usage: 0x17, name: "T",         row: 2, col: 5,  x_norm: 5.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 36, key_id: 0x22, hid_usage: 0x1C, name: "Y",         row: 2, col: 6,  x_norm: 6.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 37, key_id: 0x23, hid_usage: 0x18, name: "U",         row: 2, col: 7,  x_norm: 7.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 38, key_id: 0x24, hid_usage: 0x0C, name: "I",         row: 2, col: 8,  x_norm: 8.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 39, key_id: 0x25, hid_usage: 0x12, name: "O",         row: 2, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 40, key_id: 0x26, hid_usage: 0x13, name: "P",         row: 2, col: 10, x_norm: 10.0 / 15.0, y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 41, key_id: 0x27, hid_usage: 0x2F, name: "[",         row: 2, col: 11, x_norm: 11.0 / 15.0, y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 42, key_id: 0x28, hid_usage: 0x30, name: "]",         row: 2, col: 12, x_norm: 12.0 / 15.0, y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 43, key_id: 0x29, hid_usage: 0x31, name: "\\",        row: 2, col: 13, x_norm: 13.0 / 15.0, y_norm: 0.4 },
    BeiyingKeySlot { slot_index: 44, key_id: 0x66, hid_usage: 0x4B, name: "PgUp",      row: 2, col: 15, x_norm: 1.0,         y_norm: 0.4 },
    // Row 3 (14 keys)
    BeiyingKeySlot { slot_index: 45, key_id: 0x2A, hid_usage: 0x39, name: "Caps",      row: 3, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 46, key_id: 0x2B, hid_usage: 0x04, name: "A",         row: 3, col: 1,  x_norm: 1.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 47, key_id: 0x2C, hid_usage: 0x16, name: "S",         row: 3, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 48, key_id: 0x2D, hid_usage: 0x07, name: "D",         row: 3, col: 3,  x_norm: 3.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 49, key_id: 0x2E, hid_usage: 0x09, name: "F",         row: 3, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 50, key_id: 0x2F, hid_usage: 0x0A, name: "G",         row: 3, col: 5,  x_norm: 5.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 51, key_id: 0x30, hid_usage: 0x0B, name: "H",         row: 3, col: 6,  x_norm: 6.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 52, key_id: 0x31, hid_usage: 0x0D, name: "J",         row: 3, col: 7,  x_norm: 7.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 53, key_id: 0x32, hid_usage: 0x0E, name: "K",         row: 3, col: 8,  x_norm: 8.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 54, key_id: 0x33, hid_usage: 0x0F, name: "L",         row: 3, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 55, key_id: 0x34, hid_usage: 0x33, name: ";",         row: 3, col: 10, x_norm: 10.0 / 15.0, y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 56, key_id: 0x35, hid_usage: 0x34, name: "'",         row: 3, col: 11, x_norm: 11.0 / 15.0, y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 57, key_id: 0x36, hid_usage: 0x28, name: "Enter",     row: 3, col: 13, x_norm: 13.0 / 15.0, y_norm: 0.6 },
    BeiyingKeySlot { slot_index: 58, key_id: 0x67, hid_usage: 0x4E, name: "PgDn",      row: 3, col: 15, x_norm: 1.0,         y_norm: 0.6 },
    // Row 4 (14 keys)
    BeiyingKeySlot { slot_index: 59, key_id: 0x37, hid_usage: 0xE1, name: "LShift",    row: 4, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 60, key_id: 0x38, hid_usage: 0x1D, name: "Z",         row: 4, col: 1,  x_norm: 1.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 61, key_id: 0x39, hid_usage: 0x1B, name: "X",         row: 4, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 62, key_id: 0x3A, hid_usage: 0x06, name: "C",         row: 4, col: 3,  x_norm: 3.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 63, key_id: 0x3B, hid_usage: 0x19, name: "V",         row: 4, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 64, key_id: 0x3C, hid_usage: 0x05, name: "B",         row: 4, col: 5,  x_norm: 5.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 65, key_id: 0x3D, hid_usage: 0x11, name: "N",         row: 4, col: 6,  x_norm: 6.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 66, key_id: 0x3E, hid_usage: 0x10, name: "M",         row: 4, col: 7,  x_norm: 7.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 67, key_id: 0x3F, hid_usage: 0x36, name: ",",         row: 4, col: 8,  x_norm: 8.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 68, key_id: 0x40, hid_usage: 0x37, name: ".",         row: 4, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 69, key_id: 0x41, hid_usage: 0x38, name: "/",         row: 4, col: 10, x_norm: 10.0 / 15.0, y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 70, key_id: 0x42, hid_usage: 0xE5, name: "RShift",    row: 4, col: 11, x_norm: 11.0 / 15.0, y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 71, key_id: 0x4A, hid_usage: 0x52, name: "Up",        row: 4, col: 14, x_norm: 14.0 / 15.0, y_norm: 0.8 },
    BeiyingKeySlot { slot_index: 72, key_id: 0x65, hid_usage: 0x4D, name: "End",       row: 4, col: 15, x_norm: 1.0,         y_norm: 0.8 },
    // Row 5 (10 keys)
    BeiyingKeySlot { slot_index: 73, key_id: 0x43, hid_usage: 0xE0, name: "LCtrl",     row: 5, col: 0,  x_norm: 0.0 / 15.0,  y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 74, key_id: 0x44, hid_usage: 0xE3, name: "LWin",      row: 5, col: 1,  x_norm: 1.0 / 15.0,  y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 75, key_id: 0x45, hid_usage: 0xE2, name: "LAlt",      row: 5, col: 2,  x_norm: 2.0 / 15.0,  y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 76, key_id: 0x46, hid_usage: 0x2C, name: "Space",     row: 5, col: 4,  x_norm: 4.0 / 15.0,  y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 77, key_id: 0x47, hid_usage: 0xE6, name: "RAlt",      row: 5, col: 9,  x_norm: 9.0 / 15.0,  y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 78, key_id: 0x48, hid_usage: 0x00, name: "Fn",        row: 5, col: 10, x_norm: 10.0 / 15.0, y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 79, key_id: 0x49, hid_usage: 0xE4, name: "RCtrl",     row: 5, col: 11, x_norm: 11.0 / 15.0, y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 80, key_id: 0x4C, hid_usage: 0x50, name: "Left",      row: 5, col: 13, x_norm: 13.0 / 15.0, y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 81, key_id: 0x4B, hid_usage: 0x51, name: "Down",      row: 5, col: 14, x_norm: 14.0 / 15.0, y_norm: 1.0 },
    BeiyingKeySlot { slot_index: 82, key_id: 0x4D, hid_usage: 0x4F, name: "Right",     row: 5, col: 15, x_norm: 1.0,         y_norm: 1.0 },
];

/// LED matrix slot for dense RGB565 (`0x08 0x03`) streaming (`0xA1` bead map).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenseMatrixSlot {
    pub key_id: u16,
    pub led_addr: u16,
    pub col: u16,
    pub row: u16,
}

/// Hardware capabilities discovered at open via `0x82` & `0xA1`.
#[derive(Debug, Clone)]
pub struct BeiyingSessionInfo {
    pub uuid_hex: String,
    pub uuid_u64: u64,
    pub synthetic_device_id: u32,
    pub fw_version: u16,
    pub min_rt_um: u8,
    pub precision_um: u8,
    pub music_supported: bool,
    pub side_light_available: bool,
    pub logo_light_available: bool,
    pub side_light_count: u8,
    pub led_proto_flags: u16,
    pub has_direction: bool,
    pub has_side_sync: bool,
    pub profile_count: u8,
    pub switch_mask: u32,
    pub adv_key_mask: u32,
    pub dense_matrix_slots: Vec<DenseMatrixSlot>,
    pub grouped_rgb565_addrs: BTreeMap<u16, Vec<u8>>,
}

/// Main or side LED effect configuration (`0x84`/`0x04` params `1` & `6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BeiyingLedParams {
    pub effect_id: u8,
    pub color_idx: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
    /// Main LED uses `0..=20`; side LED uses `0..=4`.
    pub brightness: u8,
    pub speed: u8,
    pub direction: u8,
}

/// Keyboard hardware option toggles (`0x84`/`0x04` params `17, 21, 25, 33, 34`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BeiyingKbOptions {
    pub os_mode: u8,
    pub win_lock: bool,
    pub adaptive_cal: bool,
    pub wasd_swap: bool,
    pub side_sync: bool,
}

/// Per-key rapid-trigger configuration (`0x99`/`0x19`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeiyingRtEntry {
    pub key_id: u16,
    pub enabled: bool,
    pub press_um: u16,
    pub release_um: u16,
}

/// Per-key deadzone configuration (`0x96`/`0x16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeiyingDeadzoneEntry {
    pub key_id: u16,
    pub top_um: u16,
    pub bottom_um: u16,
    pub enabled: bool,
}

/// Passive sysfs check returning `/sys/class/hidraw/<name>/device/report_descriptor`.
pub fn read_sysfs_report_descriptor(hidraw_path: &str) -> Option<Vec<u8>> {
    let dev_name = Path::new(hidraw_path).file_name()?.to_str()?;
    if !dev_name.starts_with("hidraw") {
        return None;
    }
    let sys_path = Path::new("/sys/class/hidraw")
        .join(dev_name)
        .join("device/report_descriptor");
    fs::read(sys_path).ok()
}

/// Passive sysfs descriptor check confirming a Beiying `Report ID 0x09` interface.
pub fn is_beiying_hidraw_device(hidraw_path: &str) -> Option<Report09Capability> {
    read_sysfs_report_descriptor(hidraw_path).and_then(|d| parse_beiying_report09_descriptor(&d))
}

/// Parse a raw USB HID report descriptor and verify a top-level vendor collection (`>= 0xFF00`)
/// exposing `Report ID 0x09` for both Input and Output.
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
            _ => 4,
        };
        if i + item_len > desc.len() {
            break;
        }

        let mut val: u32 = 0;
        for b in 0..item_len {
            val |= (desc[i + b] as u32) << (8 * b);
        }
        i += item_len;

        let item_type = (prefix >> 2) & 0x03;
        let item_tag = (prefix >> 4) & 0x0F;

        match (item_type, item_tag) {
            (1, 0) => usage_page = val,
            (1, 7) => report_size = val,
            (1, 8) => report_id = val,
            (1, 9) => report_count = val,
            (0, 10) => {
                if depth == 0 && (0xFF00..=0xFFFF).contains(&usage_page) {
                    active_top_vendor = true;
                    top_vendor_page = Some(usage_page as u16);
                }
                depth += 1;
            }
            (0, 12) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    active_top_vendor = false;
                }
            }
            (0, 8) if active_top_vendor && report_id == BEIYING_REPORT_ID as u32 => {
                let bytes = 1 + ((report_size * report_count) as usize).div_ceil(8);
                if bytes == WIRED_REPORT_LEN || bytes == WIRELESS_REPORT_LEN {
                    input_bytes = Some(bytes);
                }
            }
            (0, 9) if active_top_vendor && report_id == BEIYING_REPORT_ID as u32 => {
                let bytes = 1 + ((report_size * report_count) as usize).div_ceil(8);
                if bytes == WIRED_REPORT_LEN || bytes == WIRELESS_REPORT_LEN {
                    output_bytes = Some(bytes);
                }
            }
            _ => {}
        }
    }

    match (top_vendor_page, input_bytes, output_bytes) {
        (Some(vp), Some(in_b), Some(out_b)) if in_b == out_b => Some(Report09Capability {
            vendor_usage_page: vp,
            input_report_bytes: in_b,
            output_report_bytes: out_b,
        }),
        _ => None,
    }
}

/// Apply BYTech trailer checksum `pkt[63] = !sum(pkt[0..63])`.
#[inline]
pub fn apply_checksum_64(pkt: &mut [u8; WIRED_REPORT_LEN]) {
    let sum = pkt[..WIRED_REPORT_LEN - 1]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    pkt[WIRED_REPORT_LEN - 1] = !sum;
}

/// Verify `pkt[63] == !sum(pkt[0..63])`.
#[inline]
pub fn verify_checksum_64(pkt: &[u8]) -> bool {
    if pkt.len() < WIRED_REPORT_LEN {
        return false;
    }
    let sum = pkt[..WIRED_REPORT_LEN - 1]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    pkt[WIRED_REPORT_LEN - 1] == !sum
}

/// Build a single checksummed 64-byte BYTech HID report packet.
pub fn build_packet_64(
    cmd: u8,
    param: u8,
    b3: u8,
    total_pkts: u8,
    cur_pkt: u8,
    payload: &[u8],
) -> [u8; WIRED_REPORT_LEN] {
    let mut pkt = [0u8; WIRED_REPORT_LEN];
    let len = payload.len().min(MAX_CHUNK_PAYLOAD);
    pkt[0] = BEIYING_REPORT_ID;
    pkt[1] = cmd;
    pkt[2] = param;
    pkt[3] = b3;
    pkt[4] = total_pkts;
    pkt[5] = cur_pkt;
    pkt[6] = len as u8;
    pkt[7..7 + len].copy_from_slice(&payload[..len]);
    apply_checksum_64(&mut pkt);
    pkt
}

/// Encode `[R, G, B]` to big-endian RGB565.
#[inline]
pub fn rgb_to_rgb565_be(rgb: [u8; 3]) -> [u8; 2] {
    let r = (rgb[0] as u16 & 0xF8) << 8;
    let g = (rgb[1] as u16 & 0xFC) << 3;
    let b = (rgb[2] as u16) >> 3;
    (r | g | b).to_be_bytes()
}

/// Map Hz to BYTech polling-rate wire byte (`0x84`/`0x04` param `23`).
pub fn polling_rate_to_byte(hz: u16) -> Option<u8> {
    match hz {
        1000 => Some(0),
        500 => Some(1),
        250 => Some(2),
        125 => Some(3),
        8000 => Some(4),
        4000 => Some(5),
        2000 => Some(6),
        _ => None,
    }
}

/// Map BYTech polling-rate wire byte (`0..=6`) to Hz.
pub fn byte_to_polling_rate(code: u8) -> Option<u16> {
    match code {
        0 => Some(1000),
        1 => Some(500),
        2 => Some(250),
        3 => Some(125),
        4 => Some(8000),
        5 => Some(4000),
        6 => Some(2000),
        _ => None,
    }
}

/// Convert Rongyuan 4-byte keymatrix config `[type, p0, p1, p2]` into BYTech `u32` keycode.
pub fn config_to_bytech_keycode(cfg: [u8; 4]) -> u32 {
    match cfg {
        [0, 0, 0, 0] => 0,
        [0, a, b, c] => {
            let usages: Vec<u8> = [a, b, c].into_iter().filter(|&u| u != 0).collect();
            if usages.is_empty() {
                0
            } else if usages.len() == 1 {
                usages[0] as u32
            } else {
                let mut mods = 0u8;
                let mut primary = 0u8;
                for u in usages {
                    if (0xE0..=0xE7).contains(&u) {
                        mods |= 1 << (u - 0xE0);
                    } else if primary == 0 {
                        primary = u;
                    }
                }
                ((mods as u32) << 16) | (primary as u32)
            }
        }
        [1, _, btn, _] => 0x0101_0000 | (btn as u32),
        [3, _, lo, hi] => 0x0200_0000 | ((hi as u32) << 8) | (lo as u32),
        [9, kind, index, _] => 0x0300_0000 | ((kind as u32) << 16) | (index as u32),
        [10, 1, _, _] => 0x0D00_0000,
        [0xFE, hi, mid, lo] => ((hi as u32) << 24) | ((mid as u32) << 8) | (lo as u32),
        _ => 0,
    }
}

/// Convert BYTech `u32` keycode into Rongyuan 4-byte keymatrix config `[type, p0, p1, p2]`.
pub fn bytech_keycode_to_config(kc: u32) -> [u8; 4] {
    if kc == 0 {
        return [0, 0, 0, 0];
    }
    match (kc >> 24) as u8 {
        0x00 => {
            let mods = ((kc >> 16) & 0xFF) as u8;
            let usage = (kc & 0xFF) as u8;
            if mods == 0 {
                [0, 0, usage, 0]
            } else if usage == 0 && mods.count_ones() == 1 {
                let bit = mods.trailing_zeros() as u8;
                [0, 0, 0xE0 + bit, 0]
            } else {
                let mut slots = [0u8; 3];
                let mut idx = 0usize;
                for bit in 0..8u8 {
                    if (mods & (1 << bit)) != 0 && idx < 3 {
                        slots[idx] = 0xE0 + bit;
                        idx += 1;
                    }
                }
                if usage != 0 && idx < 3 {
                    slots[idx] = usage;
                }
                [0, slots[0], slots[1], slots[2]]
            }
        }
        0x01 => [1, 0, (kc & 0xFF) as u8, 0],
        0x02 => {
            let code = (kc & 0xFFFF) as u16;
            [3, 0, code as u8, (code >> 8) as u8]
        }
        0x03 => [9, ((kc >> 16) & 0xFF) as u8, (kc & 0xFF) as u8, 0],
        0x0D => [10, 1, 0, 0],
        other => [0xFE, other, ((kc >> 8) & 0xFF) as u8, (kc & 0xFF) as u8],
    }
}

/// Build sorted/deduplicated dense RGB565 LED slots from `0xA1` bead addresses.
pub fn build_dense_matrix_slots(key_beads: &[(u16, Vec<u16>)]) -> Vec<DenseMatrixSlot> {
    let mut tuples: Vec<(u16, u16, u16, u16)> = Vec::new();
    for (key_id, addrs) in key_beads {
        for &addr in addrs {
            let col = addr & 0x7;
            let row = addr >> 3;
            if col < 6 {
                tuples.push((col, row, addr, *key_id));
            }
        }
    }
    tuples.sort_unstable();

    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(tuples.len());
    for (col, row, addr, key_id) in tuples {
        if seen.insert(addr) {
            out.push(DenseMatrixSlot {
                key_id,
                led_addr: addr,
                col,
                row,
            });
        }
    }
    out
}

fn layer_sys_byte(layer: u8, os_mode: u8) -> u8 {
    (layer & 0x03) | ((os_mode & 0x07) << 2)
}

fn synthetic_id_from_uuid(uuid: u64) -> u32 {
    let high = ((uuid >> 32) as u16) as u32;
    let low = (uuid & 0xFFFF) as u32;
    let id = (high << 16) | low;
    if id == 0 { 0x1100_004D } else { id }
}

/// Synchronous transport & rich typed API for Shenzhen Beiying `Report ID 0x09` devices.
pub struct HidBeiyingTransport {
    device: Arc<Mutex<HidDevice>>,
    info: TransportDeviceInfo,
    session: BeiyingSessionInfo,
    connected: Arc<AtomicBool>,
    monitoring_active: Arc<AtomicBool>,
    pause_worker: Arc<(Mutex<bool>, Condvar)>,
    event_tx: broadcast::Sender<TimestampedEvent>,
    pending_events: Arc<Mutex<VecDeque<VendorEvent>>>,
    pending_synthetic_reads: Mutex<VecDeque<Vec<u8>>>,
    start_time: Instant,
    os_mode_cache: std::sync::atomic::AtomicU8,
    um_per_unit: u16,
}

impl Drop for HidBeiyingTransport {
    fn drop(&mut self) {
        self.monitoring_active.store(false, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);
    }
}

impl HidBeiyingTransport {
    /// Open a verified Beiying `Report ID 0x09` device and perform the `0x82` / `0xA1` handshake.
    pub fn open(
        device_info: &hidapi::DeviceInfo,
        transport_info: TransportDeviceInfo,
        api: &HidApi,
    ) -> Result<Self, TransportError> {
        let dev = device_info.open_device(api).map_err(TransportError::from)?;
        Self::from_hid_device(dev, transport_info)
    }

    /// Initialize from an already-opened `HidDevice`.
    pub fn from_hid_device(
        dev: HidDevice,
        info: TransportDeviceInfo,
    ) -> Result<Self, TransportError> {
        let path_str = info.device_path.clone();
        if let Some(cap) = is_beiying_hidraw_device(&path_str) {
            debug!(
                "Verified sysfs Report ID 0x09 on {} (usage_page=0x{:04X}, {}B)",
                path_str, cap.vendor_usage_page, cap.output_report_bytes
            );
        } else {
            let mut raw_desc = [0u8; 4096];
            let n = dev
                .get_report_descriptor(&mut raw_desc)
                .map_err(TransportError::from)?;
            if parse_beiying_report09_descriptor(&raw_desc[..n]).is_none() {
                return Err(TransportError::DeviceNotFound(format!(
                    "{path_str} does not expose Beiying Report ID 0x09"
                )));
            }
        }

        drain_device_rx(&dev);
        let uuid_raw = query_single(&dev, 0x82, 1, 0, &[], 0).ok();
        let (uuid_hex, uuid_u64) = match uuid_raw.as_deref() {
            Some(d) if d.len() >= 6 && d[0] != 0 => {
                let hex = format!(
                    "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    d[0], d[1], d[2], d[3], d[4], d[5]
                );
                let val = u64::from_be_bytes([0, 0, d[0], d[1], d[2], d[3], d[4], d[5]]);
                (hex, val)
            }
            _ => ("11000000004D".to_string(), 0x1100_0000_004D),
        };
        let fw_version = query_single(&dev, 0x82, 2, 0, &[], 0)
            .ok()
            .filter(|d| d.len() >= 2)
            .map(|d| u16::from_le_bytes([d[0], d[1]]))
            .unwrap_or(0x0100);
        let switch_mask = query_single(&dev, 0x82, 3, 0, &[], 0)
            .ok()
            .filter(|d| d.len() >= 4)
            .map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
            .unwrap_or(0);
        let adv_key_mask = query_single(&dev, 0x82, 4, 0, &[], 0)
            .ok()
            .filter(|d| d.len() >= 4)
            .map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
            .unwrap_or(0);
        let min_rt_um = query_single(&dev, 0x82, 6, 0, &[], 0)
            .ok()
            .and_then(|d| d.first().copied())
            .filter(|&v| v > 0)
            .unwrap_or(10);
        let precision_um = query_single(&dev, 0x82, 8, 0, &[], 0)
            .ok()
            .and_then(|d| d.first().copied())
            .filter(|&v| v > 0)
            .unwrap_or(10);

        let lighting_caps = query_single(&dev, 0x82, 9, 0, &[], 0).ok();
        let music_supported = lighting_caps
            .as_ref()
            .and_then(|d| d.get(17).copied())
            .is_some_and(|v| v != 0);
        let side_light_available = lighting_caps
            .as_ref()
            .and_then(|d| d.get(18).copied())
            .is_some_and(|v| v != 0);
        let logo_light_available = lighting_caps
            .as_ref()
            .and_then(|d| d.get(19).copied())
            .is_some_and(|v| v != 0);
        let side_light_count = lighting_caps
            .as_ref()
            .and_then(|d| d.get(20).copied())
            .unwrap_or(0);

        // `0x82 0x0F` with `pkt[5] = 0x34` matches the verified desktop feature query.
        let feat = query_single(&dev, 0x82, 15, 0, &[], 0x34).ok();
        let raw_led_flag = feat.as_ref().and_then(|d| d.get(9).copied()).unwrap_or(0);
        let led_proto_flags = if raw_led_flag == 0 {
            0xFFFF
        } else {
            raw_led_flag as u16
        };
        let has_direction = feat
            .as_ref()
            .and_then(|d| d.get(16).copied())
            .is_some_and(|v| v != 0);
        let has_side_sync = feat
            .as_ref()
            .and_then(|d| d.get(17).copied())
            .is_some_and(|v| v != 0);
        let raw_profiles = feat.as_ref().and_then(|d| d.get(18).copied()).unwrap_or(4);
        let profile_count = if raw_profiles == 0 { 4 } else { raw_profiles };

        let (dense_matrix_slots, grouped_rgb565_addrs) =
            if led_proto_flags != 0xFFFF && (led_proto_flags & 0x0C) != 0 {
                let ids: Vec<u16> = TAC75_SLOTS.iter().map(|s| s.key_id).collect();
                let beads = query_led_beads_raw(&dev, &ids);
                let dense = build_dense_matrix_slots(&beads);
                let mut grouped = BTreeMap::new();
                for (id, addrs) in beads {
                    if !addrs.is_empty() {
                        grouped.insert(id, addrs.into_iter().map(|a| a as u8).collect());
                    }
                }
                (dense, grouped)
            } else {
                (Vec::new(), BTreeMap::new())
            };

        let os_mode = query_single(&dev, 0x84, param::OS_MODE, 0, &[], 0)
            .ok()
            .and_then(|d| d.first().copied())
            .unwrap_or(0);

        let um_per_unit = match precision_um {
            1 => 1,
            5 => 5,
            10 => 10,
            50.. => 100,
            _ => 10,
        };

        let session = BeiyingSessionInfo {
            uuid_hex,
            uuid_u64,
            synthetic_device_id: synthetic_id_from_uuid(uuid_u64),
            fw_version,
            min_rt_um,
            precision_um,
            music_supported,
            side_light_available,
            logo_light_available,
            side_light_count,
            led_proto_flags,
            has_direction,
            has_side_sync,
            profile_count,
            switch_mask,
            adv_key_mask,
            dense_matrix_slots,
            grouped_rgb565_addrs,
        };

        let (event_tx, _) = broadcast::channel(256);
        let device = Arc::new(Mutex::new(dev));
        let connected = Arc::new(AtomicBool::new(true));
        let monitoring_active = Arc::new(AtomicBool::new(false));
        let pause_worker = Arc::new((Mutex::new(false), Condvar::new()));
        let pending_events = Arc::new(Mutex::new(VecDeque::new()));
        let start_time = Instant::now();

        let me = Self {
            device,
            info,
            session,
            connected,
            monitoring_active,
            pause_worker,
            event_tx,
            pending_events,
            pending_synthetic_reads: Mutex::new(VecDeque::new()),
            start_time,
            os_mode_cache: std::sync::atomic::AtomicU8::new(os_mode),
            um_per_unit,
        };

        me.spawn_monitor_thread();
        Ok(me)
    }

    fn spawn_monitor_thread(&self) {
        let device = Arc::clone(&self.device);
        let connected = Arc::clone(&self.connected);
        let monitoring = Arc::clone(&self.monitoring_active);
        let pause = Arc::clone(&self.pause_worker);
        let event_tx = self.event_tx.clone();
        let pending_events = Arc::clone(&self.pending_events);
        let start_time = self.start_time;
        let um_per_unit = self.um_per_unit;

        let _ = std::thread::Builder::new()
            .name("beiying-monitor".to_string())
            .spawn(move || {
                let mut last_keepalive = Instant::now();
                while connected.load(Ordering::Relaxed) {
                    if !monitoring.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }

                    {
                        let (lock, cvar) = &*pause;
                        let mut paused = lock.lock().unwrap();
                        while *paused && connected.load(Ordering::Relaxed) {
                            paused = cvar.wait(paused).unwrap();
                        }
                    }
                    if !connected.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut evs = Vec::new();
                    {
                        let Ok(guard) = device.lock() else {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        };
                        if last_keepalive.elapsed() >= Duration::from_millis(850) {
                            let ka = build_packet_64(0x98, 0x00, 0, 1, 0, &[]);
                            let _ = guard.write(&ka);
                            last_keepalive = Instant::now();
                        }
                        let mut rx = [0u8; WIRED_REPORT_LEN];
                        if let Ok(n) = guard.read_timeout(&mut rx, 10)
                            && n >= 7
                            && rx[0] == BEIYING_REPORT_ID
                        {
                            parse_bubble_events(&rx[..n], um_per_unit, &mut evs);
                        }
                    }

                    for ev in evs {
                        let ts =
                            TimestampedEvent::new(start_time.elapsed().as_secs_f64(), ev.clone());
                        let _ = event_tx.send(ts);
                        if let Ok(mut q) = pending_events.lock() {
                            if q.len() >= 128 {
                                q.pop_front();
                            }
                            q.push_back(ev);
                        }
                    }
                }
            });
    }

    /// Access hardware capabilities discovered at handshake.
    pub fn session(&self) -> &BeiyingSessionInfo {
        &self.session
    }

    /// Micrometres per canonical `Precision` unit (`10` for `0.01mm`, `5` for `0.005mm`, etc.).
    pub fn um_per_unit(&self) -> u16 {
        self.um_per_unit
    }

    /// Physical key slots (`TAC75 HE`, 83 keys).
    pub fn key_slots(&self) -> &'static [BeiyingKeySlot] {
        TAC75_SLOTS
    }

    pub fn key_count(&self) -> usize {
        TAC75_SLOTS.len()
    }

    pub fn slot_to_key_id(&self, slot: usize) -> Option<u16> {
        TAC75_SLOTS.get(slot).map(|s| s.key_id)
    }

    pub fn key_id_to_slot(&self, key_id: u16) -> Option<usize> {
        TAC75_SLOTS
            .iter()
            .find(|s| s.key_id == key_id)
            .map(|s| s.slot_index)
    }

    pub fn os_mode(&self) -> u8 {
        self.os_mode_cache.load(Ordering::Relaxed)
    }

    /// Pause the monitor thread briefly while executing a synchronous HID command.
    fn with_dev_sync<F, T>(&self, f: F) -> Result<T, TransportError>
    where
        F: FnOnce(&HidDevice) -> Result<T, TransportError>,
    {
        let (lock, cvar) = &*self.pause_worker;
        {
            let mut paused = lock.lock().unwrap();
            *paused = true;
        }
        let guard = self
            .device
            .lock()
            .map_err(|_| TransportError::Disconnected)?;
        let res = f(&guard);
        drop(guard);
        {
            let mut paused = lock.lock().unwrap();
            *paused = false;
            cvar.notify_all();
        }
        res
    }

    /// Write a single command packet (fire-and-forget / streaming).
    fn send_stream_packets(
        &self,
        packets: &[[u8; WIRED_REPORT_LEN]],
    ) -> Result<(), TransportError> {
        let guard = self
            .device
            .lock()
            .map_err(|_| TransportError::Disconnected)?;
        for pkt in packets {
            guard.write(pkt).map_err(TransportError::from)?;
        }
        Ok(())
    }

    /// Send a synchronous multi-packet request (`0x82..0x99`, `0x04..0x19`) and wait for ack.
    fn send_cmd_wait(
        &self,
        cmd: u8,
        param: u8,
        b3: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        self.with_dev_sync(|dev| {
            drain_device_rx(dev);
            send_packets_chunked(dev, cmd, param, b3, payload)?;
            read_assembled_reply(dev, cmd, param, 500)
        })
    }

    /// Query a small command (`len == 0` request) and return payload slice.
    fn query_cmd(
        &self,
        cmd: u8,
        param: u8,
        b3: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        self.with_dev_sync(|dev| query_single(dev, cmd, param, b3, payload, 0))
    }

    // === Profile ===

    pub fn get_profile(&self) -> Result<u8, TransportError> {
        let d = self.query_cmd(0x90, 0, 0, &[])?;
        d.first().copied().ok_or(TransportError::InvalidResponse {
            expected: 0x90,
            actual: 0,
        })
    }

    pub fn set_profile(&self, profile: u8) -> Result<(), TransportError> {
        let _ = self.send_cmd_wait(0x10, profile, 0, &[])?;
        Ok(())
    }

    // === System Params (`0x84` / `0x04`) ===

    pub fn get_polling_rate_hz(&self) -> Result<u16, TransportError> {
        let d = self.query_cmd(0x84, param::POLLING_RATE, 0, &[])?;
        let code = d.first().copied().unwrap_or(0);
        byte_to_polling_rate(code).ok_or(TransportError::InvalidResponse {
            expected: 0x84,
            actual: code,
        })
    }

    pub fn set_polling_rate_hz(&self, hz: u16) -> Result<(), TransportError> {
        let code = polling_rate_to_byte(hz).ok_or_else(|| {
            TransportError::Internal(format!("Unsupported BYTech polling rate: {hz} Hz"))
        })?;
        let _ = self.send_cmd_wait(0x04, param::POLLING_RATE, 0, &[code])?;
        Ok(())
    }

    pub fn get_debounce_ms(&self) -> Result<u16, TransportError> {
        let d = self.query_cmd(0x84, param::DEBOUNCE_MS, 0, &[])?;
        if d.len() >= 2 {
            Ok(u16::from_be_bytes([d[0], d[1]]))
        } else {
            Ok(d.first().copied().unwrap_or(0) as u16)
        }
    }

    pub fn set_debounce_ms(&self, ms: u16) -> Result<(), TransportError> {
        let [hi, lo] = ms.to_be_bytes();
        let _ = self.send_cmd_wait(0x04, param::DEBOUNCE_MS, 0, &[hi, lo])?;
        Ok(())
    }

    pub fn get_sleep_seconds(&self) -> Result<u16, TransportError> {
        let d = self.query_cmd(0x84, param::SLEEP_TIME_S, 0, &[])?;
        if d.len() >= 2 {
            Ok(u16::from_be_bytes([d[0], d[1]]))
        } else {
            Ok(d.first().copied().unwrap_or(0) as u16 * 60)
        }
    }

    pub fn set_sleep_seconds(&self, secs: u16) -> Result<(), TransportError> {
        let [hi, lo] = secs.to_be_bytes();
        let _ = self.send_cmd_wait(0x04, param::SLEEP_TIME_S, 0, &[hi, lo])?;
        Ok(())
    }

    pub fn get_kb_options(&self) -> Result<BeiyingKbOptions, TransportError> {
        let os_mode = self
            .query_cmd(0x84, param::OS_MODE, 0, &[])
            .ok()
            .and_then(|d| d.first().copied())
            .unwrap_or(0);
        self.os_mode_cache.store(os_mode, Ordering::Relaxed);
        let win_lock = self
            .query_cmd(0x84, param::WIN_LOCK, 0, &[])
            .ok()
            .and_then(|d| d.first().copied())
            .is_some_and(|v| v != 0);
        let wasd_swap = self
            .query_cmd(0x84, param::WASD_SWAP, 0, &[])
            .ok()
            .and_then(|d| d.first().copied())
            .is_some_and(|v| v != 0);
        let adaptive_cal = self
            .query_cmd(0x84, param::ADAPTIVE_CAL, 0, &[])
            .ok()
            .and_then(|d| d.first().copied())
            .is_some_and(|v| v != 0);
        let side_sync = if self.session.has_side_sync {
            self.query_cmd(0x84, param::SIDE_SYNC, 0, &[])
                .ok()
                .and_then(|d| d.first().copied())
                .is_some_and(|v| v != 0)
        } else {
            false
        };
        Ok(BeiyingKbOptions {
            os_mode,
            win_lock,
            adaptive_cal,
            wasd_swap,
            side_sync,
        })
    }

    pub fn set_kb_options(&self, opts: BeiyingKbOptions) -> Result<(), TransportError> {
        let _ = self.send_cmd_wait(0x04, param::OS_MODE, 0, &[opts.os_mode])?;
        self.os_mode_cache.store(opts.os_mode, Ordering::Relaxed);
        let _ = self.send_cmd_wait(0x04, param::WIN_LOCK, 0, &[opts.win_lock as u8])?;
        let _ = self.send_cmd_wait(0x04, param::WASD_SWAP, 0, &[opts.wasd_swap as u8])?;
        let _ = self.send_cmd_wait(0x04, param::ADAPTIVE_CAL, 0, &[opts.adaptive_cal as u8])?;
        if self.session.has_side_sync {
            let _ = self.send_cmd_wait(0x04, param::SIDE_SYNC, 0, &[opts.side_sync as u8])?;
        }
        Ok(())
    }

    // === Main & Side LED (`0x84`/`0x04` params `1` & `6`, plus `0x08` / `0x0E`) ===

    pub fn get_main_led(&self) -> Result<BeiyingLedParams, TransportError> {
        let d = self.query_cmd(0x84, param::MAIN_LED, 0, &[])?;
        Ok(BeiyingLedParams {
            effect_id: d.first().copied().unwrap_or(0),
            color_idx: d.get(1).copied().unwrap_or(0),
            r: d.get(2).copied().unwrap_or(255),
            g: d.get(3).copied().unwrap_or(255),
            b: d.get(4).copied().unwrap_or(255),
            brightness: d.get(5).copied().unwrap_or(20),
            speed: d.get(6).copied().unwrap_or(2),
            direction: d.get(7).copied().unwrap_or(0),
        })
    }

    pub fn set_main_led(&self, p: BeiyingLedParams) -> Result<(), TransportError> {
        let payload = if self.session.has_direction {
            vec![
                p.effect_id,
                p.color_idx,
                p.r,
                p.g,
                p.b,
                p.brightness.min(20),
                p.speed.min(4),
                p.direction,
            ]
        } else {
            vec![
                p.effect_id,
                p.color_idx,
                p.r,
                p.g,
                p.b,
                p.brightness.min(20),
                p.speed.min(4),
            ]
        };
        let _ = self.send_cmd_wait(0x04, param::MAIN_LED, 0, &payload)?;
        Ok(())
    }

    pub fn get_side_led(&self) -> Result<BeiyingLedParams, TransportError> {
        let d = self.query_cmd(0x84, param::SIDE_LED, 0, &[])?;
        Ok(BeiyingLedParams {
            effect_id: d.first().copied().unwrap_or(0),
            color_idx: d.get(1).copied().unwrap_or(0),
            r: d.get(2).copied().unwrap_or(255),
            g: d.get(3).copied().unwrap_or(255),
            b: d.get(4).copied().unwrap_or(255),
            brightness: d.get(5).copied().unwrap_or(4),
            speed: d.get(6).copied().unwrap_or(2),
            direction: 0,
        })
    }

    pub fn set_side_led(&self, p: BeiyingLedParams) -> Result<(), TransportError> {
        let payload = [
            p.effect_id,
            p.color_idx,
            p.r,
            p.g,
            p.b,
            p.brightness.min(4),
            p.speed.min(4),
        ];
        let _ = self.send_cmd_wait(0x04, param::SIDE_LED, 0, &payload)?;
        Ok(())
    }

    /// Encode per-key RGB tuples `(key_id, [r, g, b])` according to `led_proto_flags`.
    pub fn encode_keyboard_led_packets(
        &self,
        keys: &[(u16, [u8; 3])],
    ) -> Vec<[u8; WIRED_REPORT_LEN]> {
        let flags = self.session.led_proto_flags;
        if flags != 0xFFFF && (flags & 0x04) != 0 && !self.session.dense_matrix_slots.is_empty() {
            let by_key: BTreeMap<u16, [u8; 3]> = keys.iter().copied().collect();
            let mut payload = Vec::with_capacity(self.session.dense_matrix_slots.len() * 2);
            for slot in &self.session.dense_matrix_slots {
                let rgb = by_key.get(&slot.key_id).copied().unwrap_or([0, 0, 0]);
                payload.extend_from_slice(&rgb_to_rgb565_be(rgb));
            }
            return chunk_stream_to_packets_64(0x08, 0x03, &payload);
        }

        if flags != 0xFFFF && (flags & 0x08) != 0 && !self.session.grouped_rgb565_addrs.is_empty() {
            let mut groups: BTreeMap<[u8; 2], Vec<u8>> = BTreeMap::new();
            for &(k, rgb) in keys {
                if rgb == [0, 0, 0] {
                    continue;
                }
                let c565 = rgb_to_rgb565_be(rgb);
                if c565 == [0, 0] {
                    continue;
                }
                if let Some(addrs) = self.session.grouped_rgb565_addrs.get(&k) {
                    groups.entry(c565).or_default().extend_from_slice(addrs);
                }
            }
            if groups.is_empty() {
                return vec![build_packet_64(0x08, 0x02, 0, 1, 0, &[0, 0, 0])];
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

        let mut groups: BTreeMap<[u8; 3], Vec<u8>> = BTreeMap::new();
        for &(k, rgb) in keys {
            if rgb != [0, 0, 0] {
                groups.entry(rgb).or_default().push(k as u8);
            }
        }
        if groups.is_empty() {
            return vec![build_packet_64(0x08, 0x02, 0, 1, 0, &[0, 0, 0])];
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

    /// Stream real-time per-key colors indexed by `TAC75_SLOTS` indices (`0..83`).
    pub fn send_per_key_slot_colors(
        &self,
        slot_colors: &[(usize, [u8; 3])],
    ) -> Result<(), TransportError> {
        let mut keys = Vec::with_capacity(slot_colors.len());
        for &(slot, rgb) in slot_colors {
            if let Some(id) = self.slot_to_key_id(slot) {
                keys.push((id, rgb));
            }
        }
        let pkts = self.encode_keyboard_led_packets(&keys);
        self.send_stream_packets(&pkts)
    }

    /// Stream a single uniform RGB color across all keys (used by screen ambient / full clear).
    pub fn send_full_color_realtime(&self, rgb: [u8; 3]) -> Result<(), TransportError> {
        let flags = self.session.led_proto_flags;
        if flags == 0xFFFF || (flags & 0x0C) == 0 || rgb == [0, 0, 0] {
            let pkt = build_packet_64(0x08, 0x02, 0, 1, 0, &rgb);
            self.send_stream_packets(&[pkt])
        } else {
            let all: Vec<(u16, [u8; 3])> = TAC75_SLOTS.iter().map(|s| (s.key_id, rgb)).collect();
            let pkts = self.encode_keyboard_led_packets(&all);
            self.send_stream_packets(&pkts)
        }
    }

    /// Clear `0x08 0x02` (and side lightbar `0x0E 0x02` if present) when stopping audio/screen FX.
    pub fn clear_realtime_leds(&self) -> Result<(), TransportError> {
        let main_off = build_packet_64(0x08, 0x02, 0, 1, 0, &[0, 0, 0]);
        self.send_stream_packets(&[main_off])?;
        if self.session.side_light_available && self.session.side_light_count > 0 {
            let side_off = build_packet_64(0x0E, 0x02, 0, 1, 0, &[0, 0, 0]);
            let _ = self.send_stream_packets(&[side_off]);
        }
        Ok(())
    }

    /// Stream side lightbar LEDs (`0x0E 0x01`) for `0..side_light_count`.
    pub fn send_side_lightbar_colors(&self, rgb: [u8; 3]) -> Result<(), TransportError> {
        let cnt = self.session.side_light_count;
        if !self.session.side_light_available || cnt == 0 {
            return Ok(());
        }
        if rgb == [0, 0, 0] {
            let off = build_packet_64(0x0E, 0x02, 0, 1, 0, &[0, 0, 0]);
            return self.send_stream_packets(&[off]);
        }
        let mut payload = Vec::with_capacity(4 + cnt as usize);
        payload.extend_from_slice(&rgb);
        payload.push(cnt);
        for i in 0..cnt {
            payload.push(i);
        }
        let pkts = chunk_stream_to_packets_64(0x0E, 0x01, &payload);
        self.send_stream_packets(&pkts)
    }

    // === Keymaps (`0x83` / `0x03`) ===

    pub fn get_keymaps(&self, layer: u8) -> Result<BTreeMap<u16, u32>, TransportError> {
        let ls = layer_sys_byte(layer, self.os_mode());
        let ids: Vec<u16> = TAC75_SLOTS.iter().map(|s| s.key_id).collect();
        let mut out = BTreeMap::new();
        self.with_dev_sync(|dev| {
            // Request 2B -> response 6B -> 9 keys per aligned packet.
            for chunk in ids.chunks(9) {
                let mut req = Vec::with_capacity(chunk.len() * 2);
                for &id in chunk {
                    req.extend_from_slice(&id.to_be_bytes());
                }
                let data = query_single(dev, 0x83, ls, 0, &req, 0)?;
                for rec in data.as_chunks::<6>().0 {
                    let id = u16::from_be_bytes([rec[0], rec[1]]);
                    let kc = u32::from_be_bytes([rec[2], rec[3], rec[4], rec[5]]);
                    out.insert(id, kc);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn set_keymaps(&self, layer: u8, entries: &[(u16, u32)]) -> Result<(), TransportError> {
        if entries.is_empty() {
            return Ok(());
        }
        let ls = layer_sys_byte(layer, self.os_mode());
        let mut payload = Vec::with_capacity(entries.len() * 6);
        for &(id, kc) in entries {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&kc.to_be_bytes());
        }
        self.with_dev_sync(|dev| {
            drain_device_rx(dev);
            send_packets_aligned(dev, 0x03, ls, 0, 6, &payload)?;
            read_assembled_reply(dev, 0x03, ls, 500)?;
            Ok(())
        })
    }

    // === Hall Effect Actuation / Rapid Trigger / Deadzones ===

    pub fn get_all_key_travels_um(&self, layer: u8) -> Result<BTreeMap<u16, u16>, TransportError> {
        let ls = layer_sys_byte(layer, self.os_mode());
        let ids: Vec<u16> = TAC75_SLOTS.iter().map(|s| s.key_id).collect();
        let mut out = BTreeMap::new();
        self.with_dev_sync(|dev| {
            // Request 2B -> response 5B -> 11 keys per packet.
            for chunk in ids.chunks(11) {
                let mut req = Vec::with_capacity(chunk.len() * 2);
                for &id in chunk {
                    req.extend_from_slice(&id.to_be_bytes());
                }
                let data = query_single(dev, 0x93, ls, 0, &req, 0)?;
                for rec in data.as_chunks::<5>().0 {
                    let id = u16::from_be_bytes([rec[0], rec[1]]);
                    let travel_um = u16::from_be_bytes([rec[2], rec[3]]);
                    out.insert(id, travel_um);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn set_key_travels_um(
        &self,
        layer: u8,
        entries: &[(u16, u16)],
    ) -> Result<(), TransportError> {
        if entries.is_empty() {
            return Ok(());
        }
        let ls = layer_sys_byte(layer, self.os_mode());
        let mut payload = Vec::with_capacity(entries.len() * 5);
        for &(id, um) in entries {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&um.to_be_bytes());
            payload.push(0);
        }
        self.with_dev_sync(|dev| {
            drain_device_rx(dev);
            send_packets_aligned(dev, 0x13, ls, 0, 5, &payload)?;
            read_assembled_reply(dev, 0x13, ls, 500)?;
            Ok(())
        })
    }

    pub fn get_all_rapid_triggers(&self, layer: u8) -> Result<Vec<BeiyingRtEntry>, TransportError> {
        let ls = layer_sys_byte(layer, self.os_mode());
        let ids: Vec<u16> = TAC75_SLOTS.iter().map(|s| s.key_id).collect();
        let mut out = Vec::with_capacity(ids.len());
        self.with_dev_sync(|dev| {
            // Request 2B -> response 8B -> 7 keys per packet.
            for chunk in ids.chunks(7) {
                let mut req = Vec::with_capacity(chunk.len() * 2);
                for &id in chunk {
                    req.extend_from_slice(&id.to_be_bytes());
                }
                let data = query_single(dev, 0x99, ls, 0, &req, 0)?;
                for rec in data.as_chunks::<8>().0 {
                    out.push(BeiyingRtEntry {
                        key_id: u16::from_be_bytes([rec[0], rec[1]]),
                        enabled: rec[2] != 0,
                        press_um: u16::from_be_bytes([rec[3], rec[4]]),
                        release_um: u16::from_be_bytes([rec[5], rec[6]]),
                    });
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn set_rapid_triggers(
        &self,
        layer: u8,
        entries: &[BeiyingRtEntry],
    ) -> Result<(), TransportError> {
        if entries.is_empty() {
            return Ok(());
        }
        let ls = layer_sys_byte(layer, self.os_mode());
        let mut payload = Vec::with_capacity(entries.len() * 8);
        for e in entries {
            payload.extend_from_slice(&e.key_id.to_be_bytes());
            payload.push(u8::from(e.enabled));
            payload.extend_from_slice(&e.press_um.to_be_bytes());
            payload.extend_from_slice(&e.release_um.to_be_bytes());
            payload.push(0);
        }
        self.with_dev_sync(|dev| {
            drain_device_rx(dev);
            send_packets_aligned(dev, 0x19, ls, 0, 8, &payload)?;
            read_assembled_reply(dev, 0x19, ls, 500)?;
            Ok(())
        })
    }

    pub fn get_all_deadzones(&self) -> Result<Vec<BeiyingDeadzoneEntry>, TransportError> {
        let ids: Vec<u16> = TAC75_SLOTS.iter().map(|s| s.key_id).collect();
        let mut out = Vec::with_capacity(ids.len());
        self.with_dev_sync(|dev| {
            // Request 2B -> response 8B -> 7 keys per packet.
            for chunk in ids.chunks(7) {
                let mut req = Vec::with_capacity(chunk.len() * 2);
                for &id in chunk {
                    req.extend_from_slice(&id.to_be_bytes());
                }
                let data = query_single(dev, 0x96, 0, 0, &req, 0)?;
                for rec in data.as_chunks::<8>().0 {
                    out.push(BeiyingDeadzoneEntry {
                        key_id: u16::from_be_bytes([rec[0], rec[1]]),
                        top_um: u16::from_be_bytes([rec[2], rec[3]]),
                        bottom_um: u16::from_be_bytes([rec[4], rec[5]]),
                        enabled: rec[7] != 0,
                    });
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn set_deadzones(&self, entries: &[BeiyingDeadzoneEntry]) -> Result<(), TransportError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(entries.len() * 8);
        for e in entries {
            payload.extend_from_slice(&e.key_id.to_be_bytes());
            payload.extend_from_slice(&e.top_um.to_be_bytes());
            payload.extend_from_slice(&e.bottom_um.to_be_bytes());
            payload.push(0);
            payload.push(u8::from(e.enabled));
        }
        self.with_dev_sync(|dev| {
            drain_device_rx(dev);
            send_packets_aligned(dev, 0x16, 0, 0, 8, &payload)?;
            read_assembled_reply(dev, 0x16, 0, 500)?;
            Ok(())
        })
    }

    /// Clear any MT / DKS / SOCD advanced assignment on a key (`0x12`, `adv_type = 0`).
    pub fn clear_advanced_key(&self, layer: u8, key_id: u16) -> Result<(), TransportError> {
        let ls = layer_sys_byte(layer, self.os_mode());
        let [hi, lo] = key_id.to_be_bytes();
        let _ = self.send_cmd_wait(0x12, ls, 0, &[hi, lo])?;
        Ok(())
    }

    // === Live Travel Monitoring (`0x98`) & Calibration (`0x94`) ===

    pub fn start_travel_monitoring(&self) -> Result<(), TransportError> {
        let _ = self.send_cmd_wait(0x98, 0, 0, &[])?;
        self.monitoring_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn stop_travel_monitoring(&self) -> Result<(), TransportError> {
        self.monitoring_active.store(false, Ordering::SeqCst);
        let _ = self.send_cmd_wait(0x98, 2, 0, &[])?;
        Ok(())
    }

    pub fn set_calibration_mode(&self, start: bool) -> Result<(), TransportError> {
        let sub = if start { 0 } else { 4 };
        let _ = self.send_cmd_wait(0x94, sub, 0, &[])?;
        Ok(())
    }

    /// Reset (`0=Full, 1=Keymap, 2=Light, 3=USB`).
    pub fn reset(&self, target: BeiyingResetTarget) -> Result<(), TransportError> {
        let _ = self.send_cmd_wait(0x11, target as u8, 0, &[])?;
        Ok(())
    }
}

impl Transport for HidBeiyingTransport {
    fn as_beiying(&self) -> Option<&HidBeiyingTransport> {
        Some(self)
    }

    fn send_report(
        &self,
        cmd: u8,
        _data: &[u8],
        _checksum: ChecksumType,
    ) -> Result<(), TransportError> {
        // Synthesize safe read-only responses for generic `FlowControlTransport` probes so
        // Rongyuan `send_feature_report` commands are NEVER emitted on Report ID 0x09 devices.
        let mut resp = vec![0u8; WIRED_REPORT_LEN];
        resp[0] = cmd;
        match cmd {
            crate::protocol::cmd::GET_USB_VERSION => {
                resp[1..5].copy_from_slice(&self.session.synthetic_device_id.to_le_bytes());
                resp[7..9].copy_from_slice(&self.session.fw_version.to_le_bytes());
            }
            crate::protocol::cmd::GET_FEATURE_LIST => {
                // Precision code matches `Precision::from_feature_byte`: 2=Fine, 1=Medium, 0=Coarse
                resp[1] = if self.um_per_unit <= 5 { 2 } else { 1 };
            }
            0x84 => {
                // GET_PROFILE fallback
                let p = self.get_profile().unwrap_or(0);
                resp[1] = p;
            }
            0x86 => {
                // GET_DEBOUNCE fallback
                let ms = self.get_debounce_ms().unwrap_or(0).min(50) as u8;
                resp[1] = ms;
            }
            _ => {
                trace!(
                    "Ignoring unmapped Rongyuan cmd 0x{:02X} on Beiying transport",
                    cmd
                );
            }
        }
        if let Ok(mut q) = self.pending_synthetic_reads.lock() {
            q.push_back(resp);
        }
        Ok(())
    }

    fn read_report(&self) -> Result<Vec<u8>, TransportError> {
        if let Ok(mut q) = self.pending_synthetic_reads.lock()
            && let Some(r) = q.pop_front()
        {
            return Ok(r);
        }
        Ok(vec![0u8; WIRED_REPORT_LEN])
    }

    fn read_event(&self, timeout_ms: u32) -> Result<Option<VendorEvent>, TransportError> {
        if let Ok(mut q) = self.pending_events.lock()
            && let Some(ev) = q.pop_front()
        {
            return Ok(Some(ev));
        }
        let mut rx = [0u8; WIRED_REPORT_LEN];
        let n = {
            let guard = self
                .device
                .lock()
                .map_err(|_| TransportError::Disconnected)?;
            guard
                .read_timeout(&mut rx, timeout_ms as i32)
                .map_err(TransportError::from)?
        };
        if n >= 7 && rx[0] == BEIYING_REPORT_ID {
            let mut evs = Vec::new();
            parse_bubble_events(&rx[..n], self.um_per_unit, &mut evs);
            let first = evs.first().cloned();
            if evs.len() > 1
                && let Ok(mut q) = self.pending_events.lock()
            {
                for ev in evs.into_iter().skip(1) {
                    q.push_back(ev);
                }
            }
            return Ok(first);
        }
        Ok(None)
    }

    fn device_info(&self) -> &TransportDeviceInfo {
        &self.info
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn close(&self) -> Result<(), TransportError> {
        if self.monitoring_active.swap(false, Ordering::SeqCst) {
            let _ = self.stop_travel_monitoring();
        }
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn get_battery_status(&self) -> Result<(u8, bool, bool), TransportError> {
        let d = self.query_cmd(0x87, 0, 0, &[])?;
        let level = d.first().copied().unwrap_or(100);
        let online = level > 0 || self.is_connected();
        Ok((level, online, false))
    }

    fn subscribe_events(&self) -> Option<broadcast::Receiver<TimestampedEvent>> {
        Some(self.event_tx.subscribe())
    }
}

fn drain_device_rx(dev: &HidDevice) {
    let mut rx = [0u8; WIRED_REPORT_LEN];
    for _ in 0..8 {
        match dev.read_timeout(&mut rx, 1) {
            Ok(n) if n > 0 => continue,
            _ => break,
        }
    }
}

fn chunk_stream_to_packets_64(cmd: u8, subcmd: u8, payload: &[u8]) -> Vec<[u8; WIRED_REPORT_LEN]> {
    if payload.is_empty() {
        return vec![build_packet_64(cmd, 0x02, 0, 1, 0, &[0, 0, 0])];
    }
    let total = payload.len().div_ceil(MAX_CHUNK_PAYLOAD);
    payload
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, c)| build_packet_64(cmd, subcmd, 0, total as u8, i as u8, c))
        .collect()
}

fn send_packets_chunked(
    dev: &HidDevice,
    cmd: u8,
    param: u8,
    b3: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    if payload.is_empty() {
        let pkt = build_packet_64(cmd, param, b3, 1, 0, &[]);
        dev.write(&pkt).map_err(TransportError::from)?;
        return Ok(());
    }
    let total = payload.len().div_ceil(MAX_CHUNK_PAYLOAD);
    for (idx, chunk) in payload.chunks(MAX_CHUNK_PAYLOAD).enumerate() {
        let pkt = build_packet_64(cmd, param, b3, total as u8, idx as u8, chunk);
        dev.write(&pkt).map_err(TransportError::from)?;
    }
    Ok(())
}

fn send_packets_aligned(
    dev: &HidDevice,
    cmd: u8,
    param: u8,
    b3: u8,
    unit_bytes: usize,
    payload: &[u8],
) -> Result<(), TransportError> {
    let chunk_bytes = (MAX_CHUNK_PAYLOAD / unit_bytes.max(1)) * unit_bytes.max(1);
    let total = payload.len().div_ceil(chunk_bytes.max(1));
    for (idx, chunk) in payload.chunks(chunk_bytes.max(1)).enumerate() {
        let pkt = build_packet_64(cmd, param, b3, total as u8, idx as u8, chunk);
        dev.write(&pkt).map_err(TransportError::from)?;
    }
    Ok(())
}

fn read_assembled_reply(
    dev: &HidDevice,
    expected_cmd: u8,
    expected_param: u8,
    timeout_ms: i32,
) -> Result<Vec<u8>, TransportError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(50) as u64);
    let mut parts: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut total_expected: Option<u8> = None;
    let mut rx = [0u8; WIRED_REPORT_LEN];

    while Instant::now() < deadline {
        match dev.read_timeout(&mut rx, 25) {
            Ok(n) if n >= 7 && rx[0] == BEIYING_REPORT_ID => {
                if rx[1] != expected_cmd || rx[2] != expected_param {
                    continue;
                }
                let total = rx[4].max(1);
                let cur = rx[5];
                let dlen = (rx[6] as usize).min(MAX_CHUNK_PAYLOAD).min(n - 7);
                total_expected = Some(total);
                parts.insert(cur, rx[7..7 + dlen].to_vec());
                if parts.len() >= total as usize {
                    let mut out = Vec::new();
                    for idx in 0..total {
                        if let Some(p) = parts.get(&idx) {
                            out.extend_from_slice(p);
                        }
                    }
                    return Ok(out);
                }
            }
            Ok(_) => continue,
            Err(e) => return Err(TransportError::from(e)),
        }
    }

    if total_expected.is_some() && !parts.is_empty() {
        let mut out = Vec::new();
        for (_, p) in parts {
            out.extend_from_slice(&p);
        }
        return Ok(out);
    }

    Err(TransportError::Timeout)
}

fn query_single(
    dev: &HidDevice,
    cmd: u8,
    param: u8,
    b3: u8,
    payload: &[u8],
    override_b5: u8,
) -> Result<Vec<u8>, TransportError> {
    drain_device_rx(dev);
    if override_b5 != 0 && payload.is_empty() {
        let mut pkt = [0u8; WIRED_REPORT_LEN];
        pkt[0] = BEIYING_REPORT_ID;
        pkt[1] = cmd;
        pkt[2] = param;
        pkt[3] = b3;
        pkt[4] = 1;
        pkt[5] = override_b5;
        apply_checksum_64(&mut pkt);
        dev.write(&pkt).map_err(TransportError::from)?;
    } else {
        send_packets_chunked(dev, cmd, param, b3, payload)?;
    }
    read_assembled_reply(dev, cmd, param, 300)
}

fn query_led_beads_raw(dev: &HidDevice, key_ids: &[u16]) -> Vec<(u16, Vec<u16>)> {
    let mut out = Vec::new();
    for chunk in key_ids.chunks(10) {
        let mut req = Vec::with_capacity(chunk.len() * 2);
        for &id in chunk {
            req.extend_from_slice(&id.to_be_bytes());
        }
        if let Ok(data) = query_single(dev, 0xA1, 0, 0, &req, 0) {
            let mut pos = 0usize;
            while pos + 3 <= data.len() {
                let id = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let cnt = data[pos + 2] as usize;
                pos += 3;
                let end = (pos + cnt).min(data.len());
                if cnt > 0 && end > pos {
                    let addrs = data[pos..end].iter().map(|&a| a as u16).collect();
                    out.push((id, addrs));
                }
                pos = end;
            }
        }
    }
    out
}

fn parse_bubble_events(rx: &[u8], um_per_unit: u16, out: &mut Vec<VendorEvent>) {
    if rx.len() < 7 || rx[0] != BEIYING_REPORT_ID {
        return;
    }
    if rx[1] == 0x98 && rx[2] == 0x01 {
        let dlen = (rx[6] as usize).min(MAX_CHUNK_PAYLOAD).min(rx.len() - 7);
        let data = &rx[7..7 + dlen];
        for rec in data.as_chunks::<6>().0 {
            let key_id = u16::from_be_bytes([rec[0], rec[1]]);
            let dist_um = u16::from_be_bytes([rec[2], rec[3]]);
            if let Some(slot) = TAC75_SLOTS.iter().find(|s| s.key_id == key_id) {
                let depth_raw = dist_um / um_per_unit.max(1);
                out.push(VendorEvent::KeyDepth {
                    key_index: slot.slot_index as u8,
                    depth_raw,
                });
            }
        }
    } else if rx[1] == 0xFE {
        // Device-initiated setting / Fn notification bubble
        let sub = rx[2];
        let val = rx[7];
        match sub {
            0x01 => out.push(VendorEvent::WinLockToggle { locked: val != 0 }),
            0x02 => out.push(VendorEvent::WasdSwapToggle { swapped: val != 0 }),
            0x03 => out.push(VendorEvent::ProfileChange { profile: val }),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tac75_slots_are_83_unique_sequential_keys() {
        assert_eq!(TAC75_SLOTS.len(), 83);
        let mut ids = HashSet::new();
        for (i, slot) in TAC75_SLOTS.iter().enumerate() {
            assert_eq!(slot.slot_index, i);
            assert!(
                ids.insert(slot.key_id),
                "duplicate key_id 0x{:02X}",
                slot.key_id
            );
        }
    }

    #[test]
    fn descriptor_accepts_beiying_report09_and_rejects_rongyuan() {
        let tac75 = [
            0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x09, 0x15, 0x00, 0x26, 0xFF, 0x00,
            0x75, 0x08, 0x95, 0x3F, 0x09, 0x01, 0x81, 0x02, 0x09, 0x02, 0x91, 0x02, 0xC0,
        ];
        assert_eq!(
            parse_beiying_report09_descriptor(&tac75),
            Some(Report09Capability {
                vendor_usage_page: 0xFF00,
                input_report_bytes: 64,
                output_report_bytes: 64,
            })
        );

        let rongyuan = [
            0x06, 0xFF, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x75, 0x08, 0x95, 0x40, 0xB1, 0x02, 0xC0,
        ];
        assert_eq!(parse_beiying_report09_descriptor(&rongyuan), None);
    }

    #[test]
    fn packet_checksum_and_polling_rate_roundtrip() {
        let pkt = build_packet_64(0x82, 0x01, 0, 1, 0, &[]);
        assert!(verify_checksum_64(&pkt));
        assert_eq!(pkt[0], 0x09);
        assert_eq!(pkt[1], 0x82);

        for (hz, code) in [
            (1000, 0),
            (500, 1),
            (250, 2),
            (125, 3),
            (8000, 4),
            (4000, 5),
            (2000, 6),
        ] {
            assert_eq!(polling_rate_to_byte(hz), Some(code));
            assert_eq!(byte_to_polling_rate(code), Some(hz));
        }
    }

    #[test]
    fn bytech_keycode_config_roundtrip() {
        // Lone key A
        let cfg_a = [0, 0, 0x04, 0];
        let kc_a = config_to_bytech_keycode(cfg_a);
        assert_eq!(kc_a, 0x0000_0004);
        assert_eq!(bytech_keycode_to_config(kc_a), cfg_a);

        // Ctrl + C
        let cfg_ctrl_c = [0, 0xE0, 0x06, 0];
        let kc_ctrl_c = config_to_bytech_keycode(cfg_ctrl_c);
        assert_eq!(kc_ctrl_c, 0x0001_0006);
        assert_eq!(bytech_keycode_to_config(kc_ctrl_c), cfg_ctrl_c);

        // Lone LCtrl
        let cfg_lctrl = [0, 0, 0xE0, 0];
        let kc_lctrl = config_to_bytech_keycode(cfg_lctrl);
        assert_eq!(kc_lctrl, 0x0000_00E0);
        assert_eq!(bytech_keycode_to_config(kc_lctrl), cfg_lctrl);

        // Consumer Volume Up (0x00E9)
        let cfg_vol = [3, 0, 0xE9, 0x00];
        let kc_vol = config_to_bytech_keycode(cfg_vol);
        assert_eq!(kc_vol, 0x0200_00E9);
        assert_eq!(bytech_keycode_to_config(kc_vol), cfg_vol);

        // Fn key
        let cfg_fn = [10, 1, 0, 0];
        let kc_fn = config_to_bytech_keycode(cfg_fn);
        assert_eq!(kc_fn, 0x0D00_0000);
        assert_eq!(bytech_keycode_to_config(kc_fn), cfg_fn);

        // Disabled
        assert_eq!(config_to_bytech_keycode([0, 0, 0, 0]), 0);
        assert_eq!(bytech_keycode_to_config(0), [0, 0, 0, 0]);
    }
}
