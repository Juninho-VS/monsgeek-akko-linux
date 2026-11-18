//! Device discovery for MonsGeek/Akko keyboards and their rebrands

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::Arc;

use hidapi::HidApi;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Check if a device is connected via Bluetooth
fn is_bluetooth_bus(device_info: &hidapi::DeviceInfo) -> bool {
    matches!(device_info.bus_type(), hidapi::BusType::Bluetooth)
}

use crate::Transport;
use crate::device_registry::{self, UsbInterfaceRule};
use crate::error::TransportError;
use crate::flow_control::FlowControlTransport;
use crate::hid_bluetooth::HidBluetoothTransport;
use crate::hid_dongle::HidDongleTransport;
use crate::hid_wired::HidWiredTransport;
use crate::printer::{Printer, PrinterConfig};
use crate::protocol::{REPORT_SIZE, device};
use crate::types::{DiscoveredDevice, DiscoveryEvent, TransportDeviceInfo, TransportType};

/// Kind of HID report defined in a report descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HidReportKind {
    Input,
    Output,
    Feature,
}

impl fmt::Display for HidReportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input => f.write_str("In"),
            Self::Output => f.write_str("Out"),
            Self::Feature => f.write_str("Feature"),
        }
    }
}

/// Summary of one logical HID report (collection + kind + optional report ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidReportEntry {
    pub collection_usage_page: u16,
    pub collection_usage: u16,
    pub kind: HidReportKind,
    pub report_id: Option<u8>,
    pub payload_bytes: usize,
}

/// Parsed summary of a raw HID report descriptor (read-only metadata).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HidDescriptorSummary {
    reports: Vec<HidReportEntry>,
}

#[derive(Clone, Copy, Default)]
struct HidGlobalState {
    usage_page: u16,
    report_size: u32,
    report_count: u32,
    report_id: Option<u8>,
}

impl HidDescriptorSummary {
    /// Parse a USB HID report descriptor (USB HID 1.11 §6.2.2.2) without panicking.
    pub fn parse(bytes: &[u8]) -> Self {
        let mut global = HidGlobalState::default();
        let mut global_stack: Vec<HidGlobalState> = Vec::new();
        let mut collection_stack: Vec<(u16, u16)> = Vec::new();
        let mut first_local_usage: Option<(Option<u16>, u16)> = None;

        let mut order: Vec<(u16, u16, HidReportKind, Option<u8>)> = Vec::new();
        let mut bit_totals: BTreeMap<(u16, u16, HidReportKind, Option<u8>), u32> = BTreeMap::new();

        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i];
            if b0 == 0xFE {
                if i + 1 >= bytes.len() {
                    break;
                }
                let data_len = bytes[i + 1] as usize;
                i = i.saturating_add(3 + data_len);
                continue;
            }

            let data_len = match b0 & 0x03 {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            let item_type = (b0 >> 2) & 0x03;
            let tag = (b0 >> 4) & 0x0F;

            if i + 1 + data_len > bytes.len() {
                break;
            }

            let mut val: u32 = 0;
            for (shift_idx, &byte) in bytes[i + 1..i + 1 + data_len].iter().enumerate() {
                val |= u32::from(byte) << (shift_idx * 8);
            }
            i += 1 + data_len;

            match item_type {
                // Main
                0 => {
                    match tag {
                        // Input (0x08), Output (0x09), Feature (0x0B)
                        8 | 9 | 11 => {
                            let kind = match tag {
                                8 => HidReportKind::Input,
                                9 => HidReportKind::Output,
                                _ => HidReportKind::Feature,
                            };
                            let bits = global.report_size.saturating_mul(global.report_count);
                            if bits > 0 {
                                let (col_up, col_u) = collection_stack
                                    .last()
                                    .copied()
                                    .unwrap_or((global.usage_page, 0));
                                let key = (col_up, col_u, kind, global.report_id);
                                if let Some(total) = bit_totals.get_mut(&key) {
                                    *total = total.saturating_add(bits);
                                } else {
                                    order.push(key);
                                    bit_totals.insert(key, bits);
                                }
                            }
                        }
                        // Collection (0x0A)
                        10 => {
                            if val == 0x01 || collection_stack.is_empty() {
                                let (up, u) = match first_local_usage {
                                    Some((Some(page), usage)) => (page, usage),
                                    Some((None, usage)) => (global.usage_page, usage),
                                    None => (global.usage_page, 0),
                                };
                                collection_stack.push((up, u));
                            } else {
                                let parent = *collection_stack.last().unwrap();
                                collection_stack.push(parent);
                            }
                        }
                        // End Collection (0x0C)
                        12 => {
                            collection_stack.pop();
                        }
                        _ => {}
                    }
                    // USB HID 1.11 §6.2.2.8: Main items clear local state.
                    first_local_usage = None;
                }
                // Global
                1 => match tag {
                    0 => global.usage_page = val as u16,
                    7 => global.report_size = val,
                    8 => global.report_id = u8::try_from(val).ok().filter(|&id| id != 0),
                    9 => global.report_count = val,
                    10 => global_stack.push(global),
                    11 => {
                        if let Some(prev) = global_stack.pop() {
                            global = prev;
                        }
                    }
                    _ => {}
                },
                // Local
                2 if matches!(tag, 0 | 1) && first_local_usage.is_none() => {
                    if data_len == 4 {
                        first_local_usage = Some((Some((val >> 16) as u16), (val & 0xFFFF) as u16));
                    } else {
                        first_local_usage = Some((None, val as u16));
                    }
                }
                _ => {}
            }
        }

        let reports = order
            .into_iter()
            .filter_map(|key| {
                let bits = *bit_totals.get(&key)?;
                Some(HidReportEntry {
                    collection_usage_page: key.0,
                    collection_usage: key.1,
                    kind: key.2,
                    report_id: key.3,
                    payload_bytes: (bits as usize).div_ceil(8),
                })
            })
            .collect();

        Self { reports }
    }

    pub fn reports(&self) -> &[HidReportEntry] {
        &self.reports
    }

    /// True if the descriptor defines an unnumbered Feature report (Report ID 0)
    /// of exact `payload_bytes` bytes, as required by `HidWiredTransport`.
    pub fn has_unnumbered_feature_report(&self, payload_bytes: usize) -> bool {
        self.reports.iter().any(|r| {
            r.kind == HidReportKind::Feature
                && r.report_id.is_none()
                && r.payload_bytes == payload_bytes
        })
    }

    /// True if the descriptor matches Shenzhen Beiying (`BY Tech` / HubX) vendor HID:
    /// collection `0xFF60:0x0061` with 63-byte Input and Output reports on Report ID `0x09`.
    pub fn is_beiying_hubx_vendor_descriptor(&self) -> bool {
        let has_report = |kind: HidReportKind| {
            self.reports.iter().any(|r| {
                r.collection_usage_page == 0xFF60
                    && r.collection_usage == 0x0061
                    && r.kind == kind
                    && r.report_id == Some(0x09)
                    && r.payload_bytes == 63
            })
        };
        has_report(HidReportKind::Input) && has_report(HidReportKind::Output)
    }

    pub fn format_reports_compact(&self) -> String {
        if self.reports.is_empty() {
            return "empty".to_string();
        }
        self.reports
            .iter()
            .map(|r| match r.report_id {
                Some(id) => format!("ID 0x{id:02X} {} {}B", r.kind, r.payload_bytes),
                None => format!("{} {}B (ID 0)", r.kind, r.payload_bytes),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Read the kernel-cached HID report descriptor for a `/dev/hidrawX` node via sysfs.
///
/// This never opens the hidraw character device and never sends USB requests.
pub fn read_sysfs_report_descriptor(hidraw_path: &str) -> Option<Vec<u8>> {
    let devname = std::path::Path::new(hidraw_path).file_name()?.to_str()?;
    if !devname.starts_with("hidraw") || devname.contains('/') || devname.contains("..") {
        return None;
    }
    std::fs::read(format!(
        "/sys/class/hidraw/{devname}/device/report_descriptor"
    ))
    .ok()
}

/// Extracted HID enumeration metadata for pure interface classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidCandidateInfo {
    pub vid: u16,
    pub pid: u16,
    pub interface_number: i32,
    pub usage_page: u16,
    pub usage: u16,
    pub is_bluetooth: bool,
}

impl HidCandidateInfo {
    pub fn from_device_info(info: &hidapi::DeviceInfo) -> Self {
        Self {
            vid: info.vendor_id(),
            pid: info.product_id(),
            interface_number: info.interface_number(),
            usage_page: info.usage_page(),
            usage: info.usage(),
            is_bluetooth: is_bluetooth_bus(info),
        }
    }
}

/// Accepted transport interface category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    UsbFeature { via_custom_rule: bool },
    BluetoothVendor,
}

/// Reason an enumerated HID interface was not accepted for device transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    NotCandidateVidPid,
    StandardKeyboard,
    ConsumerOrSystemControl,
    VendorEventInput,
    WrongInterfaceNumber {
        expected: i32,
    },
    UnsupportedBluetoothUsage,
    UnsupportedOemProtocol {
        oem: &'static str,
        web_url: &'static str,
        summary: String,
    },
    UnsupportedUsage {
        custom_rule: Option<UsbInterfaceRule>,
    },
    IncompatibleReportDescriptor {
        summary: String,
    },
    UnverifiedCustomDescriptor,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCandidateVidPid => {
                write!(f, "VID:PID is not 0x3151 and not in the device database")
            }
            Self::StandardKeyboard => write!(f, "standard HID keyboard interface"),
            Self::ConsumerOrSystemControl => write!(f, "consumer/system control interface"),
            Self::VendorEventInput => write!(f, "vendor event input interface (IF1)"),
            Self::WrongInterfaceNumber { expected } => {
                write!(f, "wrong interface number (expected interface {expected})")
            }
            Self::UnsupportedBluetoothUsage => {
                write!(f, "not Bluetooth vendor interface (expected 0xFF55:0x0202)")
            }
            Self::UnsupportedOemProtocol {
                oem,
                web_url,
                summary,
            } => write!(
                f,
                "unsupported {oem} firmware ({summary}); not RongYuan — configure via WebHID at {web_url}"
            ),
            Self::UnsupportedUsage { custom_rule } => {
                if let Some(rule) = custom_rule {
                    let iface_hint = rule
                        .interface_number
                        .map(|n| format!(" on IF{n}"))
                        .unwrap_or_default();
                    write!(
                        f,
                        "unsupported usage page/usage (expected 0xFFFF/0xFF00:0x0002 or 0x{:04X}:0x{:04X}{iface_hint})",
                        rule.usage_page, rule.usage
                    )
                } else {
                    write!(
                        f,
                        "unsupported usage page/usage (expected 0xFFFF/0xFF00:0x0002)"
                    )
                }
            }
            Self::IncompatibleReportDescriptor { summary } => write!(
                f,
                "incompatible HID report descriptor ({summary}; transport requires 64-byte unnumbered Feature report ID 0)"
            ),
            Self::UnverifiedCustomDescriptor => write!(
                f,
                "custom interface descriptor unavailable for report layout verification"
            ),
        }
    }
}

/// Outcome of evaluating a single HID collection for discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceVerdict {
    Accepted(InterfaceKind),
    Rejected(RejectReason),
}

fn beiying_hubx_verdict(
    candidate: &HidCandidateInfo,
    desc: &HidDescriptorSummary,
) -> Option<InterfaceVerdict> {
    if candidate.usage_page == 0xFF60
        && candidate.usage == 0x0061
        && desc.is_beiying_hubx_vendor_descriptor()
    {
        Some(InterfaceVerdict::Rejected(
            RejectReason::UnsupportedOemProtocol {
                oem: "Shenzhen Beiying (BY Tech / HubX)",
                web_url: "https://demo.hubx.pro/keyboard/",
                summary: desc.format_reports_compact(),
            },
        ))
    } else {
        None
    }
}

/// Evaluate whether an enumerated HID interface is valid for driver transport,
/// parameterized by database VID:PID set and per-device rules for unit testing.
pub fn classify_interface_with(
    candidate: &HidCandidateInfo,
    descriptor: Option<&HidDescriptorSummary>,
    known_ids: Option<&HashSet<(u16, u16)>>,
    rules: &[UsbInterfaceRule],
) -> InterfaceVerdict {
    let is_candidate = candidate.vid == device::VENDOR_ID
        || known_ids.is_some_and(|ids| ids.contains(&(candidate.vid, candidate.pid)));
    if !is_candidate {
        return InterfaceVerdict::Rejected(RejectReason::NotCandidateVidPid);
    }

    if candidate.is_bluetooth {
        if candidate.usage_page == bluetooth::USAGE_PAGE
            && candidate.usage == bluetooth::USAGE_VENDOR
        {
            return InterfaceVerdict::Accepted(InterfaceKind::BluetoothVendor);
        }
        return InterfaceVerdict::Rejected(RejectReason::UnsupportedBluetoothUsage);
    }

    let matches_default = device::is_vendor_usage_page(candidate.usage_page)
        && candidate.usage == device::USAGE_FEATURE;
    let matches_custom = rules.iter().any(|r| {
        r.matches(
            candidate.vid,
            candidate.pid,
            candidate.interface_number,
            candidate.usage_page,
            candidate.usage,
        )
    });

    if matches_default || matches_custom {
        let via_custom_rule = !matches_default && matches_custom;
        let expected_payload = REPORT_SIZE.saturating_sub(1);
        return match descriptor {
            Some(desc) => {
                if desc.has_unnumbered_feature_report(expected_payload) {
                    InterfaceVerdict::Accepted(InterfaceKind::UsbFeature { via_custom_rule })
                } else if let Some(verdict) = beiying_hubx_verdict(candidate, desc) {
                    verdict
                } else {
                    InterfaceVerdict::Rejected(RejectReason::IncompatibleReportDescriptor {
                        summary: desc.format_reports_compact(),
                    })
                }
            }
            None => {
                if !via_custom_rule {
                    InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                        via_custom_rule: false,
                    })
                } else {
                    InterfaceVerdict::Rejected(RejectReason::UnverifiedCustomDescriptor)
                }
            }
        };
    }

    if let Some(desc) = descriptor
        && let Some(verdict) = beiying_hubx_verdict(candidate, desc)
    {
        return verdict;
    }

    if candidate.usage_page == 0x0001 && candidate.usage == 0x0006 {
        return InterfaceVerdict::Rejected(RejectReason::StandardKeyboard);
    }
    if candidate.usage_page == 0x000C
        || (candidate.usage_page == 0x0001 && matches!(candidate.usage, 0x0002 | 0x0080))
    {
        return InterfaceVerdict::Rejected(RejectReason::ConsumerOrSystemControl);
    }
    if device::is_vendor_usage_page(candidate.usage_page)
        && candidate.usage == device::USAGE_INPUT
        && candidate.interface_number == device::INTERFACE_INPUT
    {
        return InterfaceVerdict::Rejected(RejectReason::VendorEventInput);
    }
    if let Some(rule) = rules.iter().find(|r| {
        r.vid == candidate.vid
            && r.pid == candidate.pid
            && r.usage_page == candidate.usage_page
            && r.usage == candidate.usage
    }) && let Some(expected) = rule.interface_number
    {
        return InterfaceVerdict::Rejected(RejectReason::WrongInterfaceNumber { expected });
    }

    InterfaceVerdict::Rejected(RejectReason::UnsupportedUsage {
        custom_rule: rules
            .iter()
            .find(|r| r.vid == candidate.vid && r.pid == candidate.pid)
            .copied(),
    })
}

/// Evaluate an enumerated HID interface against the globally registered database metadata.
pub fn classify_interface(
    candidate: &HidCandidateInfo,
    descriptor: Option<&HidDescriptorSummary>,
) -> InterfaceVerdict {
    classify_interface_with(
        candidate,
        descriptor,
        device_registry::known_usb_ids(),
        device_registry::known_usb_interface_rules(),
    )
}

/// Device discovery abstraction
pub trait DeviceDiscovery: Send + Sync {
    /// List currently available devices
    fn list_devices(&self) -> Result<Vec<DiscoveredDevice>, TransportError>;

    /// Open a specific device
    fn open_device(&self, device: &DiscoveredDevice) -> Result<Arc<dyn Transport>, TransportError>;

    /// Subscribe to hot-plug events
    fn watch(&self) -> Result<broadcast::Receiver<DiscoveryEvent>, TransportError>;
}

/// HID device discovery for wired and dongle connections
pub struct HidDiscovery {
    /// Hot-plug event sender
    event_tx: broadcast::Sender<DiscoveryEvent>,
    /// Optional printer config for monitoring mode - wraps transports automatically
    printer_config: Option<PrinterConfig>,
}

impl Default for HidDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Bluetooth HID usage page and usage for vendor endpoint
mod bluetooth {
    /// Bluetooth vendor usage page (from report descriptor)
    pub const USAGE_PAGE: u16 = 0xFF55;
    /// Bluetooth vendor usage (from report descriptor)
    pub const USAGE_VENDOR: u16 = 0x0202;
}

impl HidDiscovery {
    /// Create a new HID discovery instance
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(16);
        Self {
            event_tx,
            printer_config: None,
        }
    }

    /// Create with printer config for monitoring mode
    /// All transports opened via open_device() will be wrapped with Printer
    pub fn with_printer_config(config: PrinterConfig) -> Self {
        let (event_tx, _) = broadcast::channel(16);
        Self {
            event_tx,
            printer_config: Some(config),
        }
    }

    /// Check if this is the USB feature interface (default vendor page + usage 0x02,
    /// or a registered per-device interface override with compatible report layout).
    fn is_usb_feature_interface(device_info: &hidapi::DeviceInfo) -> bool {
        let candidate = HidCandidateInfo::from_device_info(device_info);
        let path = device_info.path().to_string_lossy();
        let desc = read_sysfs_report_descriptor(&path).map(|raw| HidDescriptorSummary::parse(&raw));
        matches!(
            classify_interface(&candidate, desc.as_ref()),
            InterfaceVerdict::Accepted(InterfaceKind::UsbFeature { .. })
        )
    }

    /// Check if this is the Bluetooth vendor interface (usage 0x0202, page 0xFF55)
    fn is_bluetooth_vendor_interface(device_info: &hidapi::DeviceInfo) -> bool {
        device_info.usage_page() == bluetooth::USAGE_PAGE
            && device_info.usage() == bluetooth::USAGE_VENDOR
    }

    /// Check if this is the USB input interface (IF1, vendor usage page, usage 0x01)
    fn is_usb_input_interface(device_info: &hidapi::DeviceInfo) -> bool {
        device_info.interface_number() == device::INTERFACE_INPUT
            && device::is_vendor_usage_page(device_info.usage_page())
            && device_info.usage() == device::USAGE_INPUT
    }

    /// Extract USB bus location from a hidraw sysfs path.
    /// e.g., `/sys/devices/.../usb9/9-2/9-2:1.2/0003:3151:5030.065C/hidraw/hidraw10`
    /// returns `"9-2"` — the USB port, shared by all interfaces of the same device.
    fn usb_bus_location(hidraw_path: &str) -> Option<String> {
        // Read the sysfs path for this hidraw device
        let devname = std::path::Path::new(hidraw_path).file_name()?.to_str()?;
        let sysfs = std::fs::read_link(format!("/sys/class/hidraw/{}", devname)).ok()?;
        let sysfs_str = sysfs.to_string_lossy();
        // Find the USB port segment (e.g., "9-2" in ".../usb9/9-2/9-2:1.2/...")
        for component in sysfs_str.split('/') {
            // USB port segments match pattern like "1-2", "3-4.1", "9-2"
            if component.contains('-')
                && !component.contains(':')
                && !component.contains('.')
                && component.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return Some(component.to_string());
            }
        }
        None
    }

    /// Check if two hidraw devices are on the same USB physical device.
    fn is_same_usb_device(path_a: &str, path_b: &str) -> bool {
        match (
            Self::usb_bus_location(path_a),
            Self::usb_bus_location(path_b),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Find the input interface for a USB device, preferring a sibling of `feature_path`.
    fn find_usb_input_device(
        &self,
        api: &HidApi,
        vid: u16,
        pid: u16,
        feature_path: &str,
    ) -> Option<hidapi::DeviceInfo> {
        let is_input = |d: &&hidapi::DeviceInfo| {
            d.vendor_id() == vid
                && d.product_id() == pid
                && d.path().to_string_lossy() != feature_path
                && Self::is_usb_input_interface(d)
        };
        api.device_list()
            .filter(is_input)
            .find(|d| Self::is_same_usb_device(&d.path().to_string_lossy(), feature_path))
            // Fallback: any matching VID/PID input interface
            .or_else(|| api.device_list().find(is_input))
            .cloned()
    }

    /// Find the IF1 (composite HID) interface for a dongle device,
    /// preferring a sibling of `feature_path`.
    /// IF1 hosts the patched HID descriptor with Feature Report ID 8.
    fn find_dongle_if1_device(
        api: &HidApi,
        vid: u16,
        pid: u16,
        feature_path: &str,
    ) -> Option<hidapi::DeviceInfo> {
        let is_if1 = |d: &&hidapi::DeviceInfo| {
            d.vendor_id() == vid
                && d.product_id() == pid
                && d.interface_number() == 1
                && !Self::is_usb_feature_interface(d)
                && !Self::is_usb_input_interface(d)
        };
        api.device_list()
            .filter(is_if1)
            .find(|d| Self::is_same_usb_device(&d.path().to_string_lossy(), feature_path))
            .or_else(|| api.device_list().find(is_if1))
            .cloned()
    }

    /// Find the input interface for a Bluetooth device (keyboard HID)
    fn find_bt_input_device(&self, api: &HidApi, vid: u16, pid: u16) -> Option<hidapi::DeviceInfo> {
        // Bluetooth keyboard uses standard HID keyboard usage (0x0006, page 0x0001)
        api.device_list()
            .find(|d| {
                d.vendor_id() == vid
                    && d.product_id() == pid
                    && is_bluetooth_bus(d)
                    && d.usage() == 0x0006
                    && d.usage_page() == 0x0001
            })
            .cloned()
    }
}

impl DeviceDiscovery for HidDiscovery {
    fn list_devices(&self) -> Result<Vec<DiscoveredDevice>, TransportError> {
        let api = HidApi::new().map_err(|e| TransportError::HidError(e.to_string()))?;
        let mut devices = Vec::new();
        let mut seen_paths = HashSet::new();

        for device_info in api.device_list() {
            let vid = device_info.vendor_id();
            let pid = device_info.product_id();

            if !device_registry::is_candidate_device(vid, pid) {
                continue;
            }

            // Determine transport type based on bus type and PID
            let is_bluetooth = is_bluetooth_bus(device_info);

            // For Bluetooth: look for vendor interface (usage 0x0202, page 0xFF55)
            // For USB: look for feature interface (default vendor page + usage 0x02,
            // or per-device rule with compatible descriptor)
            let is_target_interface = if is_bluetooth {
                Self::is_bluetooth_vendor_interface(device_info)
            } else {
                Self::is_usb_feature_interface(device_info)
            };

            if !is_target_interface {
                continue;
            }

            let path = device_info.path().to_string_lossy().to_string();
            if !seen_paths.insert(path.clone()) {
                continue;
            }

            // Authoritative PID list first; fall back to a product-string
            // heuristic so dongles with an unrecognized PID are still treated
            // as receivers (and surfaced by `probe`) instead of wired.
            let is_dongle = device_registry::is_dongle_pid(pid)
                || (!is_bluetooth
                    && !device_registry::is_bluetooth_pid(pid)
                    && device_registry::looks_like_dongle(device_info.product_string()));
            let transport_type = if is_bluetooth {
                TransportType::Bluetooth
            } else if is_dongle {
                TransportType::HidDongle
            } else {
                TransportType::HidWired
            };

            let serial = device_info.serial_number().map(|s| s.to_string());
            let product_name = device_info.product_string().map(|s| s.to_string());

            debug!(
                "Found device: VID={:04X} PID={:04X} type={:?} bt={} path={}",
                vid, pid, transport_type, is_bluetooth, path
            );

            devices.push(DiscoveredDevice {
                info: TransportDeviceInfo {
                    vid,
                    pid,
                    is_dongle,
                    transport_type,
                    device_path: path,
                    serial,
                    product_name,
                },
            });
        }

        info!("Found {} devices", devices.len());
        Ok(devices)
    }

    fn open_device(&self, device: &DiscoveredDevice) -> Result<Arc<dyn Transport>, TransportError> {
        let api = HidApi::new().map_err(|e| TransportError::HidError(e.to_string()))?;

        // Create appropriate transport based on type
        let transport: Arc<dyn Transport> = match device.info.transport_type {
            TransportType::Bluetooth => {
                // Find and open the Bluetooth vendor interface
                let vendor_info = api
                    .device_list()
                    .find(|d| {
                        d.vendor_id() == device.info.vid
                            && d.product_id() == device.info.pid
                            && Self::is_bluetooth_vendor_interface(d)
                    })
                    .ok_or_else(|| {
                        TransportError::DeviceNotFound(format!(
                            "Bluetooth vendor interface for {:04X}:{:04X}",
                            device.info.vid, device.info.pid
                        ))
                    })?;

                let vendor_device = vendor_info
                    .open_device(&api)
                    .map_err(TransportError::from)?;

                // Try to open keyboard input interface for events
                let input_device = self
                    .find_bt_input_device(&api, device.info.vid, device.info.pid)
                    .and_then(|info| info.open_device(&api).ok());

                if input_device.is_some() {
                    debug!("Opened Bluetooth keyboard input interface for events");
                }

                Arc::new(HidBluetoothTransport::new(
                    vendor_device,
                    input_device,
                    device.info.clone(),
                ))
            }
            TransportType::HidWired | TransportType::HidDongle => {
                // Find and open the USB feature interface.
                // Match by device_path to distinguish multiple same-VID/PID devices.
                // The discovered device_path points to the feature interface (IF2),
                // so an exact path match is the primary lookup strategy.
                let feature_info = api
                    .device_list()
                    .find(|d| {
                        d.path().to_string_lossy() == device.info.device_path
                            && Self::is_usb_feature_interface(d)
                    })
                    // Fallback: VID/PID match (for devices discovered before path was tracked)
                    .or_else(|| {
                        api.device_list().find(|d| {
                            d.vendor_id() == device.info.vid
                                && d.product_id() == device.info.pid
                                && Self::is_usb_feature_interface(d)
                        })
                    })
                    .ok_or_else(|| {
                        TransportError::DeviceNotFound(format!(
                            "Feature interface for {:04X}:{:04X}",
                            device.info.vid, device.info.pid
                        ))
                    })?;

                let feature_device = feature_info
                    .open_device(&api)
                    .map_err(TransportError::from)?;

                let feature_path = feature_info.path().to_string_lossy().to_string();

                // Try to open input interface (sibling of feature interface)
                let input_device = self
                    .find_usb_input_device(&api, device.info.vid, device.info.pid, &feature_path)
                    .and_then(|info| info.open_device(&api).ok());

                if input_device.is_some() {
                    debug!("Opened USB input interface for events");
                }

                if device.info.transport_type == TransportType::HidDongle {
                    // Open IF1 for dongle patch discovery (Feature Report ID 8)
                    let if1_device = Self::find_dongle_if1_device(
                        &api,
                        device.info.vid,
                        device.info.pid,
                        &feature_path,
                    )
                    .and_then(|info| match info.open_device(&api) {
                        Ok(dev) => {
                            debug!("Opened dongle IF1 for patch discovery");
                            Some(dev)
                        }
                        Err(e) => {
                            debug!("Failed to open dongle IF1: {}", e);
                            None
                        }
                    });

                    Arc::new(HidDongleTransport::new(
                        feature_device,
                        input_device,
                        if1_device,
                        device.info.clone(),
                    ))
                } else {
                    Arc::new(HidWiredTransport::new(
                        feature_device,
                        input_device,
                        device.info.clone(),
                    ))
                }
            }
            _ => {
                return Err(TransportError::Internal(format!(
                    "Unsupported transport type: {:?}",
                    device.info.transport_type
                )));
            }
        };

        info!(
            "Opened {:?} transport for {:04X}:{:04X}",
            device.info.transport_type, device.info.vid, device.info.pid
        );

        // Wrap with printer if monitoring is enabled
        let transport = match &self.printer_config {
            Some(config) => Printer::wrap(transport, config.clone()),
            None => transport,
        };

        Ok(transport)
    }

    fn watch(&self) -> Result<broadcast::Receiver<DiscoveryEvent>, TransportError> {
        // TODO: Implement udev hot-plug monitoring
        // For now, just return a receiver that won't get events
        warn!("Hot-plug monitoring not yet implemented");
        Ok(self.event_tx.subscribe())
    }
}

/// Result of probing a device
#[derive(Debug, Clone)]
pub struct ProbedDevice {
    /// The discovered device info
    pub device: DiscoveredDevice,
    /// Whether the device responded to a probe query
    pub responsive: bool,
    /// Device ID if probe succeeded (from GET_USB_VERSION)
    pub device_id: Option<u32>,
    /// Firmware version if probe succeeded
    pub version: Option<u16>,
}

impl HidDiscovery {
    /// Probe all discovered devices to find which ones actually respond
    ///
    /// This opens each device, sends a GET_USB_VERSION query, and returns
    /// information about which devices responded. Useful when multiple
    /// transports are available (e.g., dongle + Bluetooth) but only one
    /// is actually connected to the keyboard.
    ///
    /// Returns a list of all discovered devices with their probe results,
    /// sorted by preference (Bluetooth > Dongle > Wired) with responsive
    /// devices first.
    pub fn probe_devices(&self) -> Result<Vec<ProbedDevice>, TransportError> {
        use crate::ChecksumType;
        use crate::protocol::cmd;

        let devices = self.list_devices()?;
        let mut probed = Vec::with_capacity(devices.len());

        for device in devices {
            let probe_result = match self.open_device(&device) {
                Ok(raw_transport) => {
                    // Wrap with FlowControlTransport for probing
                    let transport = FlowControlTransport::new(raw_transport);
                    // Try to query device ID
                    match transport.query_command(cmd::GET_USB_VERSION, &[], ChecksumType::Bit7) {
                        Ok(resp) if resp.len() >= 5 && resp[0] == cmd::GET_USB_VERSION => {
                            let device_id =
                                u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
                            let version = if resp.len() >= 9 {
                                Some(u16::from_le_bytes([resp[7], resp[8]]))
                            } else {
                                None
                            };
                            info!(
                                "Probe {:?}: responsive, ID={}, version={:?}",
                                device.info.transport_type, device_id, version
                            );
                            (true, Some(device_id), version)
                        }
                        Ok(resp) => {
                            debug!(
                                "Probe {:?}: unexpected response {:02X?}",
                                device.info.transport_type,
                                &resp[..resp.len().min(8)]
                            );
                            (false, None, None)
                        }
                        Err(e) => {
                            debug!("Probe {:?}: error {}", device.info.transport_type, e);
                            (false, None, None)
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Probe {:?}: failed to open: {}",
                        device.info.transport_type, e
                    );
                    (false, None, None)
                }
            };

            probed.push(ProbedDevice {
                device,
                responsive: probe_result.0,
                device_id: probe_result.1,
                version: probe_result.2,
            });
        }

        // Sort: responsive first, then by transport preference (BT > Dongle > Wired)
        probed.sort_by(|a, b| {
            // Responsive devices first
            match (a.responsive, b.responsive) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Same responsiveness, sort by transport type preference
                    let priority = |t: &TransportType| match t {
                        TransportType::Bluetooth => 0,
                        TransportType::HidDongle => 1,
                        TransportType::HidWired => 2,
                        _ => 3,
                    };
                    priority(&a.device.info.transport_type)
                        .cmp(&priority(&b.device.info.transport_type))
                }
            }
        });

        info!(
            "Probed {} devices: {} responsive",
            probed.len(),
            probed.iter().filter(|p| p.responsive).count()
        );

        Ok(probed)
    }

    /// Open the best available device
    ///
    /// Probes all devices and returns a transport for the best one:
    /// - If only one device responds, use that one
    /// - If multiple respond, prefer Bluetooth > Dongle > Wired
    /// - If none respond but devices exist, try to open the preferred transport type anyway
    pub fn open_preferred(&self) -> Result<Arc<dyn Transport>, TransportError> {
        let probed = self.probe_devices()?;

        if probed.is_empty() {
            return Err(TransportError::DeviceNotFound("No devices found".into()));
        }

        // Get responsive devices
        let responsive: Vec<_> = probed.iter().filter(|p| p.responsive).collect();

        let chosen = if responsive.len() == 1 {
            // Only one responds - use it
            info!(
                "Single responsive device: {:?}",
                responsive[0].device.info.transport_type
            );
            &responsive[0].device
        } else if !responsive.is_empty() {
            // Multiple respond - use the preferred one (already sorted)
            info!(
                "Multiple responsive devices ({}), choosing {:?}",
                responsive.len(),
                responsive[0].device.info.transport_type
            );
            &responsive[0].device
        } else {
            // None respond - try the preferred transport type anyway
            // (maybe it just needs more time, or it's a different command set)
            warn!(
                "No devices responded to probe, trying {:?} anyway",
                probed[0].device.info.transport_type
            );
            &probed[0].device
        };

        self.open_device(chosen)
    }

    /// Get all responsive devices (for multi-device scenarios)
    ///
    /// Returns transports for all devices that responded to the probe.
    pub fn open_all_responsive(&self) -> Result<Vec<Arc<dyn Transport>>, TransportError> {
        let probed = self.probe_devices()?;
        let mut transports = Vec::new();

        for p in probed.iter().filter(|p| p.responsive) {
            match self.open_device(&p.device) {
                Ok(t) => transports.push(t),
                Err(e) => warn!("Failed to reopen {:?}: {}", p.device.info.transport_type, e),
            }
        }

        if transports.is_empty() && !probed.is_empty() {
            return Err(TransportError::DeviceNotFound(
                "No devices responded to probe".into(),
            ));
        }

        Ok(transports)
    }

    /// Probe all devices and return them with human-readable labels.
    ///
    /// Each device is probed for device_id/version and assigned a sequential index.
    /// The `model_name_fn` callback resolves device_id to a model name string;
    /// if it returns None, the USB product string or "Unknown" is used.
    pub fn list_labeled_devices<F>(
        &self,
        model_name_fn: F,
    ) -> Result<Vec<(ProbedDevice, crate::types::DeviceLabel)>, TransportError>
    where
        F: Fn(Option<u32>, u16, u16) -> Option<String>,
    {
        let probed = self.probe_devices()?;
        let mut labeled = Vec::with_capacity(probed.len());

        for (index, p) in probed.into_iter().enumerate() {
            let transport_name = match p.device.info.transport_type {
                TransportType::HidWired => "usb",
                TransportType::HidDongle => "dongle",
                TransportType::Bluetooth => "bt",
                TransportType::WebRtc => "webrtc",
            };

            let model_name = model_name_fn(p.device_id, p.device.info.vid, p.device.info.pid)
                .or_else(|| p.device.info.product_name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let label = crate::types::DeviceLabel {
                index,
                model_name,
                transport_name,
                device_id: p.device_id,
                version: p.version,
                hid_path: p.device.info.device_path.clone(),
            };

            labeled.push((p, label));
        }

        Ok(labeled)
    }
}

/// Format a device list for display (e.g., to stderr when multiple devices found).
pub fn format_device_list(labels: &[crate::types::DeviceLabel]) -> String {
    let mut out = String::new();
    for label in labels {
        out.push_str(&format!("{label}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const RAID75_IF1_DESC: &[u8] = &[
        0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x04, 0x19, 0x00, 0x2A, 0xFF, 0x1F, 0x15, 0x00,
        0x26, 0xFF, 0x1F, 0x75, 0x10, 0x95, 0x01, 0x81, 0x00, 0xC0, 0x05, 0x01, 0x09, 0x80, 0xA1,
        0x01, 0x85, 0x05, 0x1A, 0x81, 0x00, 0x2A, 0x83, 0x00, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
        0x95, 0x03, 0x81, 0x02, 0x95, 0x05, 0x81, 0x01, 0xC0, 0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
        0x85, 0x07, 0x05, 0x07, 0x25, 0x01, 0x19, 0x00, 0x29, 0x9F, 0x95, 0xA0, 0x75, 0x01, 0x81,
        0x02, 0xC0, 0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xA1, 0x00, 0x05,
        0x09, 0x19, 0x01, 0x29, 0x05, 0x15, 0x00, 0x25, 0x01, 0x95, 0x05, 0x75, 0x01, 0x81, 0x02,
        0x95, 0x01, 0x75, 0x03, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15,
        0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xC0, 0x09, 0x3C, 0x05, 0xFF, 0x09,
        0x01, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0xB1, 0x22, 0x75, 0x06, 0x95, 0x01,
        0xB1, 0x01, 0xC0,
    ];

    // Captured 61B IF2 descriptor from an Akko TAC75 HE (BY Tech / HubX, 38ee:0016),
    // which shares USB VID:PID with Akko RAID 75 HE in devices.json.
    const RAID75_IF2_DESC: &[u8] = &[
        0x06, 0x60, 0xFF, 0x09, 0x61, 0xA1, 0x01, 0x85, 0x09, 0x09, 0x62, 0x15, 0x00, 0x26, 0xFF,
        0x00, 0x95, 0x3F, 0x75, 0x08, 0x81, 0x02, 0x09, 0x63, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x95,
        0x3F, 0x75, 0x08, 0x91, 0x02, 0xC0, 0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x03,
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x19, 0x01, 0x29, 0x02, 0x75, 0x08, 0x95, 0x3F, 0xB1, 0x02,
        0xC0,
    ];

    // Hypothetical 0xFF60:0x0061 descriptor with 64B unnumbered Feature report ID 0.
    const FF60_COMPATIBLE_FEATURE_DESC: &[u8] = &[
        0x06, 0x60, 0xFF, 0x09, 0x61, 0xA1, 0x01, 0x09, 0x62, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x95,
        0x40, 0x75, 0x08, 0xB1, 0x02, 0xC0,
    ];

    // Non-Beiying 0xFF60:0x0061 descriptor using numbered Feature report ID 0x05 (63B).
    const FF60_NUMBERED_FEATURE_DESC: &[u8] = &[
        0x06, 0x60, 0xFF, 0x09, 0x61, 0xA1, 0x01, 0x85, 0x05, 0x09, 0x62, 0x15, 0x00, 0x26, 0xFF,
        0x00, 0x95, 0x3F, 0x75, 0x08, 0xB1, 0x02, 0xC0,
    ];

    fn test_known_ids() -> HashSet<(u16, u16)> {
        [(0x38EE, 0x0001), (0x38EE, 0x0016)].into_iter().collect()
    }

    fn test_rules() -> Vec<UsbInterfaceRule> {
        vec![UsbInterfaceRule {
            vid: 0x38EE,
            pid: 0x0016,
            interface_number: Some(2),
            usage_page: 0xFF60,
            usage: 0x0061,
        }]
    }

    fn candidate(
        vid: u16,
        pid: u16,
        interface_number: i32,
        usage_page: u16,
        usage: u16,
    ) -> HidCandidateInfo {
        HidCandidateInfo {
            vid,
            pid,
            interface_number,
            usage_page,
            usage,
            is_bluetooth: false,
        }
    }

    #[test]
    fn parse_real_report_descriptors() {
        let m1 = HidDescriptorSummary::parse(M1_V5_IF2_DESC);
        assert!(m1.has_unnumbered_feature_report(64));
        assert!(!m1.is_beiying_hubx_vendor_descriptor());
        assert_eq!(m1.format_reports_compact(), "Feature 64B (ID 0)");

        let compat_ff60 = HidDescriptorSummary::parse(FF60_COMPATIBLE_FEATURE_DESC);
        assert!(compat_ff60.has_unnumbered_feature_report(64));
        assert!(!compat_ff60.is_beiying_hubx_vendor_descriptor());

        let if0 = HidDescriptorSummary::parse(RAID75_IF0_DESC);
        assert!(!if0.has_unnumbered_feature_report(64));
        assert_eq!(if0.format_reports_compact(), "In 8B (ID 0), Out 1B (ID 0)");

        let if1 = HidDescriptorSummary::parse(RAID75_IF1_DESC);
        assert!(!if1.has_unnumbered_feature_report(64));
        assert_eq!(
            if1.reports(),
            &[
                HidReportEntry {
                    collection_usage_page: 0x000C,
                    collection_usage: 0x0001,
                    kind: HidReportKind::Input,
                    report_id: Some(0x04),
                    payload_bytes: 2,
                },
                HidReportEntry {
                    collection_usage_page: 0x0001,
                    collection_usage: 0x0080,
                    kind: HidReportKind::Input,
                    report_id: Some(0x05),
                    payload_bytes: 1,
                },
                HidReportEntry {
                    collection_usage_page: 0x0001,
                    collection_usage: 0x0006,
                    kind: HidReportKind::Input,
                    report_id: Some(0x07),
                    payload_bytes: 20,
                },
                HidReportEntry {
                    collection_usage_page: 0x0001,
                    collection_usage: 0x0002,
                    kind: HidReportKind::Input,
                    report_id: Some(0x02),
                    payload_bytes: 4,
                },
                HidReportEntry {
                    collection_usage_page: 0x0001,
                    collection_usage: 0x0002,
                    kind: HidReportKind::Feature,
                    report_id: Some(0x02),
                    payload_bytes: 1,
                },
            ]
        );

        let if2 = HidDescriptorSummary::parse(RAID75_IF2_DESC);
        assert!(!if2.has_unnumbered_feature_report(64));
        assert!(if2.is_beiying_hubx_vendor_descriptor());
        assert_eq!(
            if2.reports(),
            &[
                HidReportEntry {
                    collection_usage_page: 0xFF60,
                    collection_usage: 0x0061,
                    kind: HidReportKind::Input,
                    report_id: Some(0x09),
                    payload_bytes: 63,
                },
                HidReportEntry {
                    collection_usage_page: 0xFF60,
                    collection_usage: 0x0061,
                    kind: HidReportKind::Output,
                    report_id: Some(0x09),
                    payload_bytes: 63,
                },
                HidReportEntry {
                    collection_usage_page: 0xFF00,
                    collection_usage: 0x0001,
                    kind: HidReportKind::Feature,
                    report_id: Some(0x03),
                    payload_bytes: 63,
                },
            ]
        );
        assert_eq!(
            if2.format_reports_compact(),
            "ID 0x09 In 63B, ID 0x09 Out 63B, ID 0x03 Feature 63B"
        );
    }

    #[test]
    fn traditional_3151_devices_still_detected() {
        let known = test_known_ids();
        let rules = test_rules();
        let m1_desc = HidDescriptorSummary::parse(M1_V5_IF2_DESC);

        for pid in [0x5030u16, 0xFFFFu16] {
            for page in [0xFFFFu16, 0xFF00u16] {
                let c = candidate(device::VENDOR_ID, pid, 2, page, 0x0002);
                assert_eq!(
                    classify_interface_with(&c, Some(&m1_desc), Some(&known), &rules),
                    InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                        via_custom_rule: false
                    })
                );
                assert_eq!(
                    classify_interface_with(&c, None, Some(&known), &rules),
                    InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                        via_custom_rule: false
                    })
                );
            }
        }
    }

    #[test]
    fn rebranded_db_device_detected() {
        let known = test_known_ids();
        let rules = test_rules();
        let m1_desc = HidDescriptorSummary::parse(M1_V5_IF2_DESC);

        let c = candidate(0x38EE, 0x0001, 2, 0xFFFF, 0x0002);
        assert_eq!(
            classify_interface_with(&c, Some(&m1_desc), Some(&known), &rules),
            InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                via_custom_rule: false
            })
        );
    }

    #[test]
    fn raid75_ff60_rule_is_restricted_and_checks_descriptor() {
        let known = test_known_ids();
        let rules = test_rules();
        let raid_if2 = HidDescriptorSummary::parse(RAID75_IF2_DESC);
        let compat_ff60 = HidDescriptorSummary::parse(FF60_COMPATIBLE_FEATURE_DESC);
        let numbered_ff60 = HidDescriptorSummary::parse(FF60_NUMBERED_FEATURE_DESC);

        // 38ee:0016 IF2 0xFF60:0x0061 with compatible 64B Feature ID 0 descriptor is accepted.
        let c_if2 = candidate(0x38EE, 0x0016, 2, 0xFF60, 0x0061);
        assert_eq!(
            classify_interface_with(&c_if2, Some(&compat_ff60), Some(&known), &rules),
            InterfaceVerdict::Accepted(InterfaceKind::UsbFeature {
                via_custom_rule: true
            })
        );

        // Captured 61B 0xFF60:0x0061 descriptor (ID 0x09 In/Out 63B + ID 0x03 Feature 63B) is
        // Shenzhen Beiying (BY Tech / HubX) firmware sharing 38ee:0016: must NOT be opened as
        // a Report ID 0 RongYuan transport and should surface UnsupportedOemProtocol.
        let beiying_verdict =
            classify_interface_with(&c_if2, Some(&raid_if2), Some(&known), &rules);
        assert_eq!(
            beiying_verdict,
            InterfaceVerdict::Rejected(RejectReason::UnsupportedOemProtocol {
                oem: "Shenzhen Beiying (BY Tech / HubX)",
                web_url: "https://demo.hubx.pro/keyboard/",
                summary: "ID 0x09 In 63B, ID 0x09 Out 63B, ID 0x03 Feature 63B".to_string(),
            })
        );
        if let InterfaceVerdict::Rejected(reason) = &beiying_verdict {
            let msg = reason.to_string();
            assert!(!msg.contains('\n') && !msg.contains('_'), "got: {msg}");
        }

        // Any other candidate VID:PID (even without a custom rule) exposing the Beiying/HubX
        // 0xFF60:0x0061 ID 0x09 layout is also diagnosed as UnsupportedOemProtocol.
        let other_db = candidate(0x38EE, 0x0001, 2, 0xFF60, 0x0061);
        assert_eq!(
            classify_interface_with(&other_db, Some(&raid_if2), Some(&known), &rules),
            beiying_verdict
        );

        // A non-Beiying incompatible 0xFF60:0x0061 descriptor reports IncompatibleReportDescriptor.
        assert_eq!(
            classify_interface_with(&c_if2, Some(&numbered_ff60), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::IncompatibleReportDescriptor {
                summary: "ID 0x05 Feature 63B".to_string(),
            })
        );

        // Custom rule never falls back blindly when descriptor cannot be verified.
        assert_eq!(
            classify_interface_with(&c_if2, None, Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::UnverifiedCustomDescriptor)
        );

        // Wrong interface number on 38ee:0016 is rejected.
        let c_if1 = candidate(0x38EE, 0x0016, 1, 0xFF60, 0x0061);
        assert_eq!(
            classify_interface_with(&c_if1, Some(&compat_ff60), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::WrongInterfaceNumber { expected: 2 })
        );

        // 0xFF60:0x0061 on IF2 is NOT accepted for other keyboards.
        for (vid, pid) in [(0x38EE, 0x0001), (device::VENDOR_ID, 0x5030)] {
            let other = candidate(vid, pid, 2, 0xFF60, 0x0061);
            assert!(matches!(
                classify_interface_with(&other, Some(&compat_ff60), Some(&known), &rules),
                InterfaceVerdict::Rejected(RejectReason::UnsupportedUsage { custom_rule: None })
            ));
        }

        // Secondary collection 0xFF00:0x0001 on IF2 is NOT misclassified as IF1 input or feature.
        let secondary = candidate(0x38EE, 0x0016, 2, 0xFF00, 0x0001);
        assert!(matches!(
            classify_interface_with(&secondary, Some(&raid_if2), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::UnsupportedUsage {
                custom_rule: Some(_)
            })
        ));
    }

    #[test]
    fn standard_keyboard_and_consumer_interfaces_rejected() {
        let known = test_known_ids();
        let rules = test_rules();
        let if0_desc = HidDescriptorSummary::parse(RAID75_IF0_DESC);
        let if1_desc = HidDescriptorSummary::parse(RAID75_IF1_DESC);

        let kb = candidate(0x38EE, 0x0016, 0, 0x0001, 0x0006);
        assert_eq!(
            classify_interface_with(&kb, Some(&if0_desc), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::StandardKeyboard)
        );

        let consumer = candidate(0x38EE, 0x0016, 1, 0x000C, 0x0001);
        assert_eq!(
            classify_interface_with(&consumer, Some(&if1_desc), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::ConsumerOrSystemControl)
        );

        let sys_ctrl = candidate(0x38EE, 0x0016, 1, 0x0001, 0x0080);
        assert_eq!(
            classify_interface_with(&sys_ctrl, Some(&if1_desc), Some(&known), &rules),
            InterfaceVerdict::Rejected(RejectReason::ConsumerOrSystemControl)
        );
    }

    #[test]
    fn unknown_vid_pid_is_always_rejected() {
        let known = test_known_ids();
        let rules = test_rules();
        let m1_desc = HidDescriptorSummary::parse(M1_V5_IF2_DESC);
        let compat_ff60 = HidDescriptorSummary::parse(FF60_COMPATIBLE_FEATURE_DESC);

        for (vid, pid, up, u, desc) in [
            (0x1532, 0x0221, 0xFFFF, 0x0002, &m1_desc),
            (0x38EE, 0x0017, 0xFFFF, 0x0002, &m1_desc),
            (0x38EE, 0x0017, 0xFF60, 0x0061, &compat_ff60),
        ] {
            let c = candidate(vid, pid, 2, up, u);
            assert_eq!(
                classify_interface_with(&c, Some(desc), Some(&known), &rules),
                InterfaceVerdict::Rejected(RejectReason::NotCandidateVidPid)
            );
        }
    }

    #[test]
    fn parser_handles_truncated_or_long_items_without_panicking() {
        assert_eq!(HidDescriptorSummary::parse(&[]).reports(), &[]);
        // Truncated short item and long item should stop cleanly
        let malformed = &[0x06, 0xFF, 0xFE, 0x05, 0x00, 0x01];
        assert_eq!(HidDescriptorSummary::parse(malformed).reports(), &[]);
    }
}
