//! USB Device Control — monitor and enforce policy on USB device connections.
//!
//! Provides a declarative [`UsbPolicy`] that can block or allow USB devices
//! by class (storage, HID, network, etc.) and vendor-ID allowlist.

use serde::{Deserialize, Serialize};

// ── USB class codes (from USB specification) ─────────────────────────
const USB_CLASS_MASS_STORAGE: u8 = 0x08;
const USB_CLASS_HID: u8 = 0x03;
const USB_CLASS_NETWORK: u8 = 0xE0; // Wireless controller (covers USB NICs)
const USB_CLASS_AUDIO: u8 = 0x01;
const USB_CLASS_VIDEO: u8 = 0x0E;
// CDC (Communications Device Class) is another common network class.
const USB_CLASS_CDC: u8 = 0x02;

// ── Public types ─────────────────────────────────────────────────────

/// Policy governing which USB device classes are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPolicy {
    /// Allow USB mass-storage devices (flash drives, external HDDs).
    pub allow_storage: bool,
    /// Allow USB HID keyboards / mice.
    pub allow_keyboard: bool,
    /// Allow USB network adapters.
    pub allow_network: bool,
    /// Vendor IDs that are always allowed regardless of class rules.
    pub allowed_vendor_ids: Vec<String>,
    /// Whether to emit telemetry for all USB connections (even allowed ones).
    pub log_all_connections: bool,
}

/// A USB device connection / disconnection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    /// USB vendor ID, e.g. `"0x1234"`.
    pub vendor_id: String,
    /// USB product ID, e.g. `"0x5678"`.
    pub product_id: String,
    /// Coarse device class derived from the USB class code.
    pub device_class: UsbDeviceClass,
    /// Serial number if available.
    pub serial: Option<String>,
    /// Whether the device was connected or disconnected.
    pub action: UsbAction,
    /// Unix timestamp of the event.
    pub timestamp: i64,
}

/// Coarse device class used for policy decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbDeviceClass {
    MassStorage,
    HumanInterface,
    Network,
    Audio,
    Video,
    Other(String),
}

/// Whether a device was plugged in or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbAction {
    Connected,
    Disconnected,
}

/// A policy violation produced when a prohibited device is connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbViolation {
    /// The event that caused the violation.
    pub event: UsbEvent,
    /// Human-readable reason the device was blocked.
    pub reason: String,
}

// ── UsbPolicy implementation ─────────────────────────────────────────

impl UsbPolicy {
    /// Permissive default: allow all device classes, log everything.
    pub fn default() -> Self {
        Self {
            allow_storage: true,
            allow_keyboard: true,
            allow_network: true,
            allowed_vendor_ids: Vec::new(),
            log_all_connections: true,
        }
    }

    /// Strict posture: block mass-storage, allow HID, log everything.
    pub fn strict() -> Self {
        Self {
            allow_storage: false,
            allow_keyboard: true,
            allow_network: false,
            allowed_vendor_ids: Vec::new(),
            log_all_connections: true,
        }
    }

    /// Evaluate a USB event against the policy.
    ///
    /// Returns `Some(UsbViolation)` if the device is prohibited, `None` if
    /// allowed.  Disconnection events are never violations.
    pub fn check_device(&self, event: &UsbEvent) -> Option<UsbViolation> {
        // Disconnections are always allowed.
        if event.action == UsbAction::Disconnected {
            return None;
        }

        // Vendor-ID allowlist takes precedence over class rules.
        if self
            .allowed_vendor_ids
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&event.vendor_id))
        {
            return None;
        }

        let blocked = match &event.device_class {
            UsbDeviceClass::MassStorage => !self.allow_storage,
            UsbDeviceClass::HumanInterface => !self.allow_keyboard,
            UsbDeviceClass::Network => !self.allow_network,
            // Audio, Video, and Other are always allowed (no policy knob).
            UsbDeviceClass::Audio | UsbDeviceClass::Video | UsbDeviceClass::Other(_) => false,
        };

        if blocked {
            let class_name = match &event.device_class {
                UsbDeviceClass::MassStorage => "mass storage",
                UsbDeviceClass::HumanInterface => "HID",
                UsbDeviceClass::Network => "network adapter",
                _ => "unknown",
            };
            Some(UsbViolation {
                event: event.clone(),
                reason: format!(
                    "USB {} device (vendor={}, product={}) blocked by policy",
                    class_name, event.vendor_id, event.product_id,
                ),
            })
        } else {
            None
        }
    }
}

/// Map a raw USB class code byte to a [`UsbDeviceClass`].
pub fn parse_usb_class(class_code: u8) -> UsbDeviceClass {
    match class_code {
        USB_CLASS_MASS_STORAGE => UsbDeviceClass::MassStorage,
        USB_CLASS_HID => UsbDeviceClass::HumanInterface,
        USB_CLASS_NETWORK | USB_CLASS_CDC => UsbDeviceClass::Network,
        USB_CLASS_AUDIO => UsbDeviceClass::Audio,
        USB_CLASS_VIDEO => UsbDeviceClass::Video,
        other => UsbDeviceClass::Other(format!("0x{:02x}", other)),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_event(vendor: &str) -> UsbEvent {
        UsbEvent {
            vendor_id: vendor.to_string(),
            product_id: "0x0001".to_string(),
            device_class: UsbDeviceClass::MassStorage,
            serial: None,
            action: UsbAction::Connected,
            timestamp: 1_700_000_000,
        }
    }

    fn hid_event() -> UsbEvent {
        UsbEvent {
            vendor_id: "0xAAAA".to_string(),
            product_id: "0x0002".to_string(),
            device_class: UsbDeviceClass::HumanInterface,
            serial: None,
            action: UsbAction::Connected,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn default_policy_allows_everything() {
        let policy = UsbPolicy::default();
        assert!(policy.check_device(&storage_event("0x1234")).is_none());
        assert!(policy.check_device(&hid_event()).is_none());
    }

    #[test]
    fn strict_policy_blocks_storage() {
        let policy = UsbPolicy::strict();
        let violation = policy.check_device(&storage_event("0x1234"));
        assert!(violation.is_some());
        assert!(violation.unwrap().reason.contains("mass storage"));
    }

    #[test]
    fn allowlisted_vendor_passes_strict() {
        let mut policy = UsbPolicy::strict();
        policy.allowed_vendor_ids.push("0xABCD".to_string());
        let event = storage_event("0xABCD");
        assert!(policy.check_device(&event).is_none());
    }

    #[test]
    fn hid_allowed_in_strict_mode() {
        let policy = UsbPolicy::strict();
        assert!(policy.check_device(&hid_event()).is_none());
    }

    #[test]
    fn unknown_class_parses_to_other() {
        let class = parse_usb_class(0xFF);
        assert_eq!(class, UsbDeviceClass::Other("0xff".to_string()));
    }

    #[test]
    fn known_class_codes_parse_correctly() {
        assert_eq!(parse_usb_class(0x08), UsbDeviceClass::MassStorage);
        assert_eq!(parse_usb_class(0x03), UsbDeviceClass::HumanInterface);
        assert_eq!(parse_usb_class(0xE0), UsbDeviceClass::Network);
        assert_eq!(parse_usb_class(0x01), UsbDeviceClass::Audio);
        assert_eq!(parse_usb_class(0x0E), UsbDeviceClass::Video);
        // CDC also maps to Network.
        assert_eq!(parse_usb_class(0x02), UsbDeviceClass::Network);
    }

    #[test]
    fn disconnection_never_violates() {
        let policy = UsbPolicy::strict();
        let mut event = storage_event("0x1234");
        event.action = UsbAction::Disconnected;
        assert!(policy.check_device(&event).is_none());
    }

    #[test]
    fn vendor_id_case_insensitive() {
        let mut policy = UsbPolicy::strict();
        policy.allowed_vendor_ids.push("0xabcd".to_string());
        let event = storage_event("0xABCD");
        assert!(policy.check_device(&event).is_none());
    }

    #[test]
    fn strict_blocks_network_adapter() {
        let policy = UsbPolicy::strict();
        let event = UsbEvent {
            vendor_id: "0x1234".to_string(),
            product_id: "0x0003".to_string(),
            device_class: UsbDeviceClass::Network,
            serial: None,
            action: UsbAction::Connected,
            timestamp: 1_700_000_000,
        };
        let violation = policy.check_device(&event);
        assert!(violation.is_some());
        assert!(violation.unwrap().reason.contains("network adapter"));
    }
}
