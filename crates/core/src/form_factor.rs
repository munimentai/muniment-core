//! The shape of the computer a runtime runs on, so a paired device can draw
//! a laptop, an all-in-one, a desktop case or a rack server.
//!
//! macOS names the model in `hw.model`. Apple silicon models share the `Mac`
//! prefix, so a battery marks a laptop and a short list marks the all-in-one
//! models. Linux and Windows read the SMBIOS chassis type.

use std::sync::OnceLock;

pub use muniment_attach::FormFactor;

/// The form factor of this computer, read once. `None` when the platform
/// does not say, as in most containers and virtual machines.
pub fn detect() -> Option<FormFactor> {
    static DETECTED: OnceLock<Option<FormFactor>> = OnceLock::new();
    *DETECTED.get_or_init(platform::detect)
}

/// The SMBIOS chassis type, as Linux `chassis_type` and Windows tables give it.
pub fn from_chassis_type(chassis: u8) -> Option<FormFactor> {
    match chassis & 0x7f {
        8 | 9 | 10 | 11 | 14 | 30 | 31 | 32 => Some(FormFactor::Laptop),
        13 => Some(FormFactor::AllInOne),
        3..=7 | 15 | 16 | 24 | 34..=36 => Some(FormFactor::Desktop),
        17 | 23 | 25 | 28 | 29 => Some(FormFactor::Server),
        _ => None,
    }
}

/// Apple silicon all-in-one models, which carry the plain `Mac` prefix.
const APPLE_SILICON_ALL_IN_ONES: &[&str] = &["Mac15,4", "Mac15,5", "Mac16,2", "Mac16,3"];

/// The form factor of a Mac from its `hw.model` and whether it has a battery.
pub fn from_mac_model(model: &str, battery: bool) -> FormFactor {
    if battery || model.starts_with("MacBook") {
        FormFactor::Laptop
    } else if model.starts_with("iMac") || APPLE_SILICON_ALL_IN_ONES.contains(&model) {
        FormFactor::AllInOne
    } else {
        FormFactor::Desktop
    }
}

/// The chassis type in the first type 3 structure of an SMBIOS table.
pub fn smbios_chassis_type(table: &[u8]) -> Option<u8> {
    let mut at = 0;
    while at + 4 <= table.len() {
        let kind = table[at];
        let length = table[at + 1] as usize;
        if length < 4 || at + length > table.len() {
            return None;
        }
        if kind == 3 && length > 5 {
            return Some(table[at + 5]);
        }
        if kind == 127 {
            return None;
        }
        // The strings after the formatted area end at a double null.
        let mut next = at + length;
        while next + 1 < table.len() && !(table[next] == 0 && table[next + 1] == 0) {
            next += 1;
        }
        at = next + 2;
    }
    None
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{from_mac_model, FormFactor};

    pub fn detect() -> Option<FormFactor> {
        let model = model()?;
        Some(from_mac_model(&model, battery()))
    }

    fn model() -> Option<String> {
        let name = c"hw.model";
        let mut size = 0usize;
        // SAFETY: the first call asks only for the length.
        let asked = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if asked != 0 || size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: the buffer holds `size` bytes, the length the first call answered.
        let read = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if read != 0 {
            return None;
        }
        buffer.truncate(size);
        let text = String::from_utf8_lossy(&buffer);
        Some(text.trim_end_matches('\0').to_owned())
    }

    fn battery() -> bool {
        std::process::Command::new("/usr/bin/pmset")
            .args(["-g", "batt"])
            .output()
            .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("InternalBattery"))
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{from_chassis_type, FormFactor};

    pub fn detect() -> Option<FormFactor> {
        let text = std::fs::read_to_string("/sys/class/dmi/id/chassis_type").ok()?;
        from_chassis_type(text.trim().parse().ok()?)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{from_chassis_type, smbios_chassis_type, FormFactor};
    use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;

    // 'RSMB', the raw SMBIOS provider.
    const RSMB: u32 = u32::from_be_bytes(*b"RSMB");
    // The raw table starts after its 8-byte header.
    const HEADER: usize = 8;

    pub fn detect() -> Option<FormFactor> {
        // SAFETY: a null buffer asks only for the size.
        let size = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) } as usize;
        if size <= HEADER {
            return None;
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: the buffer holds `size` bytes.
        let read =
            unsafe { GetSystemFirmwareTable(RSMB, 0, buffer.as_mut_ptr().cast(), size as u32) }
                as usize;
        if read != size {
            return None;
        }
        from_chassis_type(smbios_chassis_type(&buffer[HEADER..])?)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod platform {
    pub fn detect() -> Option<super::FormFactor> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chassis_types_map_to_shapes() {
        assert_eq!(from_chassis_type(9), Some(FormFactor::Laptop));
        assert_eq!(from_chassis_type(10), Some(FormFactor::Laptop));
        assert_eq!(from_chassis_type(13), Some(FormFactor::AllInOne));
        assert_eq!(from_chassis_type(3), Some(FormFactor::Desktop));
        assert_eq!(from_chassis_type(35), Some(FormFactor::Desktop));
        assert_eq!(from_chassis_type(23), Some(FormFactor::Server));
        // The lock bit does not change the type.
        assert_eq!(from_chassis_type(0x80 | 17), Some(FormFactor::Server));
        // QEMU and most hypervisors answer Other.
        assert_eq!(from_chassis_type(1), None);
        assert_eq!(from_chassis_type(2), None);
    }

    #[test]
    fn mac_models_map_to_shapes() {
        assert_eq!(from_mac_model("Mac14,5", true), FormFactor::Laptop);
        assert_eq!(from_mac_model("MacBookPro18,3", false), FormFactor::Laptop);
        assert_eq!(from_mac_model("iMacPro1,1", false), FormFactor::AllInOne);
        assert_eq!(from_mac_model("Mac15,4", false), FormFactor::AllInOne);
        assert_eq!(from_mac_model("Mac14,3", false), FormFactor::Desktop);
        assert_eq!(from_mac_model("Macmini9,1", false), FormFactor::Desktop);
    }

    #[test]
    fn smbios_table_names_its_chassis() {
        // A type 0 structure with one string, then a type 3 with chassis 10.
        let mut table = vec![0, 4, 0, 0, b'A', 0, 0];
        table.extend([3, 6, 1, 0, 0, 10, 0, 0]);
        table.extend([127, 4, 2, 0, 0, 0]);
        assert_eq!(smbios_chassis_type(&table), Some(10));
        assert_eq!(smbios_chassis_type(&[127, 4, 0, 0, 0, 0]), None);
        assert_eq!(smbios_chassis_type(&[3, 2]), None);
    }

    #[test]
    fn form_factors_name_themselves_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&FormFactor::AllInOne).unwrap(),
            "\"all_in_one\""
        );
        assert_eq!(FormFactor::from_wire("server"), Some(FormFactor::Server));
        assert_eq!(FormFactor::from_wire("tablet"), None);
    }
}
