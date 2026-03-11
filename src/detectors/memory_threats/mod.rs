mod allowlists;
mod deep_scan;
mod elf_parser;
mod fileless;
mod library_injection;
mod masquerading;
mod shellcode;
mod utils;

pub use deep_scan::{deep_scan_process_memory, detect_process_hollowing};
pub use fileless::detect_fileless_malware;
pub use library_injection::detect_ld_preload_injection;
pub use masquerading::detect_process_masquerading;
