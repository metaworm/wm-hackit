
use std::ffi::{CString, NulError};

#[cfg(feature = "process_dump")]
#[link(name = "pd")]
extern "cdecl" {
    pub fn DumpModule(pid: u32, address: usize, output_path: *const u8);
}

#[cfg(feature = "process_dump")]
pub fn pd_dump(pid: u32, address: usize, dir: Option<&str>) -> Result<(), NulError> {
    unsafe {
        DumpModule(pid, address, CString::new(dir.unwrap_or("."))?.as_bytes_with_nul().as_ptr());
        Ok(())
    }
}