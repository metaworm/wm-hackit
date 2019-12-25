
use core::mem::transmute;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::winbase::QueryDosDeviceA;
use winapi::um::winbase::GetLogicalDriveStringsA;

// https://docs.microsoft.com/zh-cn/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
pub fn replace_device_name(mut device_path: String) -> String {
    let mut driver_char = [0i8; 100];
    let mut sz_driver = [0i8, b':' as i8, 0];
    unsafe {
        if 0 == GetLogicalDriveStringsA(driver_char.len() as u32, driver_char.as_mut_ptr()) {
            return device_path;
        }
        let mut buffer = [0i8; MAX_PATH];
        for c in driver_char.iter() {
            if *c > 0 {
                sz_driver[0] = *c;
                let mut len = QueryDosDeviceA(sz_driver.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32);
                if len == 0 { continue; }
                while buffer[len as usize - 1] == 0 { len -= 1; }

                let driver: &str = transmute(&sz_driver[..2]);
                let device: &str = transmute(&buffer[..len as usize]);
                if device_path.starts_with(device) {
                    device_path.replace_range(..len as usize, driver); break;
                }
            }
        }
    }
    device_path
}