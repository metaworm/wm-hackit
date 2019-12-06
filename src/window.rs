
use core::mem::{zeroed, transmute};
use core::ptr::null_mut;

use winapi::shared::minwindef::*;
use winapi::shared::windef::*;
use winapi::um::winuser::*;

use crate::string::*;

/// Wrapper of EnumWindows
pub fn enum_window<F: FnMut(HWND) -> bool>(mut callback: F) {
    extern "system" fn wrapper(hwnd: HWND, param: LPARAM) -> BOOL {
        unsafe {
            let callback: *mut &'static mut dyn FnMut(HWND) -> bool = transmute(param);
            return (*callback)(hwnd) as BOOL;
        }
    }
    unsafe {
        let r: &mut dyn FnMut(HWND) -> bool = &mut callback;
        EnumWindows(Some(wrapper), transmute(&r));
    }
}

/// Wrapper of GetTopWindow, GetWindow
pub fn enum_top_window<F: FnMut(HWND) -> bool>(mut callback: F) {
    unsafe {
        let mut hwnd = GetTopWindow(null_mut());
        let mut cont = true;
        while hwnd != null_mut() && cont {
            cont = callback(hwnd);
            hwnd = GetWindow(hwnd, GW_HWNDNEXT);
        }
    }
}

pub trait WindowInfo {
    fn get_tid_pid(self) -> (u32, u32);
    fn is_visible(self) -> bool;
    fn get_text(self) -> String;
    fn get_class_name(self) -> String;
    fn get_wndproc(self) -> usize;
    fn set_wndproc(self, ptr: usize) -> usize;
    fn client_area(self) -> Option<RECT>;
    fn client_size(self) -> (usize, usize);
}

impl WindowInfo for HWND {
    fn get_tid_pid(self) -> (u32, u32) {
        unsafe {
            let mut pid: u32 = 0;
            let tid = GetWindowThreadProcessId(self, &mut pid);
            (tid, pid)
        }
    }

    fn is_visible(self) -> bool {
        unsafe { IsWindowVisible(self) > 0 }
    }

    fn get_text(self) -> String {
        unsafe {
            let mut buf = [0u16; 2000];
            if GetWindowTextW(self, buf.as_mut_ptr(), buf.len() as i32) > 0 {
                String::from_wide(&buf)
            } else { String::new() }
        }
    }

    fn get_class_name(self) -> String {
        unsafe {
            let mut buf = [0u16; 2000];
            if GetClassNameW(self, buf.as_mut_ptr(), buf.len() as i32) > 0 {
                String::from_wide(&buf)
            } else { String::new() }
        }
    }

    fn get_wndproc(self) -> usize {
        unsafe {
            let r = GetWindowLongPtrW(self, GWL_WNDPROC) as usize;
            if r == 0 {
                GetClassLongPtrW(self, GCL_WNDPROC) as usize
            } else { r }
        }
    }

    fn set_wndproc(self, ptr: usize) -> usize {
        unsafe {
            transmute(SetWindowLongPtrW(self, GWL_WNDPROC, transmute(ptr)))
        }
    }

    fn client_area(self) -> Option<RECT> {
        unsafe {
            let mut rect: RECT = zeroed();
            if GetClientRect(self, &mut rect) > 0 {
                Some(rect)
            } else { None }
        }
    }

    fn client_size(self) -> (usize, usize) {
        match self.client_area() {
            Some(r) => ((r.right - r.left) as usize, (r.bottom - r.top) as usize),
            None => (0, 0),
        }
    }
}

pub fn get_top_window(pid: u32) -> HWND {
    let mut result: HWND = null_mut();
    enum_top_window(|hwnd| {
        if pid == hwnd.get_tid_pid().1 {
            result = hwnd; false
        } else { true }
    }); result
}