#![feature(proc_macro_hygiene)]
#![feature(asm)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(unused_must_use)]

use core::ops::Deref;
use core::{ptr, mem};
use core::iter::Iterator;

pub use winapi::shared::minwindef::*;
pub use winapi::um::winnt::*;
pub use winapi::shared::windef::*;
use winapi::um::tlhelp32::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winbase::*;
use winapi::um::errhandlingapi::*;
use winapi::um::memoryapi::*;
use winapi::um::winuser::*;
use winapi::um::heapapi::*;
use winapi::um::handleapi::*;
use winapi::um::debugapi::OutputDebugStringW;

pub mod disasm;
pub mod inject;
pub mod hook;
pub mod ntdll;
pub mod symbol;
pub mod third_util;

mod ffi;
mod string;
mod window;
mod process;
mod toolhelper;

pub use string::*;
pub use window::*;
pub use process::*;
pub use toolhelper::*;
pub use symbol::*;

pub use ffi::SYMOPT_CASE_INSENSITIVE;
pub use ffi::SYMOPT_UNDNAME;

pub struct Handle(pub HANDLE);

impl Handle {
    #[inline(always)]
    pub fn is_valid(&self) -> bool { self.0 != INVALID_HANDLE_VALUE }

    #[inline(always)]
    pub fn is_null(&self) -> bool { self.0.is_null() }

    #[inline]
    pub fn success(&self) -> bool { self.is_valid() && !self.is_null() }
}

impl From<HANDLE> for Handle {
    fn from(handle: HANDLE) -> Self { Self(handle) }
}

impl Deref for Handle {
    type Target = HANDLE;

    fn deref<'a>(&'a self) -> &'a HANDLE { &self.0 }
}

impl Drop for Handle {
    fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
}

#[derive(Debug)]
pub enum Error {
    Win32(DWORD),
    Reason(&'static str),
    Failure,
    DisAsm,
    ReadMemory,
    CreateFile,
    LoadLibrary,
    VirtualAlloc,
    GetProcAddress,
    WindowNotFound,
    ThreadNotFound,
}

impl Error {
    #[inline]
    pub fn last() -> Error { Error::Win32(get_last_error()) }

    #[inline]
    pub fn last_result<T>() -> Result<T, Error> { Err(Self::last()) }
}

#[inline]
pub fn get_last_error() -> DWORD { unsafe { GetLastError() } }

#[inline]
pub fn get_error_string(code: DWORD) -> String {
    unsafe {
        let mut buf = [0 as u16; MAX_PATH as usize];
        if FormatMessageW(
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
            ptr::null_mut(), code, 0, buf.as_mut_ptr(),
            buf.len() as u32, ptr::null_mut()) != 0 {
            format!("{} {}", code, String::from_wide(&buf))
        } else { "".to_string() }
    }
}

#[inline]
pub fn get_last_error_string() -> String {
    get_error_string(get_last_error())
}

pub fn output_debug_string<T: AsRef<str>>(s: T) {
    unsafe { OutputDebugStringW(s.as_ref().to_wide().as_ptr()) }
}

#[inline]
pub fn open_process(pid: u32, access: u32, inherit: bool) -> Handle {
    unsafe { OpenProcess(access, inherit as i32, pid).into() }
}

#[inline]
pub fn get_current_tid() -> u32 {
    unsafe { GetCurrentThreadId() }
}

#[inline]
pub fn get_current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub fn msgbox<T: AsRef<str>>(msg: T) {
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            msg.as_ref().to_wide().as_ptr(),
            "\0\0".as_ptr() as *const u16, 0u32);
    }
}

#[inline]
pub fn open_thread(tid: u32, access: u32, inherit: bool) -> Handle {
    unsafe { Handle::from(OpenThread(access, inherit as i32, tid)) }
}

pub fn suspend_thread(tid: u32) -> Handle {
    let handle = open_thread(tid, THREAD_SUSPEND_RESUME, false);
    if handle.is_valid() { unsafe { SuspendThread(handle.0); } }
    return handle;
}

#[inline]
pub fn resume_thread(handle: &Handle) { unsafe { ResumeThread(handle.0); } }

#[inline]
pub fn heap_alloc(size: usize) -> usize {
    unsafe { mem::transmute(HeapAlloc(GetProcessHeap(), 0, size)) }
}

#[inline]
pub fn heap_free(ptr: usize) {
    unsafe { HeapFree(GetProcessHeap(), 0, mem::transmute(ptr)); }
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! dlog {
    () => ($crate::output_debug_string("\n"));
    ($($arg:tt)*) => ({
        $crate::output_debug_string(format!($($arg)*));
    })
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! dlog {
    () => (());
    ($($arg:tt)*) => (());
}