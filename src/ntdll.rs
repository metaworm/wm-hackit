
pub use crate::ffi::*;
use crate::string::*;

use core::mem::{transmute, size_of, zeroed, size_of_val};
use winapi::um::winnt::HANDLE;
use winapi::shared::ntdef::*;

pub enum ProcessInfoClass {
    BasicInformation = 0,
    DebugPort = 7,
    Wow64Information = 26,
    ImageFileName = 27,
    BreakOnTermination = 29,
    SubsystemInformation = 75,
}

pub enum ThreadInfoClass {
    BasicInformation = 0,
    Times = 1,
    Priority = 2,
    BasePriority = 3,
    AffinityMask = 4,
    ImpersonationToken = 5,
    DescriptorTableEntry = 6,
    EnableAlignmentFaultFixup = 7,
    EventPair = 8,
    QuerySetWin32StartAddress = 9,
    ZeroTlsCell = 10,
    PerformanceCount = 11,
    AmILastThread = 12,
    IdealProcessor = 13,
    PriorityBoost = 14,
    SetTlsArrayAddress = 15,
    IsIoPending = 16,
    HideFromDebugger = 17,
}

pub fn NT_SUCCESS(status: NTSTATUS) -> bool { status >= 0 }

pub fn error(status: NTSTATUS) -> &'static str {
    use winapi::um::winnt::*;
    match status as u32 {
        STATUS_ACCESS_VIOLATION => "STATUS_ACCESS_VIOLATION",
        STATUS_INVALID_PARAMETER => "STATUS_INVALID_PARAMETER",
        0xC0000004 => "STATUS_INFO_LENGTH_MISMATCH",
        0xC0000022 => "STATUS_ACCESS_DENIED",
        0xC0000003 => "STATUS_INVALID_INFO_CLASS",
        _ => "<UNKNOWN>",
    }
}

pub fn query_thread_info<T>(handle: HANDLE, info: ThreadInfoClass, out_len: Option<&mut usize>) -> Option<*mut T> {
    let mut result: usize = 0;
    let mut len: ULONG = 0;
    unsafe {
        let r = NtQueryInformationThread(handle, info as usize, transmute(&mut result), size_of::<T>(), &mut len);
        if let Some(out_len) = out_len { *out_len = len as usize; }
        if NT_SUCCESS(r) { Some(transmute(result)) } else { None }
    }
}

pub fn get_mapped_file_name(handle: HANDLE, base: usize) -> Option<String> {
    struct MEMORY_MAPPED_FILE_NAME_INFORMATION {
        name: UNICODE_STRING,
        buffer: [WCHAR; 512],
    }

    let mut buffer: MEMORY_MAPPED_FILE_NAME_INFORMATION = unsafe { zeroed() };
    buffer.name.Length = 0;
    buffer.name.Buffer = buffer.buffer.as_mut_ptr();
    let mut len: ULONG = 0;
    unsafe {
        let r = NtQueryVirtualMemory(handle, base, MEMORY_INFORMATION_CLASS::MemoryMappedFilenameInformation, transmute(&mut buffer), size_of_val(&buffer), &mut len);
        if NT_SUCCESS(r) { Some(buffer.name.to_string()) } else { None }
    }
}

pub trait UnicodeUtil {
    fn to_string(&self) -> String;
}

impl UnicodeUtil for UNICODE_STRING {
    fn to_string(&self) -> String {
        unsafe {
            String::from_wide(std::slice::from_raw_parts(self.Buffer, self.Length as usize))
        }
    }
}

use std::alloc::{System, Layout, GlobalAlloc};
use std::ops::Deref;

pub struct UnicdoeString(UNICODE_STRING);

impl UnicdoeString {
    pub fn with_capacity(size: usize) -> Self {
        Self(UNICODE_STRING {
            Length: 0, MaximumLength: size as USHORT,
            Buffer: unsafe {
                System.alloc(Layout::from_size_align(size, 2).unwrap()) as *mut u16
            },
        })
    }
}

impl Deref for UnicdoeString {
    type Target = UNICODE_STRING;

    #[inline(always)]
    fn deref(&self) -> &UNICODE_STRING { &self.0 }
}

impl Drop for UnicdoeString {
    fn drop(&mut self) {
        unsafe {
            System.dealloc(self.Buffer as *mut u8, Layout::from_size_align(self.MaximumLength as usize, 2).unwrap());
        }
    }
}

// https://docs.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification
pub type FnLdrRegisterDllNotification = unsafe extern "system" fn(flags: ULONG, callback: LDR_DLL_NOTIFICATION_FUNCTION, context: PVOID, cookie: *mut usize) -> NTSTATUS;