
use crate::ffi::*;
use core::mem::{transmute, size_of};
use winapi::um::winnt::HANDLE;
use winapi::shared::minwindef::ULONG;

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

pub fn query_thread_info<T>(handle: HANDLE, info: ThreadInfoClass, out_len: Option<&mut usize>) -> Option<*mut T> {
    let mut result: usize = 0;
    let mut len: ULONG = 0;
    unsafe {
        let r = NtQueryInformationThread(handle, info as usize, transmute(&mut result), size_of::<T>(), &mut len);
        if let Some(out_len) = out_len { *out_len = len as usize; }
        if NT_SUCCESS(r) { Some(transmute(result)) } else { None }
    }
}