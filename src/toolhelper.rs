
use crate::*;

use core::mem::{size_of_val, zeroed};

// use winapi::shared::minwindef::*;
// use winapi::um::winnt::*;
// use winapi::shared::windef::*;
// use winapi::um::tlhelp32::*;

type ToolHelper<T> = unsafe extern "system" fn(HANDLE, *mut T) -> BOOL;

pub struct ToolHelperIter<T: Copy> {
    count: u32,
    handle: Handle,
    data: T,
    f_first: ToolHelper<T>,
    f_next: ToolHelper<T>,
}

impl<T: Copy> ToolHelperIter<T> {
    fn new(handle: Handle, data: T, f_first: ToolHelper<T>, f_next: ToolHelper<T>) -> ToolHelperIter<T> {
        // assert!(handle != INVALID_HANDLE_VALUE);
        ToolHelperIter { handle, count: 0, data, f_first: f_first, f_next: f_next }
    }

    fn next_item(&mut self) -> bool {
        let success = unsafe {
            if self.count > 0 {
                (self.f_next)(*self.handle, &mut self.data) > 0
            } else {
                (self.f_first)(*self.handle, &mut self.data) > 0
            }
        };
        self.count += 1;
        return success;
    }
}

impl<T: Copy> Iterator for ToolHelperIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next_item() { Some(self.data) } else { None }
    }
}

pub trait ProcessInfo {
    fn pid(&self) -> u32;
    fn name(&self) -> String;
}

impl ProcessInfo for PROCESSENTRY32W {
    #[inline]
    fn pid(&self) -> u32 { self.th32ProcessID }
    #[inline]
    fn name(&self) -> String { String::from_wide(&self.szExeFile) }
}

pub fn enum_process() -> ToolHelperIter<PROCESSENTRY32W> {
    unsafe {
        let mut pe32: PROCESSENTRY32W = zeroed();
        pe32.dwSize = size_of_val(&pe32) as u32;
        ToolHelperIter::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).into(), pe32, Process32FirstW, Process32NextW)
    }
}

pub fn enum_process_filter_name(name: &str) -> impl Iterator<Item = PROCESSENTRY32W> + '_ {
    enum_process().filter(move |p| p.name().find(name).is_some())
}

// --------------------------------------------

pub trait ThreadInfo {
    fn pid(&self) -> u32;
    fn tid(&self) -> u32;
}

impl ThreadInfo for THREADENTRY32 {
    #[inline]
    fn pid(&self) -> u32 { self.th32OwnerProcessID }
    #[inline]
    fn tid(&self) -> u32 { self.th32ThreadID }
}

pub fn enum_thread() -> ToolHelperIter<THREADENTRY32> {
    unsafe {
        let mut te32: THREADENTRY32 = zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        ToolHelperIter::new(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).into(), te32, Thread32First, Thread32Next)
    }
}

// --------------------------------------------

pub trait ModuleInfo {
    fn name(&self) -> String;
    fn base(&self) -> usize;
    fn size(&self) -> usize;
    fn path(&self) -> String;
    fn id(&self) -> u32;
}

impl ModuleInfo for MODULEENTRY32W {
    fn name(&self) -> String { String::from_wide(&self.szModule) }
    fn path(&self) -> String { String::from_wide(&self.szExePath) }
    fn base(&self) -> usize { self.modBaseAddr as usize }
    fn size(&self) -> usize { self.modBaseSize as usize }
    fn id(&self) -> u32 { self.th32ModuleID }
}

pub fn enum_module(pid: u32) -> ToolHelperIter<MODULEENTRY32W> {
    unsafe {
        let mut te32: MODULEENTRY32W = zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        ToolHelperIter::new(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid).into(), te32, Module32FirstW, Module32NextW)
    }
}

pub struct MemoryInfo {
    pub base: usize,
    pub alloc_base: usize,
    pub size: usize,
    pub type_: u32,
    pub state: u32,
    pub protect: u32,
    pub alloc_protect: u32,
}

impl MemoryInfo {
    pub fn from_mbi(mbi: &MEMORY_BASIC_INFORMATION) -> MemoryInfo {
        MemoryInfo {
            base: mbi.BaseAddress as usize,
            alloc_base: mbi.AllocationBase as usize,
            size: mbi.RegionSize,
            type_: mbi.Type,
            state: mbi.State,
            protect: mbi.Protect,
            alloc_protect: mbi.AllocationProtect,
        }
    }

    #[inline]
    pub fn is_commit(&self) -> bool { self.state & MEM_COMMIT > 0 }

    #[inline]
    pub fn is_reserve(&self) -> bool { self.state & MEM_RESERVE > 0 }

    #[inline]
    pub fn is_free(&self) -> bool { self.state & MEM_FREE > 0 }

    #[inline]
    pub fn is_private(&self) -> bool { self.type_ & MEM_PRIVATE > 0 }
}