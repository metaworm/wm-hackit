
use crate::*;
use winapi::shared::windef::HHOOK;
use winapi::um::libloaderapi::*;

use core::slice::from_raw_parts;
use core::mem::transmute;
use core::ptr;

pub fn by_remotethread(p: &Process, dll_path: &str) -> Result<u32, Error> {
    let buf = p.virtual_alloc(0, dll_path.len() * 2, MEM_COMMIT, PAGE_READWRITE);
    if 0usize == buf { return Err(Error::VirtualAlloc); }

    let dll_path = dll_path.to_wide();
    p.write_memory(buf, unsafe {
        from_raw_parts::<u8>(transmute(dll_path.as_ptr()), dll_path.len() * 2)
    });

    p.sym_init(None, true);
    let load_library = p.get_address_by_symbol("kernel32!LoadLibraryW")?;
    unsafe {
        let mut tid = 0u32;
        let h = CreateRemoteThreadEx(p.handle.0, ptr::null_mut(), 0usize, transmute(load_library), buf as LPVOID, 0u32, ptr::null_mut(), &mut tid);
        if h.is_null() { Error::last_result() } else { CloseHandle(h); Ok(tid) }
    }
}

pub fn by_windowhook(hwnd: HWND, dll_path: &str, func: &str) -> Result<HHOOK, Error> {
    unsafe {
        let tid = GetWindowThreadProcessId(hwnd, ptr::null_mut());
        if tid == 0 { return Err(Error::ThreadNotFound); }

        let hmod = LoadLibraryExW(dll_path.to_wide().as_ptr(), ptr::null_mut(), 1);
        if hmod.is_null() { return Err(Error::LoadLibrary); }

        let hook_proc: usize = transmute(GetProcAddress(hmod, func.to_cstring().as_ptr() as *const i8));
        if 0 == hook_proc {
            FreeLibrary(hmod);
            return Err(Error::GetProcAddress);
        }

        let hook = SetWindowsHookExA(WH_GETMESSAGE, transmute(hook_proc), hmod, tid);
        FreeLibrary(hmod);
        if hook.is_null() { return Error::last_result(); }

        SendMessageA(hwnd, WM_NULL, 0, 0);
        return Ok(hook);
    }
}

// --------------------------- ReflectiveInject ---------------------------

#[cfg(feature = "rdi_inject")]
#[link(name = "rdi_inject")]
extern {
    pub fn GetReflectiveLoaderOffset(buf: *const u8) -> u32;
}

#[cfg(feature = "rdi_inject")]
#[link(name = "rdi_inject")]
extern "stdcall" {
    pub fn LoadRemoteLibraryR(process: HANDLE, lpBuf: LPVOID, dwLength: DWORD, param: LPVOID) -> HANDLE;
    pub fn LoadLibraryR(lpBuf: LPVOID, dwLength: DWORD) -> HMODULE;
}

#[cfg(feature = "rdi_dll_lib")]
#[link(name = "rdi_dll_lib")]
extern "stdcall" {
    #[no_mangle]
    pub fn ReflectiveLoader(param: *const u8) -> *const u8;
}

use crate::Process;

#[cfg(feature = "rdi_inject")]
pub fn by_remotethread_rdi(p: &Process, dll: &[u8]) -> HANDLE {
    unsafe {
        // println!("len {:}", dll.len());
        LoadRemoteLibraryR(p.handle as HANDLE, dll.as_ptr() as LPVOID, dll.len() as DWORD, ptr::null_mut())
    }
}