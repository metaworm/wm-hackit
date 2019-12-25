
use crate::*;

use core::ffi::c_void;
use core::slice;
use core::mem::{zeroed, transmute, size_of, size_of_val};

use winapi::um::psapi::*;
use winapi::um::fileapi::*;

pub const SIZE_OF_CALL: usize = 5;
pub const MAX_INSN_SIZE: usize = 16;

pub fn read_process_memory(handle: HANDLE, address: usize, data: &mut [u8]) -> usize {
    let mut readed = 0usize;
    let address = address as LPVOID;
    let pdata = data.as_mut_ptr() as LPVOID;
    unsafe {
        if ReadProcessMemory(handle, address, pdata, data.len(), &mut readed) > 0 {
            readed
        } else { 0usize }
    }
}

pub fn write_process_memory(handle: HANDLE, address: usize, data: &[u8]) -> usize {
    let mut written = 0usize;
    let mut old_protect = 0u32;
    let mut new_protect = 0u32;
    let address = address as LPVOID;
    unsafe {
        VirtualProtectEx(handle, address, data.len(), PAGE_EXECUTE_READWRITE, &mut old_protect);
        let result = WriteProcessMemory(
                handle, address, data.as_ptr() as LPVOID, data.len(), &mut written);
        VirtualProtectEx(handle, address, data.len(), old_protect, &mut new_protect);
        if result > 0 { written } else { 0usize }
    }
}

pub struct Process {
    pub pid: u32,
    pub handle: Handle,
}

pub enum DumpType {
    Mini,
    Full
}

pub struct SymbolInfo {
    pub module: String,
    pub symbol: String,
    pub offset: usize,
    pub mod_base: usize,
}

pub struct MemoryIter<'p> {
    pub process: &'p Process,
    pub address: usize,
}

impl MemoryIter<'_> {
    pub fn next_commit(&mut self) -> Option<MemoryInfo> {
        while let Some(m) = self.next() {
            if m.is_commit() { return Some(m); }
        }
        return None;
    }
}

impl Iterator for MemoryIter<'_> {
    type Item = MemoryInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.process.virtual_query(self.address);
        if let Ok(m) = result.as_ref() {
            self.address += m.size;
            // println!("page: 0x{:x} page-size: 0x{:x}", m.base, m.size);
        }
        return result.ok();
    }
}

impl Process {
    pub fn open(pid: u32, access: Option<u32>) -> Result<Process, Error> {
        unsafe {
            let handle = OpenProcess(access.unwrap_or(PROCESS_ALL_ACCESS), 0, pid);
            if handle.is_null() {
                Error::last_result()
            } else {
                Process::from_handle(handle)
            }
        }
    }

    // https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
    pub fn is_wow64(&self) -> bool {
        use winapi::um::wow64apiset::IsWow64Process;
        let mut result: BOOL = 0;
        unsafe { IsWow64Process(*self.handle, &mut result); };
        return result != 0;
    }

    pub fn from_handle(handle: HANDLE) -> Result<Process, Error> {
        unsafe {
            let pid = GetProcessId(handle);
            if pid == 0 { return Error::last_result(); }

            return Ok(Process { pid, handle: handle.into() });
        }
    }

    pub(crate) fn current() -> Process {
        unsafe { Self::from_handle(GetCurrentProcess()).unwrap() }
    }

    pub fn get_module_name(&self, module: u64) -> Result<String, Error> {
        unsafe {
            let mut name = [0 as u16; MAX_PATH];
            if GetModuleBaseNameW(*self.handle, module as HMODULE, name.as_mut_ptr(), MAX_PATH as u32) > 0 {
                Ok(String::from_wide(&name))
            } else { Error::last_result() }
        }
    }

    pub fn get_module_path(&self, module: u64) -> Result<String, Error> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            if GetModuleFileNameExW(*self.handle, module as HMODULE, path.as_mut_ptr(), MAX_PATH as u32) > 0 {
                Ok(String::from_wide(&path))
            } else { Error::last_result() }
        }
    }

    #[inline]
    pub fn enum_thread<'a>(&'a self) -> impl Iterator<Item=THREADENTRY32> + 'a {
        enum_thread().filter(move |x| x.pid() == self.pid)
    }

    #[inline]
    pub fn enum_module(&self) -> ToolHelperIter<MODULEENTRY32W> { enum_module(self.pid) }

    pub fn image_path(&self) -> Result<String, Error> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            let mut size = path.len() as u32;
            if QueryFullProcessImageNameW(*self.handle, 0, path.as_mut_ptr(), &mut size) > 0 {
                Ok(String::from_wide(&path))
            } else { Error::last_result() }
        }
    }

    pub fn protect_memory(&self, address: usize, size: usize, attr: u32) -> Option<u32> {
        unsafe {
            let mut oldattr = 0u32;
            let r = VirtualProtectEx(*self.handle, address as LPVOID, size, attr, &mut oldattr);
            if r > 0 { Some(oldattr) } else { None }
        }
    }

    pub fn read_memory<'a>(&self, address: usize, data: &'a mut [u8]) -> &'a mut [u8] {
        let r = read_process_memory(*self.handle, address, data);
        &mut data[..r]
    }

    pub fn write_memory(&self, address: usize, data: &[u8]) -> usize {
        write_process_memory(*self.handle, address, data)
    }

    pub fn write_code(&self, address: usize, data: &[u8]) -> usize {
        let r = write_process_memory(*self.handle, address, data);
        unsafe {
            FlushInstructionCache(*self.handle, address as LPCVOID, data.len());
        }
        return r;
    }

    pub fn read_util<T: PartialEq + Clone>(&self, address: usize, val: T, max_bytes: usize) -> Vec<T> {
        const BUFLEN: usize = 100usize;
        let bufsize = BUFLEN * size_of::<T>();
        let mut result: Vec<T> = Vec::with_capacity(BUFLEN);

        unsafe {
            let mut buf: [T; BUFLEN] = zeroed();
            let mut addr = address;

            let pdata: *mut u8 = transmute(buf.as_mut_ptr());
            let mut data = slice::from_raw_parts_mut(pdata, bufsize);
            while self.read_memory(addr, &mut data).len() > 0 {
                let mut end = false;
                let mut pos = match buf.iter().position(|x| x == &val) {
                    None => buf.len(),
                    Some(pos) => { end = true; pos },
                };
                if addr - address > max_bytes {
                    end = true;
                    pos = addr - address - max_bytes;
                }
                result.extend_from_slice(&buf[..pos]);
                if end { break; }
                addr += BUFLEN;
            }
        }
        return result;
    }

    pub fn read_bytes(&self, address: usize, size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(size);
        result.resize(size, 0);
        let r = self.read_memory(address, &mut result).len();
        result.resize(r, 0);

        result
    }

    pub fn read_cstr(&self, address: usize) -> Result<String, Error> {
        unsafe {
            Ok(String::from_utf8_unchecked(self.read_util(address, 0u8, 1000)))
        }
    }

    pub fn read_wstr(&self, address: usize) -> String {
        String::from_wide(&self.read_util(address, 0u16, 1000))
    }

    pub fn write_cstr(&self, address: usize, s: String) -> bool {
        let b = self.write_memory(address, s.as_bytes()) == s.len();
        return b && self.write(address + s.len(), &0u8);
    }

    pub fn read<T: Copy>(&self, address: usize) -> Result<T, Error> {
        unsafe {
            let mut val: T = zeroed();
            let size = size_of::<T>();
            let pdata: *mut u8 = transmute(&mut val);
            let mut data = slice::from_raw_parts_mut(pdata, size);
            let readed = self.read_memory(address, &mut data);
            if readed.len() == size { Ok(val) } else { Error::last_result() }
        }
    }

    pub fn write<T>(&self, address: usize, val: &T) -> bool {
        unsafe {
            let size = size_of::<T>();
            let pdata: *mut u8 = transmute(val);
            let data = slice::from_raw_parts(pdata, size);
            self.write_memory(address, data) == size
        }
    }

    pub fn read_nt_header(&self, mod_base: usize) -> Option<IMAGE_NT_HEADERS> {
        let dos: IMAGE_DOS_HEADER = self.read(mod_base).ok()?;
        if dos.e_magic != IMAGE_DOS_SIGNATURE { return None; }
        let nt: IMAGE_NT_HEADERS = self.read(mod_base + dos.e_lfanew as usize).ok()?;
        if nt.Signature != IMAGE_NT_SIGNATURE { return None; }
        Some(nt)
    }

    pub fn enum_memory(&self, address: usize) -> MemoryIter {
        MemoryIter {process: self, address: address}
    }

    pub fn virtual_alloc(&self, address: usize, size: usize, mem_type: u32, protect: u32) -> usize {
        unsafe {
            VirtualAllocEx(*self.handle, address as LPVOID, size, mem_type, protect) as usize
        }
    }

    pub fn virtual_free(&self, address: usize) -> bool {
        unsafe {
            VirtualFreeEx(*self.handle, address as LPVOID, 0, MEM_RELEASE) > 0
        }
    }

    pub fn virtual_query(&self, address: usize) -> Result<MemoryInfo, Error> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            match VirtualQueryEx(*self.handle, address as LPVOID, &mut mbi, size_of_val(&mbi)) {
                0 => Error::last_result(),
                _ => Ok(MemoryInfo::from_mbi(&mbi)),
            }
        }
    }

    // https://docs.microsoft.com/zh-cn/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
    pub fn get_mapped_file_name(&self, address: usize) -> Option<String> {
        unsafe {
            let mut buf = [0u16; 300];
            let len = GetMappedFileNameW(*self.handle, address as LPVOID, buf.as_mut_ptr(), buf.len() as u32);
            if len > 0 { Some(String::from_wide(&buf[..len as usize])) } else { None }
        }
    }

    pub fn get_exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        unsafe {
            if GetExitCodeProcess(*self.handle, &mut code) > 0 {
                Some(code)
            } else { None }
        }
    }

    pub fn dump_process(&self, path: &str, dump_type: DumpType) -> Result<(), Error> {
        use crate::ffi::*;

        unsafe extern "system" fn callback(_p: *const c_void, input: *const MINIDUMP_CALLBACK_INPUT, output: *mut MINIDUMP_CALLBACK_OUTPUT) -> BOOL {
            if input.is_null() || output.is_null() { return FALSE; }
            else if IncludeVmRegionCallback == (*input).CallbackType { (*output).Continue = TRUE; }

            TRUE
        }

        unsafe {
            let mci = MINIDUMP_CALLBACK_INFORMATION {
                CallbackRoutine: callback, CallbackParam: ptr::null()
            };
            let file = Handle(CreateFileW(
                path.to_wide().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0, ptr::null_mut(), CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, ptr::null_mut()
            ));
            if !file.success() { return Err(Error::CreateFile); }

            if MiniDumpWriteDump(*self.handle, self.pid, file.0, match dump_type {
                DumpType::Mini => MiniDumpNormal,
                DumpType::Full => MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules |
                                  MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData |
                                  MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo |
                                  MiniDumpWithFullAuxiliaryState | MiniDumpIgnoreInaccessibleMemory |
                                  MiniDumpWithTokenInformation,
            }, ptr::null_mut(), ptr::null_mut(), &mci) == 0 { Error::last_result() } else { Ok(()) }
        }
    }
}

pub fn this_process() -> &'static Process {
    static mut P: Option<Process> = None;

    unsafe { P.get_or_insert_with(|| Process::current()) }
}