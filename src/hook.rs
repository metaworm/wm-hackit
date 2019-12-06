
use crate::{*, disasm::*};

use core::mem::{transmute, size_of};
use core::slice;
use std::sync::Arc;

use dynasm::dynasm;
use dynasmrt::{DynasmApi, ExecutableBuffer};

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct HookContext {
    pub EFlags: usize,
    pub R15: usize,
    pub R14: usize,
    pub R13: usize,
    pub R12: usize,
    pub R11: usize,
    pub R10: usize,
    pub R9: usize,
    pub R8: usize,
    pub Rdi: usize,
    pub Rsi: usize,
    pub Rbp: usize,
    pub Rbx: usize,
    pub Rdx: usize,
    pub Rcx: usize,
    pub Rax: usize,
    pub Rsp: usize,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct HookContext {
    pub EFlags: usize,
    pub Edi: usize,
    pub Esi: usize,
    pub Ebp: usize,
    pub Esp: usize,
    pub Ebx: usize,
    pub Edx: usize,
    pub Ecx: usize,
    pub Eax: usize,
}

impl HookContext {
    #[cfg(target_arch = "x86_64")]
    pub fn arg(&self, i: usize) -> usize {
        unsafe {
            let p: *const usize = transmute(self.Rsp);
            let s = slice::from_raw_parts(p, i + 1);
            match i {
                1 => self.Rcx,
                2 => self.Rdx,
                3 => self.R8,
                4 => self.R9,
                e => s[e],
            }
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn arg(&self, i: usize) -> usize {
        unsafe {
            let p: *const usize = transmute(self.Esp);
            slice::from_raw_parts(p, i + 1)[i]
        }
    }
}

// arg1: &The HookContext, arg2: &The Address to ret
pub type HookCallback = Box<dyn Fn(&mut HookContext, &mut usize)>;

// TODO: prevent to re-entry
unsafe extern "system" fn hook_handler(hook: *mut HookBase, context: *mut HookContext) -> usize {
    let hook = &mut *hook;
    let context = &mut *context;
    let mut addr = 0usize;
    #[cfg(target_arch = "x86")] { context.Esp += 4; }
    (hook.callback)(context, &mut addr);
    #[cfg(target_arch = "x86")] { context.Esp -= 4; }
    if addr > 0 { addr } else { hook.codeback }
}

#[cfg(target_arch = "x86_64")]
fn create_hook_handler() ->  ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; push rsp
        ; push rax
        ; push rcx
        ; push rdx
        ; push rbx
        ; push rbp
        ; push rsi
        ; push rdi
        ; push r8
        ; push r9
        ; push r10
        ; push r11
        ; push r12
        ; push r13
        ; push r14
        ; push r15
        ; pushfq
        ; mov rcx, [rsp+0x88]
        ; mov rdx, rsp
        ; sub rsp, 0x18
        ; mov rax, QWORD hook_handler as _
        ; call rax
        ; add rsp, 0x18
        ; mov [rsp+0x88], rax
        ; popfq
        ; pop r15
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdi
        ; pop rsi
        ; pop rbp
        ; pop rbx
        ; pop rdx
        ; pop rcx
        ; pop rax
        ; pop rsp
        ; ret
    );

    ops.finalize().unwrap()
}

#[cfg(target_arch = "x86")]
fn create_hook_handler() ->  ExecutableBuffer {
    let mut ops = dynasmrt::x86::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x86
        ; pushad
        ; pushf
        ; mov ebp, esp
        ; push ebp
        ; push DWORD [ebp+0x24]
        ; mov eax, DWORD hook_handler as _
        ; call eax
        ; mov [ebp+0x24], eax
        ; popf
        ; popad
        ; ret
    );

    ops.finalize().unwrap()
}

// generate the handler function dynamiclly
unsafe fn get_hook_handler() -> usize {
    static mut CODEBUF: Option<ExecutableBuffer> = None;

    CODEBUF.get_or_insert_with(create_hook_handler).ptr(dynasmrt::AssemblyOffset(0usize)) as usize
}


pub struct InsnWriter {
    pc: usize,
}

#[cfg(target_arch = "x86_64")]
fn is_in_same_4gb(from: usize, to: usize) -> (bool, isize) {
    let delta = to as isize - from as isize;
    return (delta.abs() < 0x80000000, delta);
}

pub enum Register {
    ZAX = 0, ZCX, ZDX, ZBX, ZSP, ZBP, ZSI, ZDI,
}

impl InsnWriter {
    pub fn new<T>(pc: *const T) -> InsnWriter {
        InsnWriter {pc: pc as usize}
    }

    // xxx [dest]
    #[cfg(target_arch = "x86_64")]
    fn write_dest(&mut self, dest: usize) {
        let (in_same_4gb, _delta) = is_in_same_4gb(self.pc as usize + size_of::<u32>(), dest);
        if !in_same_4gb { msgbox("NOT IN SAME 4GB"); }
        self.write_offset(dest);
    }
    #[cfg(target_arch = "x86")]
    fn write_dest(&mut self, dest: usize) { self.write(dest as isize); }

    fn write_offset(&mut self, dest: usize) {
        let offset = dest as isize - self.pc as isize - size_of::<i32>() as isize;
        self.write(offset as i32);
    }

    fn write<T>(&mut self, val: T) {
        unsafe {
            *(self.pc as *mut T) = val;
            self.pc = self.pc + size_of::<T>();
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        unsafe {
            let s = slice::from_raw_parts_mut(self.pc as *mut u8, bytes.len());
            s.copy_from_slice(bytes);
            self.pc += s.len();
        }
    }

    fn jmp(&mut self, addr: usize) {
        self.write(0xE9u8);
        self.write_offset(addr);
    }

    fn call(&mut self, addr: usize) {
        self.write(0xE8u8);
        self.write_offset(addr);
    }

    pub fn jmp_mem<T>(&mut self, addr: *const T) {
        self.write(0x25FFu16);
        self.write_dest(addr as usize);
    }

    pub fn call_mem<T>(&mut self, addr: *const T) {
        self.write(0x15FFu16);
        self.write_dest(addr as usize);
    }

    // push imm
    pub fn push_imm(&mut self, imm: u32) {
        self.write(0x68u8);
        self.write(imm);
    }

    #[cfg(target_arch = "x86_64")]
    pub fn push_usize(&mut self, imm: usize) {
        self.push_imm((imm & 0xFFFFFFFF) as u32);
        // c7 44 24 04 ?? ?? ?? ??  // mov dword ptr [rsp+4], 0x????????
        self.write(0x042444C7u32);
        self.write((imm >> 32) as u32);
    }

    #[cfg(target_arch = "x86")]
    pub fn push_usize(&mut self, imm: usize) { self.push_imm(imm as u32); }

    // push [mem]
    pub fn push_mem(&mut self, mem: usize) {
        self.write(0x35FFu16);
        self.write_dest(mem);
    }

    pub fn push_reg(&mut self, reg: Register) {
        self.write((0x50 | reg as u8) as u8);
    }

    pub fn pop_reg(&mut self, reg: Register) {
        self.write((0x58 | reg as u8) as u8);
    }

    /// mov rax, [mem]
    pub fn mov_zax_mem(&mut self, mem: usize) {
        #[cfg(target_arch = "x86_64")] {
            self.write(0x48u8);
        }
        self.write(0xA1u8);
        self.write(mem);
    }

    /// xchg rax, [rsp]
    pub fn xchg_zax_stack(&mut self) {
        #[cfg(target_arch = "x86_64")] {
            self.write(0x48u8);
        }
        self.write(0x87u8);
        self.write(0x04u8);
        self.write(0x24u8);
    }

    pub fn ret(&mut self) { self.write(0xC3u8); }

    pub fn retn(&mut self, n: u16) { self.write(0xC2u8); self.write(n); }

    pub fn pushfd(&mut self) { self.write(0x9cu8); }

    pub fn popfd(&mut self) { self.write(0x9du8); }

    pub fn pushad(&mut self) { self.write(0x60u8); }

    pub fn popad(&mut self) { self.write(0x61u8); }
}

#[repr(C)]
pub struct HookBase {
    pub address: usize,
    pub codeback: usize,
    pub callback: HookCallback,
}

pub trait Hook {
    fn enable(&self) -> bool;
    fn disable(&self) -> bool;
}

pub struct TrapLine {
    pub jmp_back: usize,
    pub trap_left: [u8; MAX_INSN_SIZE * 2],
    pub trap_right: [u8; MAX_INSN_SIZE * 2],
}

#[inline]
fn virtual_reserve_commit(address: usize, size: usize, protect: u32) -> usize {
    this_process().virtual_alloc(address, size, MEM_RESERVE | MEM_COMMIT, protect)
}

#[cfg(target_arch = "x86_64")]
fn alloc_mem_in_4gb(address: usize, size: usize) -> Result<usize, Error> {
    const LOW_2GB: usize = 0x7FFFFFFF;
    let begin_address = if address > LOW_2GB { address - LOW_2GB } else { 0x10000 };
    for m in this_process().enum_memory(begin_address) {
        if m.base > address && m.base - address > LOW_2GB { break; }
        if m.is_free() && (m.base & 0xFFFF == 0) {
            let r = virtual_reserve_commit(m.base, size, PAGE_EXECUTE_READWRITE);
            if r > 0 { return Ok(r) }
        }
    }
    Err(Error::Reason("alloc_mem_in_4gb"))
}

#[cfg(target_arch = "x86")]
fn alloc_mem_in_4gb(address: usize, size: usize) -> Result<usize, Error> {
    let r = virtual_reserve_commit(0usize, size, PAGE_EXECUTE_READWRITE);
    if r > 0 { Ok(r) } else { Err(Error::VirtualAlloc) }
}

impl TrapLine {
    pub fn alloc_in_4gb(address: usize) -> Result<&'static mut TrapLine, Error> {
        let result = alloc_mem_in_4gb(address, size_of::<TrapLine>())?;
        unsafe { Ok(transmute(result)) }
    }

    pub fn alloc() -> Result<&'static mut TrapLine, Error> {
        let result = virtual_reserve_commit(0usize, size_of::<TrapLine>(), PAGE_EXECUTE_READWRITE);
        unsafe {
            if result > 0 { Ok(transmute(result)) } else { Err(Error::VirtualAlloc) }
        }
    }

    pub(crate) fn write_left(&self, arg: *const HookBase) {
        let mut iw = InsnWriter::new(self.trap_left.as_ptr());
        unsafe {
            iw.push_usize(arg as usize);
            iw.push_usize(get_hook_handler());
            iw.ret();
        }
    }

    fn left(&self) -> *const u8 { self.trap_left.as_ptr() }
}

pub struct InlineHook {
    pub base: HookBase,
    pub rawbytes: [u8; SIZE_OF_CALL],
    pub trapline: &'static mut TrapLine,
}

impl InlineHook {
    pub fn trap_back(&self) -> usize {
        self.trapline.trap_right.as_ptr() as usize
    }

    pub fn jmp_code_bytes(&self) -> [u8; SIZE_OF_CALL] {
        let disp = self.trapline.left() as isize - self.base.address as isize - SIZE_OF_CALL as isize;
        let mut r = [0xE9u8, 0, 0, 0, 0];
        unsafe {
            *((&mut r[1..]).as_mut_ptr() as *mut i32) = disp as i32;
            return r;
        }
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        // TODO: delete self.trapline
    }
}

impl Hook for InlineHook {
    fn enable(&self) -> bool {
        let r = this_process().write_memory(self.base.address, &self.jmp_code_bytes()) > 0;
        return r;
    }

    fn disable(&self) -> bool {
        this_process().write_memory(self.base.address, &self.rawbytes) > 0
    }
}

pub struct TableHook {
    pub base: HookBase,
    pub trapline: &'static mut TrapLine,
}

impl Hook for TableHook {
    fn enable(&self) -> bool {
        let trap_left = self.trapline.left() as usize;
        this_process().write(self.base.address, &trap_left)
    }

    fn disable(&self) -> bool {
        this_process().write(self.base.address, &self.base.codeback)
    }
}

pub fn get_code_bytes(address: usize, len: usize) -> Result<Vec<u8>, Error> {
    let mut result: Vec<u8> = Vec::with_capacity(MAX_INSN_SIZE);

    let tp = this_process();
    while let Some(insn) = tp.disasm(address + result.len()) {
        result.extend_from_slice(insn.bytes());
        if result.len() >= len { return Ok(result); }
    }
    return Err(Error::DisAsm);
}

pub fn create_inline_hook(address: usize, callback: HookCallback) -> Result<Arc<InlineHook>, Error> {
    let tp = this_process();
    let trapline = TrapLine::alloc_in_4gb(address)?;
    let right_ptr = trapline.trap_right.as_ptr();
    let hook = InlineHook {
        base: HookBase { address, callback, codeback: right_ptr as usize },
        trapline, rawbytes: tp.read(address).map_err(|_| Error::ReadMemory)?,
    };

    let origin_code = get_code_bytes(address, SIZE_OF_CALL)?;
    let jmpback_address = address + origin_code.len();
    let mut iw = InsnWriter::new(right_ptr);
    let mut offset = 0usize;
    while let Some(insn) = DisAsmWrapper::new(address + offset, &origin_code[offset..]) {
        offset += insn.len();
        // Handle the specific instructions: call/jmp
        let is_call = insn.mnemonic == Mnemonic::CALL;
        if is_call || insn.mnemonic == Mnemonic::JMP {
            let op = &insn.operands[0];
            let target_address = insn.calc_absolute_address(insn.address as u64, op)
                                     .map_err(|_| Error::Reason("Absolute Address"))? as usize;
            if is_call { iw.push_usize(jmpback_address); }              // push jmpback     ; Ensure the callee can return back
            // Jump to the real address of call/jmp instruction
            match op.ty {
                OperandType::IMMEDIATE => {
                    hook.trapline.jmp_back = target_address;
                    iw.jmp_mem(&hook.trapline.jmp_back);                // jmp [target_address]
                }
                OperandType::MEMORY => {
                    if cfg!(target_arch = "x86_64") {
                        iw.push_reg(Register::ZAX);                         // push rax
                        iw.mov_zax_mem(target_address);                     // mov rax, [target_address]
                        iw.xchg_zax_stack();                                // xchg rax, [rsp]
                        iw.ret();                                           // ret
                    } else {
                        iw.jmp_mem(target_address as *const u8);            // jmp [target_address]
                    }
                }
                _ => { return Err(Error::Reason("Invalid Operand")); }
            }
            break;
        } else { iw.write_bytes(insn.bytes()); }
    }
    assert!(origin_code.len() < MAX_INSN_SIZE);

    let hook = Arc::new(hook);
    hook.trapline.write_left(&hook.base);
    Ok(hook)
}

pub fn create_table_hook(address: usize, callback: HookCallback) -> Result<Arc<TableHook>, Error> {
    let tp = this_process();
    let raw_pointer: usize = tp.read(address)?;
    let hook = Arc::new(TableHook {
        base: HookBase {address, callback, codeback: raw_pointer},
        trapline: TrapLine::alloc_in_4gb(address)?,
    });
    hook.trapline.write_left(&hook.base);

    Ok(hook)
}

pub fn suspend_else_threads() -> Vec<Handle> {
    let mut result: Vec<Handle> = Vec::new();
    let tid = get_current_tid();
    for t in this_process().enum_thread() {
        if t.tid() != tid {
            result.push(suspend_thread(t.tid()));
        }
    }
    return result;
}

pub fn new_inline_hook<F>(address: usize, callback: F) -> Result<bool, Error>
where F: Fn(&mut HookContext, &mut usize) + 'static {
    create_inline_hook(address, Box::new(callback)).and_then(|hook| {
        let tids = suspend_else_threads();
        let result = hook.enable();
        tids.iter().for_each(resume_thread);
        Ok(result)
    })
}

pub fn new_table_hook<F>(address: usize, callback: F) -> Result<bool, Error>
where F: Fn(&mut HookContext, &mut usize) + 'static {
    create_table_hook(address, Box::new(callback)).and_then(|hook| Ok(hook.enable()))
}