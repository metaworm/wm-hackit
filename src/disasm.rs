
use core::ops::Deref;
use crate::process::*;

pub use zydis::{
    OutputBuffer, FormatterStyle,
    DecodedInstruction, DecodedOperand,
    MachineMode, AddressWidth, Mnemonic,
    formatter::Formatter, OperandType,
};

pub struct DisAsmWrapper {
    pub address: usize,
    data: [u8; 16],
    insn: DecodedInstruction,
}

impl Deref for DisAsmWrapper {
    type Target = DecodedInstruction;
    fn deref(&self) -> &DecodedInstruction { &self.insn }
}

impl DisAsmWrapper {
    pub fn new(address: usize, buffer: &[u8]) -> Option<Self> {
        let decoder = if cfg!(target_arch = "x86_64") {
            zydis::Decoder::new(MachineMode::LONG_64, AddressWidth::_64).unwrap()
        } else {
            zydis::Decoder::new(MachineMode::LEGACY_32, AddressWidth::_32).unwrap()
        };
        let insn = decoder.decode(buffer).ok()??;
        let length = insn.length as usize;
        let mut data = [0u8; 16];
        (&mut data[..length]).copy_from_slice(&buffer[..length]);
        Some(Self { insn, address, data })
    }

    #[inline]
    pub fn len(&self) -> usize { self.length as usize }

    #[inline]
    pub fn bytes(&self) -> &[u8] { &self.data[0..self.len()] }

    pub fn to_string(&self) -> String {
        let formatter = Formatter::new(FormatterStyle::INTEL).unwrap();
        let mut v = [0u8; 200];
        let mut buf = OutputBuffer::new(&mut v);
        formatter.format_instruction(self, &mut buf, Some(self.address as u64), None);
        buf.as_str().unwrap().to_string()
    }
}

pub trait DisAsmUtil {
    fn disasm(&self, address: usize) -> Option<DisAsmWrapper>;
}

impl DisAsmUtil for Process {
    fn disasm(&self, address: usize) -> Option<DisAsmWrapper> {
        let mut buf = [0 as u8; MAX_INSN_SIZE];
        if self.read_memory(address, &mut buf).len() > 0 {
            DisAsmWrapper::new(address, &buf)
        } else { None }
    }
}