
use std::ffi::{OsStr, OsString, CString};
use std::os::windows::prelude::*;

pub trait StrLen {
    fn strlen(&self) -> usize;
}

impl StrLen for &[u16] {
    fn strlen(&self) -> usize {
        match self.iter().position(|&x| x == 0) {
            None => self.len(),
            Some(x) => x,
        }
    }
}

pub trait FromWide {
    fn from_wide(wstr: &[u16]) -> Self;
}

impl FromWide for String {
    fn from_wide(wstr: &[u16]) -> Self {
        OsString::from_wide(&wstr[0..wstr.strlen()]).into_string().unwrap()
    }
}

pub trait StringUtil {
    fn to_wide(&self) -> Vec<u16>;
    fn to_cstring(&self) -> Vec<u8>;
}

impl StringUtil for str {
    fn to_wide(&self) -> Vec<u16> {
        let mut r: Vec<u16> = OsStr::new(self).encode_wide().collect();
        r.push(0u16); return r;
    }

    fn to_cstring(&self) -> Vec<u8> {
        CString::new(self).unwrap().into_bytes_with_nul()
    }
}