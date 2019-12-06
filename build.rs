#![deny(warnings)]
#![feature(rustc_private)]

extern crate cc;

use std::env;

fn main() {
    let target = env::var("TARGET").expect("TARGET was not set");
    if !target.contains("windows") {
        panic!("Only Windows platform is supported");
    }

    if cfg!(feature = "rdi_dll_lib") {
        build_rdi_dll_lib(&target);
    }

    if cfg!(feature = "rdi_inject") {
        build_rdi_inject(&target);
    }

    if cfg!(feature = "process_dump") {
        build_process_dump(&target);
    }
}

fn build_process_dump(_target: &String) {
    let mut build = cc::Build::new();
    build
        .define("_UNICODE", None)
        .define("UNICODE", None)
        .flag("/Zc:wchar_t")
        .file("Process-Dump/pd/dump_process.cpp")
        .file("Process-Dump/pd/export_list.cpp")
        .file("Process-Dump/pd/hash.cpp")
        .file("Process-Dump/pd/module_list.cpp")
        .file("Process-Dump/pd/pd.cpp")
        .file("Process-Dump/pd/pe_exports.cpp")
        .file("Process-Dump/pd/pe_hash_database.cpp")
        .file("Process-Dump/pd/terminate_monitor_hook.cpp")
        .file("Process-Dump/pd/pe_header.cpp")
        .file("Process-Dump/pd/pe_imports.cpp")
        .file("Process-Dump/pd/close_watcher.cpp")
        .file("Process-Dump/pd/simple.cpp")
        .file("Process-Dump/pd/stdafx.cpp")
        .compile("pd");
}

fn build_rdi_dll_lib(target: &String) {
    let mut build = cc::Build::new();
    build
        .define("REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN", None)
        .define("_WINDLL", None)
        .define("REFLECTIVE_DLL_EXPORTS", None)
        .define("REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR", None)
        .file("ReflectiveDLLInjection/dll/src/ReflectiveLoader.c");
    if target.contains("x86_64") {
        build.define("WIN_X64", None);
    } else {
        build.define("WIN_X86", None);
    }
    build.compile("rdi_dll_lib");
}

fn build_rdi_inject(target: &String) {
    let mut build = cc::Build::new();
    build
        .file("ReflectiveDLLInjection/inject/src/GetProcAddressR.c")
        .file("ReflectiveDLLInjection/inject/src/LoadLibraryR.c");
    if target.contains("x86_64") {
        build.define("WIN_X64", None);
    } else {
        build.define("WIN_X86", None);
    }
    build.compile("rdi_inject");
}