#![no_main]
#![no_std]
#![feature(lang_items)]
#![allow(non_camel_case_types, internal_features)]

extern "C" {
    fn printk(fmt: *const u8, ...) -> i32;
}

#[no_mangle]
pub extern "C" fn testhook(fn_name: *const u8, fn_hook: extern "C" fn()) -> u64 {
    unsafe {
        printk(b"Hooking function:".as_ptr());
    }
    5
}


