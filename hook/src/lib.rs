#![no_main]
#![no_std]
#![feature(lang_items)]
#![allow(non_camel_case_types, internal_features)]

use core::ffi::*;

#[no_mangle]
extern "C" {
    fn _printk(s: *const c_char, ...) -> c_int;
}


fn lde_get_length(target: *mut c_void) -> usize {
    0
}

fn x86_put_jmp(loc: *mut c_void, target: *mut c_void) {
    unsafe {
        let mut offset = target.wrapping_sub(loc as usize).wrapping_sub(5);
        core::ptr::write(loc as *mut u8, 0xE9);
        core::ptr::write(loc.wrapping_add(1) as *mut i32, offset as i32);
    }
}

struct Hook {
    target: *mut c_void,
    replacement: *mut c_void,
    clone: *mut c_void,
    original: *mut c_void,
}

fn hook_fn(target: *mut c_void, replacement: *mut c_void, clone: *mut c_void) -> Hook {
    unsafe {
        let mut length = lde_get_length(target);
        _printk("length: %d".as_ptr() as *const i8, length);
        while length < 5 {
            length += lde_get_length(target.wrapping_add(length));
        }
        _printk("length: %d".as_ptr() as *const i8, length);


        _printk("backing up %d bytes from target (%px) to clone (%px)\n".as_ptr() as *const i8, length, target, clone);
        core::ptr::copy_nonoverlapping(target, clone, length);
        _printk("hooking target (%px) to replacement (%px)\n".as_ptr() as *const i8, target, replacement);
        x86_put_jmp(target, replacement);

        Hook {
            target,
            replacement,
            clone,
            original: target.wrapping_add(length),
        }
    }
}

