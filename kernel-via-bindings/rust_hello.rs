// SPDX-License-Identifier: GPL-2.0
#![allow(unreachable_pub)]
#![allow(warnings)]

//! Rust hello.

use core::ffi::*;
use kernel::prelude::*;

mod bindings_generated;
mod bindings_helpers_generated;
use bindings_generated::*;
use bindings_helpers_generated::*;


module! {
    type: RustHello,
    name: "rust_hello",
    author: "Rust for Linux Contributors",
    description: "Rust minimal sample",
    license: "GPL",
}


fn read_kallsyms() -> &'static str {
    let kallsyms_path = "/proc/kallsyms";

    "hello".as_ref()
}

struct RustHello {}

/// Copy from linux kernel master, not present in v6.8
/// Produces a pointer to an object from a pointer to one of its fields.
///
/// # Safety
///
/// The pointer passed to this macro, and the pointer returned by this macro, must both be in
/// bounds of the same allocation.
///
/// # Examples
///
/// ```
/// # use kernel::container_of;
/// struct Test {
///     a: u64,
///     b: u32,
/// }
///
/// let test = Test { a: 10, b: 20 };
/// let b_ptr = &test.b;
/// // SAFETY: The pointer points at the `b` field of a `Test`, so the resulting pointer will be
/// // in-bounds of the same allocation as `b_ptr`.
/// let test_alias = unsafe { container_of!(b_ptr, Test, b) };
/// assert!(core::ptr::eq(&test, test_alias));
/// ```
#[macro_export]
macro_rules! container_of {
    ($ptr:expr, $type:ty, $($f:tt)*) => {{
        let ptr = $ptr as *const _ as *const u8;
        let offset: usize = ::core::mem::offset_of!($type, $($f)*);
        ptr.sub(offset) as *const $type
    }}
}


#[repr(C)]
#[repr(align(64))]
pub struct bpf_trace_module {
    pub module: module,
    pub list: list_head
}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {
            let _printk: unsafe extern "C" fn(*const c_char, ...) -> c_int = core::mem::transmute(0xffffffff937b03b0 as usize);
            _printk("[rust_hello] console_printkool %d\n".as_ptr() as *const i8, 42u32);
            let _bpf_trace_modules: list_head = core::mem::transmute(0xffffffff95c08140 as u128);
            let head_module: *const bpf_trace_module = container_of!(_bpf_trace_modules.next, bpf_trace_module, list);
            _printk("[rust_hello] module name = %s\n".as_ptr() as *const i8, (*head_module).module.name);
        }

        Ok(RustHello {})
    }
}

impl Drop for RustHello {
    fn drop(&mut self) {
        // pr_info!("Hello exit!\n");
    }
}
