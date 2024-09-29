// SPDX-License-Identifier: GPL-2.0
#![allow(unreachable_pub)]
#![allow(warnings)]

//! Rust hello.

use core::ffi::*;
use kernel::prelude::*;
use kernel::print::call_printk;

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
    pub module: *const module,
    pub list: list_head
}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {
            let _printk: unsafe extern "C" fn(*const c_char, ...) -> c_int = core::mem::transmute(0xffffffff8b3b03b0 as usize);
            // _printk("[rust_hello] console_printkool %d\n".as_ptr() as *const i8, 42u32);

            let _bpf_trace_modules_next: *const u8 = core::mem::transmute(0xffffffff8d808140 as usize);
            // _printk("[rust_hello] _bpf_trace_modules_next: %px\n".as_ptr() as *const i8, _bpf_trace_modules_next);
            let mut btm: *const bpf_trace_module = container_of!(_bpf_trace_modules_next, bpf_trace_module, list);
            let mut l = 0;
            let mut seen = [0 as *const bpf_trace_module; 100];
            // _printk("[rust_hello] start btm = %px\n".as_ptr() as *const i8, btm);
            while btm != 0 as *const bpf_trace_module {
                let mut buf = [2u8; 128];
                let mut pfx = "[rust_hello] btm->module->name: ".as_bytes();
                for i in 0..pfx.len() {
                    buf[i] = pfx[i as usize];
                }
                for i in 0..56 {
                    buf[i as usize + pfx.len() as usize] = (*(*btm).module).name[i] as u8;
                }
                _printk(buf.as_ptr() as *const i8);
                let num_bpf_raw_events = (*(*btm).module).num_bpf_raw_events;
                _printk("[rust_hello] btm->module->num_bpf_raw_events: %u\n".as_ptr() as *const i8, num_bpf_raw_events);
                if (num_bpf_raw_events > 200) {
                    _printk("[rust_hello] skipping invalid event\n".as_ptr() as *const i8);
                    btm = container_of!((*btm).list.next, bpf_trace_module, list);
                    continue;
                }

                let mut bpf_raw_event_map: *mut bpf_raw_event_map = (*(*btm).module).bpf_raw_events;
                for i in 1..num_bpf_raw_events {
                    if bpf_raw_event_map == core::ptr::null_mut() { continue; }

                    let tp: *mut tracepoint = (*bpf_raw_event_map).tp;
                    if tp == core::ptr::null_mut() { continue; }

                    let mut buff = [2u8; 128];
                    let mut pfxx = "[rust_hello] tp->name: ".as_bytes();
                    for j in 0..pfxx.len() {
                        buff[j] = pfxx[j as usize];
                    }
                    let mut cc = (*tp).name;
                    let mut ci = 0;
                    while *cc != 0i8 {
                        buff[ci + pfxx.len()] = *cc as u8;
                        ci = ci + 1;
                        cc = cc.add(1);
                        if (pfxx.len() + ci > buff.len() - 1) { break; }
                    }
                    _printk(buff.as_ptr() as *const i8);
                }


                btm = container_of!((*btm).list.next, bpf_trace_module, list);
                //  _printk("[rust_hello] next btm = %px\n".as_ptr() as *const i8, btm);
                l = l + 1;
                if l > 10 { break; }
            }
        }

        Ok(RustHello {})
    }
}

impl Drop for RustHello {
    fn drop(&mut self) {
        // pr_info!("Hello exit!\n");
    }
}
