// SPDX-License-Identifier: GPL-2.0
#![allow(unreachable_pub)]
#![allow(warnings)]

use core::arch::asm;
use core::ffi::*;
use core::*;
use core::mem::MaybeUninit;
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
    pub list: list_head,
}

#[no_mangle]
extern "C" {
    fn _printk(s: *const c_char, ...) -> c_int;
    fn stop_machine(
        _fn: fn(arg: *mut c_void) -> c_int,
        data: *mut c_void,
        cpus: *mut cpumask
    ) -> c_int;
    fn smp_call_function_single(
        cpu: c_int,
        _fn: fn(data: *mut c_void),
        info: *mut c_void,
        wait: c_int
    ) -> c_int;

    static __per_cpu_offset: usize;
    static pcpu_hot: pcpu_hot;
}

fn print_info(data: *mut c_void) {
    unsafe {
        let cpu_number: i32;
        unsafe {
            asm!("mov eax, dword ptr GS:[0x3434c]", out("eax") cpu_number)
        };
        _printk("[rust_hello] cpu_number: %d\n".as_ptr() as *const i8, cpu_number);

        let this_cpu_off_: usize;
        unsafe {
            asm!("mov rax, qword ptr GS:[0x19a20]", out("rax") this_cpu_off_)
        };
        _printk("[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8, this_cpu_off_);

        let mut cpuctx: *mut perf_cpu_context = 0x2fd20usize.wrapping_add(this_cpu_off_) as _;
        _printk("[rust_hello] cpuctx: %px\n".as_ptr() as *const i8, cpuctx);

        let mut taskctx: *mut perf_event_context = (*cpuctx).task_ctx;
        _printk("[rust_hello] taskctx: %px\n".as_ptr() as *const i8, taskctx);

    }
}

fn _run(_blob: *mut c_void) -> c_int {
    unsafe {
        smp_call_function_single(0, print_info, core::ptr::null_mut(), 1);
    }
    return 0;
}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {

            // let pmu_idr: *mut idr = core::mem::transmute(0xffffffffa48a8c90usize);
            // _printk("[rust_hello] pmu_idr.idr_base: %u\n".as_ptr() as *const i8, (* pmu_idr ).idr_base);
            // _printk("[rust_hello] pmu_idr.idr_next: %u\n".as_ptr() as *const i8, (* pmu_idr ).idr_next);
            // _printk(
            //     "[rust_hello] pmu_idr.idr_rt.xa_lock.rlock.raw_lock.__bindgen_anon_1.val: %d\n".as_ptr() as *const i8,
            //     (* pmu_idr ).idr_rt.xa_lock.rlock.raw_lock.__bindgen_anon_1.val.counter
            // );
            // let pmu: *mut pmu = idr_find(pmu_idr, perf_type_id_PERF_TYPE_TRACEPOINT.into()) as *mut _;
            // _printk("[rust_hello] pmu: %px\n".as_ptr() as *const i8, pmu);

            // let perf_cpu_context: usize = 0x000000000002fd20;
            // _printk(
            //     "[rust_hello] perf_cpu_context: %px\n".as_ptr() as *const i8,
            //     perf_cpu_context
            // );
            // _printk(
            //     "[rust_hello] __per_cpu_offset: %px\n".as_ptr() as *const i8,
            //     __per_cpu_offset
            // );
            // let mut t: *const usize = __per_cpu_offset as _;
            // for i in 1..8192 {
            //     if (!(*t == 0usize || *t == 0xffffffffffffffffusize)) {
            //         _printk(
            //             "[rust_hello] t: %px\n".as_ptr() as *const i8,
            //             *t
            //         );
            //     }
            //     t = t.add(1);
            // }

            // let this_cpu_off: usize = 0x0000000000019a20;
            // _printk(
            //     "[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8,
            //     this_cpu_off
            // );

            // let cpuctx: *const perf_cpu_context = perf_cpu_context.wrapping_add(__per_cpu_offset) as _;
            // _printk(
            //     "[rust_hello] cpuctx: %px\n".as_ptr() as *const i8,
            //     cpuctx
            // );

            let this_cpu_off_: usize;
            unsafe {
                asm!("mov rax, qword ptr GS:[0x19a20]", out("rax") this_cpu_off_)
            };
            _printk("[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8, this_cpu_off_);

            let mut cpuctx: *mut perf_cpu_context = 0x2fd20_usize.wrapping_add(this_cpu_off_) as _;
            _printk("[rust_hello] cpuctx: %px\n".as_ptr() as *const i8, cpuctx);

            let cpu_number: i32;
            unsafe {
                asm!("mov eax, dword ptr GS:[0x3434c]", out("eax") cpu_number)
            };
            _printk("[rust_hello] cpu_number: %d\n".as_ptr() as *const i8, cpu_number);

            stop_machine(_run, core::ptr::null_mut(), core::ptr::null_mut());
        }

        Ok(RustHello {})
    }
}

impl Drop for RustHello {
    fn drop(&mut self) {
        // pr_info!("Hello exit!\n");
    }
}

fn bpf_get_raw_tracepoint_module() {
    unsafe {
        let _bpf_trace_modules_next: *const u8 = core::mem::transmute(0xffffffff86e08140 as usize);
        // _printk("[rust_hello] _bpf_trace_modules_next: %px\n".as_ptr() as *const i8, _bpf_trace_modules_next);
        let mut btm: *const bpf_trace_module =
            container_of!(_bpf_trace_modules_next, bpf_trace_module, list);
        let mut l = 0;
        let mut seen = [0 as *const bpf_trace_module; 100];
        // _printk("[rust_hello] start btm = %px\n".as_ptr() as *const i8, btm);
        let mut btp: *const bpf_raw_event_map = core::mem::transmute(0xffffffff8703bec0 as usize);
        let mut end: *const bpf_raw_event_map = core::mem::transmute(0xffffffff870434c0 as usize);
        while btp < end {
            let tp: *mut tracepoint = (*btp).tp;
            if tp == core::ptr::null_mut() {
                continue;
            }

            let mut buff = [0u8; 128];
            let mut pfxx = "[rust_hello] btp->tp->name: ".as_bytes();
            for j in 0..pfxx.len() {
                buff[j] = pfxx[j as usize];
            }
            let mut cc = (*tp).name;
            let mut ci = 0;
            while *cc != 0i8 {
                buff[ci + pfxx.len()] = *cc as u8;
                ci = ci + 1;
                cc = cc.add(1);
                if (pfxx.len() + ci > buff.len() - 1) {
                    break;
                }
            }
            _printk(buff.as_ptr() as *const i8);

            let mut sys_enter = true;
            let reff = "sys_enter".as_bytes();
            for k in 0..9 {
                if (buff[pfxx.len() + k] == reff[k]) {
                    continue;
                } else {
                    sys_enter = false;
                    break;
                }
            }

            if sys_enter {
                _printk("[rust_hello] sys_enter found...\n".as_ptr() as *const i8);
                let bpf_func = (*btp).bpf_func;
                _printk(
                    "[rust_hello] tp->bpf_func: %px\n".as_ptr() as *const i8,
                    bpf_func,
                );
            }

            btp = btp.add(1);
        }
    }
}
