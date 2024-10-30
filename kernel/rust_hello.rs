// SPDX-License-Identifier: GPL-2.0
#![allow(unreachable_pub)]
#![allow(warnings)]

use core::arch::asm;
use core::ffi::*;
use core::mem::MaybeUninit;
use ::alloc::boxed::Box;
use kernel::print::call_printk;


use kernel::prelude::*;
mod bindings_generated;
mod bindings_helpers_generated;
use bindings_generated::*;
use bindings_helpers_generated::*;

mod hook;
mod hook_bindings;
use hook::*;

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
    fn idr_find(
        idr: *const idr,
        id: c_long
    ) -> *mut c_void;

    static __per_cpu_offset: *const usize;
    static pcpu_hot: pcpu_hot;

}

fn load_ftrace(data: *mut c_void) {
    unsafe {
        let mut ftrace_events: *mut list_head = core::mem::transmute(0xffffffff90802f70u64);
        let mut _f: *const trace_event_call = container_of!((*ftrace_events).next, trace_event_call, list);

        _printk("[rust_hello] _f: %px\n".as_ptr() as *const i8, _f);
        _printk("[rust_hello] _f.event.type: %llu\n".as_ptr() as *const i8, (*_f).event.type_);
        _printk("[rust_hello] _f.class: %px\n".as_ptr() as *const i8, (*_f).class);
        _printk("[rust_hello] _f.class.reg: %px\n".as_ptr() as *const i8, (*(*_f).class).reg);
        _printk("[rust_hello] _f.class.system: %s\n".as_ptr() as *const i8, (*(*_f).class).system);

        while (*_f).list.next != ftrace_events {
            _printk("[rust_hello] _f.event.type: %llu\n".as_ptr() as *const i8, (*_f).event.type_);
            _printk("[rust_hello] _f.class: %px\n".as_ptr() as *const i8, (*_f).class);
            _printk("[rust_hello] _f.class.reg: %px\n".as_ptr() as *const i8, (*(*_f).class).reg);
            _printk("[rust_hello] _f.class.system: %s\n".as_ptr() as *const i8, (*(*_f).class).system);
            _f = container_of!((*_f).list.next, trace_event_call, list);
        }

    }
}

fn print_info(data: *mut c_void) {
    unsafe {
        let cpu_number: i32;
        asm!("mov eax, dword ptr GS:[0x3434c]", out("eax") cpu_number);
        _printk("[rust_hello] cpu_number: %d\n".as_ptr() as *const i8, cpu_number);

        let this_cpu_off_: usize;
        asm!("mov rax, qword ptr GS:[0x19a20]", out("rax") this_cpu_off_);
        _printk("[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8, this_cpu_off_);

        let mut cpuctx: *mut perf_cpu_context = 0x2fd20usize.wrapping_add(this_cpu_off_) as _;
        _printk("[rust_hello] cpuctx: %px\n".as_ptr() as *const i8, cpuctx);

        _printk("[rust_hello] (*cpuctx).task: %px\n".as_ptr() as *const i8, (*cpuctx).ctx.task);

        let mut taskctx: *mut perf_event_context = (*cpuctx).task_ctx;
        _printk("[rust_hello] taskctx: %px\n".as_ptr() as *const i8, taskctx);

        let pmu_idr: *const idr = 0xffffffffb12a8c90usize as _;
        let tracepoint_pmu: *const pmu = idr_find(pmu_idr, perf_type_id_PERF_TYPE_TRACEPOINT.into()) as _;
        _printk("[rust_hello] tracepoint_pmu: %px\n".as_ptr() as *const i8, tracepoint_pmu);

        let cpc: *const perf_cpu_pmu_context = this_cpu_off_.wrapping_add( ( *tracepoint_pmu ).cpu_pmu_context  as _) as _;
        _printk("[rust_hello] cpc: %px\n".as_ptr() as *const i8, cpc);
        let pmu_ctx: *const perf_event_pmu_context = &(*cpc).epc;
        _printk("[rust_hello] pmu_ctx: %px\n".as_ptr() as *const i8, pmu_ctx);

        let event_heap: min_heap = min_heap {
            data: (*cpuctx).heap as _,
            nr: 0,
            size: (*cpuctx).heap_size
        };

        // let evt: *const *const perf_event = core::mem::transmute( event_heap.data );

    }
}

fn _run(_blob: *mut c_void) -> c_int {
    unsafe {
        // smp_call_function_single(0, print_info, core::ptr::null_mut(), 1);
        smp_call_function_single(0, load_ftrace, core::ptr::null_mut(), 1);

        let i: Box<u32> = Box::try_new(5).unwrap();

        // let hook: Hook = hook_fn(
        //     _printk as *mut c_void,
        //     _run as *mut c_void,
        // );
    }
    return 0;
}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {
            // let this_cpu_off_: usize;
            // unsafe {
            //     asm!("mov rax, qword ptr GS:[0x19a20]", out("rax") this_cpu_off_)
            // };
            // _printk("[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8, this_cpu_off_);

            // let mut cpuctx: *mut perf_cpu_context = 0x2fd20_usize.wrapping_add(this_cpu_off_) as _;
            // _printk("[rust_hello] cpuctx: %px\n".as_ptr() as *const i8, cpuctx);

            // let cpu_number: i32;
            // unsafe {
            //     asm!("mov eax, dword ptr GS:[0x3434c]", out("eax") cpu_number)
            // };
            // _printk("[rust_hello] cpu_number: %d\n".as_ptr() as *const i8, cpu_number);

            // bpf_get_raw_tracepoint_module();

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
        let _bpf_trace_modules_next: *const u8 = core::mem::transmute(0xffffffffb0a08140 as usize);
        _printk("[rust_hello] _bpf_trace_modules_next: %px\n".as_ptr() as *const i8, _bpf_trace_modules_next);
        // let mut btm: *const bpf_trace_module =
        //     container_of!(_bpf_trace_modules_next, bpf_trace_module, list);
        // let mut l = 0;
        // let mut seen = [0 as *const bpf_trace_module; 100];
        // // _printk("[rust_hello] start btm = %px\n".as_ptr() as *const i8, btm);
        // let mut btp: *const bpf_raw_event_map = core::mem::transmute(0xffffffffb0c3bec0 as usize);
        // let mut end: *const bpf_raw_event_map = core::mem::transmute(0xffffffffb0c434c0 as usize);
        // while btp < end {
        //     let tp: *mut tracepoint = (*btp).tp;
        //     if tp == core::ptr::null_mut() {
        //         continue;
        //     }

        //     let mut buff = [0u8; 128];
        //     let mut pfxx = "[rust_hello] btp->tp->name: ".as_bytes();
        //     for j in 0..pfxx.len() {
        //         buff[j] = pfxx[j as usize];
        //     }
        //     let mut cc = (*tp).name;
        //     let mut ci = 0;
        //     while *cc != 0i8 {
        //         buff[ci + pfxx.len()] = *cc as u8;
        //         ci = ci + 1;
        //         cc = cc.add(1);
        //         if (pfxx.len() + ci > buff.len() - 1) {
        //             break;
        //         }
        //     }
        //     _printk(buff.as_ptr() as *const i8);

        //     let mut sys_enter = true;
        //     let reff = "sys_enter".as_bytes();
        //     for k in 0..9 {
        //         if (buff[pfxx.len() + k] == reff[k]) {
        //             continue;
        //         } else {
        //             sys_enter = false;
        //             break;
        //         }
        //     }

        //     if sys_enter {
        //         _printk("[rust_hello] sys_enter found...\n".as_ptr() as *const i8);
        //         let bpf_func = (*btp).bpf_func;
        //         _printk(
        //             "[rust_hello] tp->bpf_func: %px\n".as_ptr() as *const i8,
        //             bpf_func,
        //         );
        //     }

        //     btp = btp.add(1);
        // }
    }
}
