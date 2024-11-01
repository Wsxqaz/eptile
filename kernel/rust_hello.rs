// SPDX-License-Identifier: GPL-2.0
#![allow(unreachable_pub)]
#![allow(warnings)]

use alloc::boxed::Box;
use core::arch::asm;
use core::ffi::*;
use core::mem::MaybeUninit;
use kernel::print::call_printk;

use kernel::prelude::*;
mod bindings_generated;
mod bindings_helpers_generated;
use bindings_generated::*;
use bindings_helpers_generated::*;

mod hook;
mod hook_bindings;
use hook::*;
use hook_bindings::*;

module! {
    type: RustHello,
    name: "rust_hello",
    author: "Rust for Linux Contributors",
    description: "Rust minimal sample",
    license: "GPL",
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
    pub module: *const bindings_generated::module,
    pub list: bindings_generated::list_head,
}

#[no_mangle]
extern "C" {
    fn _printk(s: *const c_char, ...) -> c_int;
    fn stop_machine(
        _fn: fn(arg: *mut c_void) -> c_int,
        data: *mut c_void,
        cpus: *mut bindings_generated::cpumask,
    ) -> c_int;
    fn smp_call_function_single(
        cpu: c_int,
        _fn: fn(data: *mut c_void),
        info: *mut c_void,
        wait: c_int,
    ) -> c_int;
    fn idr_find(idr: *const bindings_generated::idr, id: c_long) -> *mut c_void;

    fn filp_open(
        filename: *const u8,
        flags: u32,
        mode: bindings_generated::umode_t,
    ) -> *mut bindings_generated::file;

    fn filp_close(filp: *mut bindings_generated::file, id: bindings_generated::fl_owner_t)
        -> c_int;

    fn kernel_read(
        file: *mut bindings_generated::file,
        buf: *mut u8,
        count: core::ffi::c_ulong,
        pos: *mut usize,
    ) -> c_int;

    fn rw_verify_area(
        read: c_int,
        addr: *const bindings_generated::file,
        ppos: *mut usize,
        size: core::ffi::c_ulong,
    ) -> c_int;

    static __per_cpu_offset: *const usize;
    static pcpu_hot: bindings_generated::pcpu_hot;

}

fn read_kallsyms(fn_: *const u8) -> *const u8 {
    let mut kallsyms_path: &str = "/proc/kallsyms\0";

    unsafe {
        let file = filp_open(
            kallsyms_path.as_ptr(),
            bindings_generated::O_RDONLY,
            u16::MAX as bindings_generated::umode_t,
        );

        _printk("[rust_hello] file: %px\n".as_ptr() as *const i8, file);
        _printk(
            "[rust_hello] file->f_mode: %d\n".as_ptr() as *const i8,
            (*file).f_mode,
        );
        _printk(
            "[rust_hello] file->f_op: %px\n".as_ptr() as *const i8,
            (*file).f_op,
        );
        _printk(
            "[rust_hello] file->f_op->read: %px\n".as_ptr() as *const i8,
            (*(*file).f_op).read,
        );
        _printk(
            "[rust_hello] file->f_op->read_iter: %px\n".as_ptr() as *const i8,
            (*(*file).f_op).read_iter,
        );

        let mut buf = [0u8; 128];
        let mut pos = 8;

        _printk(
            "[rust_hello] buf: %px\n".as_ptr() as *const i8,
            buf.as_mut_ptr(),
        );

        let verify = rw_verify_area(0, file, &mut pos, 8);
        _printk("[rust_hello] verify: %d\n".as_ptr() as *const i8, verify);

        // let read = core::mem::transmute::<_, unsafe extern "C" fn(*mut bindings_generated::file, *mut i8, usize, *mut i64) -> isize>(
        //     (*(*file).f_op).read
        // )(file, buf.as_mut_ptr() as _, 1, &mut pos);
        let read = kernel_read(file, buf.as_mut_ptr(), 1, &mut pos);
        _printk("[rust_hello] read: %d\n".as_ptr() as *const i8, read);

        // _printk("[rust_hello] buf: %s\n".as_ptr() as *const i8, buf);
        for i in 0..10 {
            _printk(
                "[rust_hello] buf[%d]: %c\n".as_ptr() as *const i8,
                i,
                buf[i] as c_int,
            );
        }

        let _ = filp_close(file, core::ptr::null_mut());

        core::mem::transmute(0usize)
    }
}

fn load_ftrace(data: *mut c_void) {
    unsafe {
        let mut ftrace_events: *mut bindings_generated::list_head =
            core::mem::transmute(0xffffffff90802f70u64);
        let mut _f: *const bindings_generated::trace_event_call = container_of!(
            (*ftrace_events).next,
            bindings_generated::trace_event_call,
            list
        );

        _printk("[rust_hello] _f: %px\n".as_ptr() as *const i8, _f);
        _printk(
            "[rust_hello] _f.event.type: %llu\n".as_ptr() as *const i8,
            (*_f).event.type_,
        );
        _printk(
            "[rust_hello] _f.class: %px\n".as_ptr() as *const i8,
            (*_f).class,
        );
        _printk(
            "[rust_hello] _f.class.reg: %px\n".as_ptr() as *const i8,
            (*(*_f).class).reg,
        );
        _printk(
            "[rust_hello] _f.class.system: %s\n".as_ptr() as *const i8,
            (*(*_f).class).system,
        );

        while (*_f).list.next != ftrace_events {
            _printk(
                "[rust_hello] _f.event.type: %llu\n".as_ptr() as *const i8,
                (*_f).event.type_,
            );
            _printk(
                "[rust_hello] _f.class: %px\n".as_ptr() as *const i8,
                (*_f).class,
            );
            _printk(
                "[rust_hello] _f.class.reg: %px\n".as_ptr() as *const i8,
                (*(*_f).class).reg,
            );
            _printk(
                "[rust_hello] _f.class.system: %s\n".as_ptr() as *const i8,
                (*(*_f).class).system,
            );
            _f = container_of!((*_f).list.next, bindings_generated::trace_event_call, list);
        }
    }
}

fn print_info(data: *mut c_void) {
    unsafe {
        let cpu_number: i32;
        asm!("mov eax, dword ptr GS:[0x3434c]", out("eax") cpu_number);
        _printk(
            "[rust_hello] cpu_number: %d\n".as_ptr() as *const i8,
            cpu_number,
        );

        let this_cpu_off_: usize;
        asm!("mov rax, qword ptr GS:[0x19a20]", out("rax") this_cpu_off_);
        _printk(
            "[rust_hello] this_cpu_off: %px\n".as_ptr() as *const i8,
            this_cpu_off_,
        );

        let mut cpuctx: *mut perf_cpu_context = 0x2fd20usize.wrapping_add(this_cpu_off_) as _;
        _printk("[rust_hello] cpuctx: %px\n".as_ptr() as *const i8, cpuctx);

        _printk(
            "[rust_hello] (*cpuctx).task: %px\n".as_ptr() as *const i8,
            (*cpuctx).ctx.task,
        );

        let mut taskctx: *mut bindings_generated::perf_event_context = (*cpuctx).task_ctx;
        _printk("[rust_hello] taskctx: %px\n".as_ptr() as *const i8, taskctx);

        let pmu_idr: *const bindings_generated::idr = 0xffffffffb12a8c90usize as _;
        let tracepoint_pmu: *const pmu =
            idr_find(pmu_idr, perf_type_id_PERF_TYPE_TRACEPOINT.into()) as _;
        _printk(
            "[rust_hello] tracepoint_pmu: %px\n".as_ptr() as *const i8,
            tracepoint_pmu,
        );

        let cpc: *const perf_cpu_pmu_context =
            this_cpu_off_.wrapping_add((*tracepoint_pmu).cpu_pmu_context as _) as _;
        _printk("[rust_hello] cpc: %px\n".as_ptr() as *const i8, cpc);
        let pmu_ctx: *const perf_event_pmu_context = &(*cpc).epc;
        _printk("[rust_hello] pmu_ctx: %px\n".as_ptr() as *const i8, pmu_ctx);

        let event_heap: min_heap = min_heap {
            data: (*cpuctx).heap as _,
            nr: 0,
            size: (*cpuctx).heap_size,
        };

        // let evt: *const *const perf_event = core::mem::transmute( event_heap.data );
    }
}

fn stub() {
    unsafe {
        asm!(".rept 0x80", ".byte 0", ".endr");
    }
}

fn _foobar() -> c_int {
    unsafe {
        _printk("original function\n".as_ptr() as *const i8);
    }
    0
}

fn _hook() -> c_int {
    unsafe {
        _printk("hooked function\n".as_ptr() as *const i8);
        core::mem::transmute::<fn(), fn() -> i32>(stub)()
    }
}

fn lde_get_length(target: *mut c_void) -> i32 {
    unsafe {
        let mut insn_init: extern "C" fn(*mut insn, *mut c_void, i32, i32) -> c_int =
            core::mem::transmute(0xffffffff85db0810usize);
        let mut insn_get_length: extern "C" fn(*mut insn) -> c_int =
            core::mem::transmute(0xffffffff85db1680usize);

        let mut insn: insn = core::mem::zeroed();

        insn_init(&mut insn, target, 64, 0);
        insn_get_length(&mut insn)
    }
}

fn x86_put_jmp(loc: *mut u8, target: *mut u8) {
    unsafe {
        let mut offset = target.wrapping_sub(loc as usize).wrapping_sub(5);
        core::ptr::write(loc as *mut u8, 0xE9);
        core::ptr::write(loc.wrapping_add(1) as *mut i32, offset as i32);
    }
}

// smp_call_function_single(0, print_info, core::ptr::null_mut(), 1);
// smp_call_function_single(0, load_ftrace, core::ptr::null_mut(), 1);
fn _run(_blob: *mut c_void) -> c_int {
    unsafe {
        let r = read_kallsyms(core::ptr::null());

        // let mut len: i32 = lde_get_length(_foobar as *mut c_void);
        // while len < 5 {
        //     _printk("[rust_hello] len: %d\n".as_ptr() as *const i8, len);
        //     len.wrapping_add(lde_get_length((_foobar as *mut c_void).wrapping_add(len as usize)));
        // }

        // core::ptr::copy(_foobar as *const u8, stub as *mut u8, len as usize);
        // x86_put_jmp(
        //     (_foobar as *mut u8).wrapping_add(len as usize),
        //     (stub as *mut u8).wrapping_add(len as usize),
        // );
        // x86_put_jmp(
        //     (stub as *mut u8).wrapping_add(len as usize),
        //     (_foobar as *mut u8).wrapping_add(len as usize),
        // );

        // .fn = hook function = _hook
        // .target.name = name of function to hook = _foobar
        // .orig = copy of n bytes (5 + insn size) =
        //      this should be the top n (n >= 5) bytes of foobar
        //      we need to use at least 5 bytes, so we can insert
        //      a jump instruction to the location we want to the
        //      function we want to jump to, i.e. _hook
        // .stub = KHOOK_STUB_hook_noref copy
        //      what is the purpose of stub? in the khook code,
        //      stub is a wrapper around a jump to our hook function
        //      we require the wrapper to handle the case when there are
        //      more than 8 args being passed to the function, since some part
        //      of the ABI requires distinct handling of that case by putting
        //      the args on the stack or something like that
        //      since we're just playing with this stuff, and it doesn't need
        //      to be super generic yet, we can  probably ignore the stub
        //      function, if we ignore the stub function then that means that
        //      we want to insert a jump directly to our hook function at the
        //      start of target
        //
        //      how do we decide that we want to call the original function?
        //      khook achieves this by generating a function for each hook
        //      that it uses as a place to copy the top N bytes of the target
        //      function into, currently we're just copying that stuff into
        //      some heap allocated array, we can transmute and call that
        //      array as a function, so just ensure that you place a jump
        //      back to the original target function at the end of the array
        // _foobar();
    }
    return 0;
}

impl kernel::Module for RustHello {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe {
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
        _printk(
            "[rust_hello] _bpf_trace_modules_next: %px\n".as_ptr() as *const i8,
            _bpf_trace_modules_next,
        );
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
