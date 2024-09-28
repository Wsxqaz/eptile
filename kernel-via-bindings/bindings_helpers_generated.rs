/* automatically generated by rust-bindgen 0.65.1 */
use crate::*;

extern "C" {
    #[link_name="rust_helper_BUG"]
    pub fn BUG() -> !;
}
extern "C" {
    #[link_name="rust_helper_mutex_lock"]
    pub fn mutex_lock(lock: *mut mutex);
}
extern "C" {
    #[link_name="rust_helper___spin_lock_init"]
    pub fn __spin_lock_init(
        lock: *mut spinlock_t,
        name: *const core::ffi::c_char,
        key: *mut lock_class_key,
    );
}
extern "C" {
    #[link_name="rust_helper_spin_lock"]
    pub fn spin_lock(lock: *mut spinlock_t);
}
extern "C" {
    #[link_name="rust_helper_spin_unlock"]
    pub fn spin_unlock(lock: *mut spinlock_t);
}
extern "C" {
    #[link_name="rust_helper_init_wait"]
    pub fn init_wait(wq_entry: *mut wait_queue_entry);
}
extern "C" {
    #[link_name="rust_helper_signal_pending"]
    pub fn signal_pending(t: *mut task_struct) -> core::ffi::c_int;
}
extern "C" {
    #[link_name="rust_helper_REFCOUNT_INIT"]
    pub fn REFCOUNT_INIT(n: core::ffi::c_int) -> refcount_t;
}
extern "C" {
    #[link_name="rust_helper_refcount_inc"]
    pub fn refcount_inc(r: *mut refcount_t);
}
extern "C" {
    #[link_name="rust_helper_refcount_dec_and_test"]
    pub fn refcount_dec_and_test(r: *mut refcount_t) -> bool_;
}
extern "C" {
    #[link_name="rust_helper_ERR_PTR"]
    pub fn ERR_PTR(err: core::ffi::c_long) -> *mut core::ffi::c_void;
}
extern "C" {
    #[link_name="rust_helper_IS_ERR"]
    pub fn IS_ERR(ptr: *const core::ffi::c_void) -> bool_;
}
extern "C" {
    #[link_name="rust_helper_PTR_ERR"]
    pub fn PTR_ERR(ptr: *const core::ffi::c_void) -> core::ffi::c_long;
}
extern "C" {
    #[link_name="rust_helper_errname"]
    pub fn errname(err: core::ffi::c_int) -> *const core::ffi::c_char;
}
extern "C" {
    #[link_name="rust_helper_get_current"]
    pub fn get_current() -> *mut task_struct;
}
extern "C" {
    #[link_name="rust_helper_get_task_struct"]
    pub fn get_task_struct(t: *mut task_struct);
}
extern "C" {
    #[link_name="rust_helper_put_task_struct"]
    pub fn put_task_struct(t: *mut task_struct);
}
extern "C" {
    #[link_name="rust_helper_kunit_get_current_test"]
    pub fn kunit_get_current_test() -> *mut kunit;
}
extern "C" {
    #[link_name="rust_helper_init_work_with_key"]
    pub fn init_work_with_key(
        work: *mut work_struct,
        func: work_func_t,
        onstack: bool_,
        name: *const core::ffi::c_char,
        key: *mut lock_class_key,
    );
}
extern "C" {
    #[link_name="rust_helper_krealloc"]
    pub fn krealloc(
        objp: *const core::ffi::c_void,
        new_size: usize,
        flags: gfp_t,
    ) -> *mut core::ffi::c_void;
}
