#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

typedef int (*remote_function_f)(void *);

struct remote_function_call {
  struct task_struct  *p;
  remote_function_f   func;
  void                *info;
  int                 ret;
};


static void remote_function(void *data)
{
  struct remote_function_call *tfc = data;
  struct task_struct *p = tfc->p;

  if (p) {
    /* -EAGAIN */
    if (task_cpu(p) != smp_processor_id())
      return;

    /*
     * Now that we're on right CPU with IRQs disabled, we can test
     * if we hit the right task without races.
     */

    tfc->ret = -ESRCH; /* No such (running) process */
    if (p != current)
      return;
  }

  tfc->ret = tfc->func(tfc->info);
}


int test_func(void *blob) {
    printk(KERN_INFO "Hello, world!\n");
    int cpu = get_cpu();
    printk(KERN_INFO "[rust_hello] CPU: %d\n", cpu);
    struct perf_cpu_context *cpuctx = this_cpu_ptr((void *)0x2fd20);
    printk(KERN_INFO "[rust_hello] cpuctx: %px\n", cpuctx);
    void * off = (void *)this_cpu_read(this_cpu_off);
    printk(KERN_INFO "[rust_hello] this_cpu_off: %px\n", off);
    return 0;
}

int driver_entry(void)
{
    printk(KERN_INFO "Hello, world!\n");
    int cpu = get_cpu();
    printk(KERN_INFO "[rust_hello] CPU: %d\n", cpu);
    struct perf_cpu_context *cpuctx = this_cpu_ptr((void *)0x2fd20);
    printk(KERN_INFO "[rust_hello] cpuctx: %px\n", cpuctx);
    void * off = (void *)this_cpu_read(this_cpu_off);
    printk(KERN_INFO "[rust_hello] this_cpu_off: %px\n", off);

    struct remote_function_call data = {
      .p  = NULL,
      .func = test_func,
      .info = NULL,
      .ret  = -ENXIO, /* No such CPU */
    };

    smp_call_function_single(0, remote_function, &data, 1);

    return 0;
}

void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
