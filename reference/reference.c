#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int driver_entry(void)
{
    printk(KERN_INFO "Hello, world!\n");
    int cpu = get_cpu();
    printk(KERN_INFO "CPU: %d\n", cpu);
    return 0;
}

static void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
