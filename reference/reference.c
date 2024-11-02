#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/kernel.h>
#include <linux/min_heap.h>

MODULE_LICENSE("GPL");

int driver_entry(void)
{
    char * kallsyms_path = "/proc/kallsyms\0";

    struct file *file = filp_open(kallsyms_path, O_RDONLY, 0);

    printk(KERN_INFO "[rust_hello] file = %px\n", file);
    printk(KERN_INFO "[rust_hello] file->f_op = %px\n", file->f_op);
    printk(KERN_INFO "[rust_hello] file->f_op->read = %px\n", file->f_op->read);
    printk(KERN_INFO "[rust_hello] file->f_op->read_iter = %px\n", file->f_op->read_iter);

    char * buf = kmalloc(4096, GFP_KERNEL);
    loff_t pos = 0;

    ssize_t (*vfs_read)(struct file *, char *, size_t, loff_t *) = (ssize_t (*)(struct file *, char *, size_t, loff_t *))0xffffffffba2e4170;

    ssize_t ret = vfs_read(file, buf, 4096, &pos);
    printk(KERN_INFO "[rust_hello] ret = %d\n", ret);

    printk(KERN_INFO "[rust_hello] buf = %px\n", buf);
    for (int i = 0; i < 10; i++) {
      printk(KERN_INFO "buf[%d] = %c\n", i, buf[i]);
    }

    return 0;
}

void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
