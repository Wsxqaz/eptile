#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

long line_to_addr(char *line) {
    return simple_strtoul(line, NULL, 16);
}

static int driver_entry(void)
{
    char * kallsyms_path = "/boot/System.map-6.8.0-48-generic\0";

    struct file *file = filp_open(kallsyms_path, O_RDONLY, 0);

    printk(KERN_INFO "[rust_hello] file = %px\n", file);
    printk(KERN_INFO "[rust_hello] file->f_op = %px\n", file->f_op);
    printk(KERN_INFO "[rust_hello] file->f_op->read = %px\n", file->f_op->read);
    printk(KERN_INFO "[rust_hello] file->f_op->read_iter = %px\n", file->f_op->read_iter);

    char * buf = kmalloc(4096, GFP_KERNEL);
    long long pos = 0;

    int read = kernel_read(file, buf, 4096, &pos);
    while (read > 0) {
      printk(KERN_INFO "[rust_hello] read = %d\n", read);
      for (int i = 0; i < 32; i++) {
        printk(KERN_INFO "buf[%d] = %c\n", i, buf[i]);
      }

      for (int i = 0; i < 4096; i++) {
          if (buf[i] == '\n') {
              long addr = line_to_addr(buf + i + 1);
              printk(KERN_INFO "addr = %lx\n", addr);
          }
      }
      read = kernel_read(file, buf, 4096, &pos);
    }

    filp_close(file, NULL);

    return 0;
}

static void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
