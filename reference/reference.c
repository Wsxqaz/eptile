#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

long line_to_addr(char *line) {
    return simple_strtoul(line, NULL, 16);
}

long find_kallsym(char *name) {
  char * kallsyms_path = "/boot/System.map-6.8.0-48-generic\0";
  struct file *file = filp_open(kallsyms_path, O_RDONLY, 0);

  printk(KERN_INFO "file: %p\n", file);
  printk(KERN_INFO "file->f_op: %p\n", file->f_op);
  printk(KERN_INFO "file->f_op->read: %p\n", file->f_op->read);
  printk(KERN_INFO "file->f_op->read_iter: %p\n", file->f_op->read_iter);

  char * buf = kmalloc(4096, GFP_KERNEL);
  long long pos = 0;

  int read = kernel_read(file, buf, 4096, &pos);
  while (read > 0) {
    for (int i = 0; i < 4096; i++) {
        if (buf[i] == '\n') {
          int j = i + 1;
          while (buf[j] != '\n') {
            j++;
          }
          char tmp = buf[j];
          buf[j] = '\0';
          if (i + 20 >= 4096) {
            buf[j] = tmp;
            continue;
          }
          printk(KERN_INFO "line: %s\n", buf + i + 20);
          if (strcmp(buf + i + 20, name) != 0) {
            buf[j] = tmp;
            continue;
          }
          buf[j] = tmp;
          long addr = line_to_addr(buf + i + 1);
          filp_close(file, NULL);
          return addr;
        }
    }
    read = kernel_read(file, buf, 4096, &pos);
  }
  filp_close(file, NULL);
  return 0;
}

static int driver_entry(void)
{

  long addr = find_kallsym("trace_call_bpf");
  printk(KERN_INFO "trace_call_bpf: %lx\n", addr);
  return 0;
}

static void driver_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(driver_entry);
module_exit(driver_exit);
