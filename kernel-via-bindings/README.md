# kernel-via-bindings

build module via bindings

## prerequisites

see https://www.kernel.org/doc/html/next/rust/quick-start.html

## build kernel

```bash
podman build -t fedora-kernel-build -f fedora.kern.Containerfile .
```

## build busybox

```bash
podman build -t fedora-busybox-build -f fedora.busybox.Containerfile .
```

## build modules

```bash
podman build -t fedora-mod-build -f fedora.mod.Containerfile .
```

### test with qemu

```bash
podman run -i -t --rm fedora-mod-build

qemu-system-x86_64 -nographic -kernel vmlinux -initrd ramdisk.img
insmod modules/rust_hello.ko
```
