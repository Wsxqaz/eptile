# kernel

build module

## notes

- set `rust_allowed_features := allocator_api` in `scripts/Makefile.build`

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

## building against ubuntu

ubuntu kernel source
```bash
git clone git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble
```
