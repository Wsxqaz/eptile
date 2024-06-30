FROM fedora-busybox-build as busybox

FROM fedora-kern-build as kernel

RUN dnf install -y qemu

COPY --from=busybox /busybox/_install /busybox-install

COPY . /build
WORKDIR /build
RUN make LLVM=1 KDIR=/linux


RUN mkdir /busybox-install/modules
RUN cp *.ko /busybox-install/modules
COPY etc /busybox-install/etc

WORKDIR /busybox-install
RUN find . | cpio -H newc -o | gzip > ramdisk.img

WORKDIR /kernel-test
RUN cp /busybox-install/ramdisk.img /kernel-test
RUN cp /linux/vmlinux /kernel-test




