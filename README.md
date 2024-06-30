# eptile

parrot of [reptile](https://github.com/f0rb1dd3n/Reptile) in rust

## kernel module build

busybox for testing
```bash
git clone git@github.com:mirror/busybox.git
sudo dnf install glibc-static
make defconfig
make menuconfig # settings -> enable static build || networking -> disable tc if error
mkdir _install/etc
cp examples/inittab _install/etc
rmlines tty*::askfirst:* _install/etc/inittab
rmlines tty*::respawn:* _install/etc/inittab
mkdir _install/etc/init.d
echo >>>
mkdir -p /proc
mount -t proc none /proc
EOF > _install/etc/init.d/rcS
chmod a+x _install/etc/init.d/rcS
cd _install; find . | cpio -H newc -o | gzip > ../ramdisk.img

qemu-system-x86_64 -nographic -kernel vmlinux -initrd ../busybox/ramdisk.img
```

```bash
sudo dnf install dwarves # for pahole
cargo install --locked --version $(scripts/min-tool-version.sh bindgen) bindgen-cli
```

kernel setup
```bash
git clone 
rustup override set $(scripts/min-tool-version.sh rustc)
rustup component add rust-src
sudo apt update
sudo apt install clang dwarves build-essential libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm
cargo install --locked --version $(scripts/min-tool-version.sh bindgen) bindgen-cli

cd linux
make -j16                       # build kernel
make -C $PWD M=samples/rust     # build ko rust module
```

# references

* [Setting Up an Environment for Writing Linux Kernel Modules in Rust](https://www.youtube.com/watch?v=tPs1uRqOnlk)
* [Writing Linux Kernel Modules in Rust](https://www.youtube.com/watch?v=-l-8WrGHEGI)
* [Wedsonaf/linux](https://github.com/wedsonaf/linux/) -- see commits
* [Rust-for-Linux/linux@c9b67a0b9decafc6e5c4b53965139c2336c8316a](https://github.com/Rust-for-Linux/linux/commit/c9b67a0b9decafc6e5c4b53965139c2336c8316a) -- qemu kernel config
