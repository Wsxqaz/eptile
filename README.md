# eptile

linux rootkit examples

## security_socket_connect

This example demonstrates a Linux kernel module that hooks the `security_socket_connect` LSM hook to intercept and monitor network connections. The module:

- Uses direct function hooking to override the security hook
- Inspects socket connection details including IP addresses and address families (IPv4, IPv6, Unix sockets)
- Allows connections to 1.1.1.1 while passing other connections through to the original security hook
- Safely handles memory protection by temporarily disabling write protection and CET
- Includes debug logging and proper cleanup on module unload

The code shows techniques for:
- Finding kernel symbols at runtime
- Instruction length decoding for safe function hooking
- Memory protection management
- Socket address parsing and inspection
- LSM hook interception


# references

* [Setting Up an Environment for Writing Linux Kernel Modules in Rust](https://www.youtube.com/watch?v=tPs1uRqOnlk)
* [Writing Linux Kernel Modules in Rust](https://www.youtube.com/watch?v=-l-8WrGHEGI)
* [Wedsonaf/linux](https://github.com/wedsonaf/linux/) -- see commits
* [Rust-for-Linux/linux@c9b67a0b9decafc6e5c4b53965139c2336c8316a](https://github.com/Rust-for-Linux/linux/commit/c9b67a0b9decafc6e5c4b53965139c2336c8316a) -- qemu kernel config
