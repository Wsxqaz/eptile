FROM fedora:38

RUN dnf install -y git
RUN dnf install -y make
RUN dnf install -y gcc
RUN dnf install -y ncurses-devel
RUN dnf install -y flex
RUN dnf install -y bison
RUN dnf install -y clang-devel
RUN dnf install -y elfutils-devel
RUN dnf install -y bc
RUN dnf install -y diffutils
RUN dnf install -y openssl-devel
RUN dnf install -y llvm
RUN dnf install -y lld

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN git clone --depth 1 --branch master --single-branch https://github.com/torvalds/linux.git /linux

WORKDIR /linux

ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup override set $(scripts/min-tool-version.sh rustc)
RUN cargo install --locked --version $(scripts/min-tool-version.sh bindgen) bindgen-cli
RUN rustup component add rust-src

COPY rust.config /linux/.config
RUN make LLVM=1 -j16
