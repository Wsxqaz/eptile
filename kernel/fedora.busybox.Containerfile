FROM fedora:38

RUN dnf install -y git
RUN git clone https://github.com/mirror/busybox.git /busybox

RUN dnf install -y make
RUN dnf install -y diffutils
RUN dnf install -y gcc
RUN dnf install -y bzip2
RUN dnf install -y glibc-static
RUN dnf install -y perl-Pod-Html
RUN dnf install -y cpio

WORKDIR /busybox

COPY busybox.config /busybox/.config
RUN make
RUN make install

