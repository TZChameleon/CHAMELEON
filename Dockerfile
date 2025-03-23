FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y && apt install -y \
    android-tools-adb \
    android-tools-fastboot \
    autoconf \
    automake \
    bc \
    bison \
    build-essential \
    ccache \
    cpio \
    cscope \
    curl \
    device-tree-compiler \
    expect \
    flex \
    ftp-upload \
    gdisk \
    git \
    iasl \
    libattr1-dev \
    libcap-ng-dev \
    libfdt-dev \
    libftdi-dev \
    libglib2.0-dev \
    libgmp3-dev \
    libhidapi-dev \
    libmpc-dev \
    libncurses5-dev \
    libpixman-1-dev \
    libslirp-dev \
    libssl-dev \
    libtool \
    make \
    mtools \
    netcat \
    ninja-build \
    python-is-python3 \
    python3-crypto \
    python3-cryptography \
    python3-pip \
    python3-pyelftools \
    python3-serial \
    rsync \
    unzip \
    uuid-dev \
    wget \
    xdg-utils \
    xsltproc \
    xterm \
    xz-utils \
    zlib1g-dev \
    e2fsprogs \
    e2fslibs \
    texinfo \
    texlive \
    tmux \
    vim

RUN curl https://storage.googleapis.com/git-repo-downloads/repo > /bin/repo && chmod a+x /bin/repo

RUN mkdir /chameleon

WORKDIR /chameleon

RUN repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 3.21.0 && repo sync -j`nproc` && \
    mv trusted-firmware-a trusted-firmware-a.bak && \
    mv optee_os optee_os.bak

COPY ./Chameleon-EL3/arm-tf /chameleon/trusted-firmware-a

COPY ./Chameleon-EL3/optee_os /chameleon/optee_os

COPY ./rw-apps/wallet /chameleon/optee_examples/wallet

COPY ./rw-apps/clearkey /chameleon/optee_examples/clearkey

WORKDIR /chameleon/build

RUN make -j2 toolchains

RUN make -j$(nproc)

COPY ./run_tmux.sh /chameleon/build/
