## One Time Setup

### Install Dependencies

Update PATH:

    export PATH=$PATH:~/.local/bin

On Debian:

    sudo apt-get update
    sudo apt-get install -y \
      autoconf automake build-essential git libtool libgmp-dev libsqlite3-dev \
      python3 python3-pip net-tools zlib1g-dev libsodium-dev gettext \
      python3-mako \
      libprotobuf-c-dev \
      protobuf-compiler protobuf-compiler-grpc libgrpc++-dev pkg-config \
      curl \
      gawk

On Fedora:

    sudo dnf update -y && \
      sudo dnf groupinstall -y \
              'C Development Tools and Libraries' \
              'Development Tools' && \
      sudo dnf install -y \
              clang \
              gettext \
              git \
              gmp-devel \
              libsq3-devel \
              python3-devel \
              python3-pip \
              python3-setuptools \
              net-tools \
              valgrind \
              wget \
              zlib-devel \
              libsodium-devel \
              python3-mako \
              protobuf-compiler protobuf-devel grpc-devel grpc-plugins \
              perl \
              gawk

On Both:

    pip3 install --upgrade pip
    pip3 install --user poetry

    # These are currently touchy about versions (2022-05-02)
    pip3 install --user mistune==0.8.4
    pip3 install --user mrkd==0.2.0

### Install Rust

You can skip this section entirely if you already have rust installed.

Directions from (https://www.rust-lang.org/learn/get-started):
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# accept the defaults ...
source $HOME/.cargo/env
```

### Install Bitcoind

You can skip this section entirely if you have `bitcoind` and
`bitcoin-cli` installed on your system.

Install the bitcoind binaries on the `CLNHOST`.

On Debian:
```
sudo apt-get install -y snapd
sleep 30
sudo snap install bitcoin-core
# Snap does some weird things with binary names; you'll
# want to add a link to them so everything works as expected
sudo ln -s /snap/bitcoin-core/current/bin/bitcoin{d,-cli} /usr/local/bin/
```

On Fedora:
```
sudo dnf install -y snapd
sleep 30
sudo snap install bitcoin-core
# Snap does some weird things with binary names; you'll
# want to add a link to them so everything works as expected
sudo ln -s /var/lib/snapd/snap/bitcoin-core/current/bin/bitcoin{d,-cli} /usr/local/bin/
```

### Clone CLN+VLS Integration Repository

Choose somewhere to clone tree:
```
mkdir ~/lightning-signer && cd ~/lightning-signer
```

Clone tree, select branch, update:
```
git clone https://gitlab.com/lightning-signer/vls-hsmd.git && cd vls-hsmd
git checkout <branch-tag-or-main>
git submodule update --init --recursive
```

One-time setup stuff:
```
./scripts/enable-githooks
```

Initial Build of CLN and VLS:
```
cd ~/lightning-signer/vls-hsmd && make build-standard
cd ~/lightning-signer/vls-hsmd/lightning && poetry run make
```

Check if an integration test works:
```
make configure-standard test-one TEST=tests/test_pay.py::test_pay
```

### Install CLN+VLS Service Components

You can skip this if you are only developing ...

Install CLN components on the `CLNHOST`:
```
cd ~/lightning-signer/vls-hsmd/lightning
sudo make install
/usr/local/bin/lightningd --version

sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/remote_hsmd_serial \
    /usr/local/libexec/c-lightning/
sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/remote_hsmd_socket \
    /usr/local/libexec/c-lightning/
/usr/local/libexec/c-lightning/remote_hsmd_serial --git-desc
/usr/local/libexec/c-lightning/remote_hsmd_socket --git-desc
```

Install the VLS signer on the `VLSHOST` if you are running in `SOCKET` mode:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/vlsd2 /usr/local/bin
/usr/local/bin/vlsd2 --git-desc
```
