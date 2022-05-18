FROM rustlang/rust:nightly-bullseye

RUN apt-get update
RUN cat /etc/apt/sources.list # 1
RUN apt-get install -y qemu-system-arm gcc-arm-none-eabi firefox-esr
RUN rustup target add thumbv7m-none-eabi
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-pack
RUN apt-get install -y clang gcc-multilib
RUN rustup target add thumbv7em-none-eabihf

