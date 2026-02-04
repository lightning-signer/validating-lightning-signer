FROM rustlang/rust:nightly

RUN apt-get update
RUN apt-get install -y qemu-system-arm gcc-arm-none-eabi firefox-esr
RUN rustup target add thumbv7m-none-eabi
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-pack --version 0.13.1 --locked
RUN apt-get install -y clang gcc-multilib
RUN rustup target add thumbv7em-none-eabihf
