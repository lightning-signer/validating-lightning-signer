FROM rustlang/rust:nightly

RUN apt-get update && apt-get install -y qemu-system-arm gcc-arm-none-eabi
RUN rustup target add thumbv7m-none-eabi
