# Running in the dev tree:
#     make run                      - build, load (flash) and run from dev tree
#     make rerun                    - rerun (without load) using dev tree
#
# Installing:
#     make build                    - build in dev tree
#     make install-testnet  - build and install in target location (uses sudo)
#     make load-testnet     - load (flash) stm32 w/ installed version
#     make rerun-testnet    - rerun (without load) using installed

# Use the EXTRA_FEATURES environment variable to add additional features
EXTRA_FEATURES ?=

# Chip and paths
CHIP = STM32F413ZHTx
TARGET = target/thumbv7em-none-eabihf/release/demo_signer
INSTALL_DIR = /usr/local/vls-hsmd-testnet/lib

# Use the EXTRA_FEATURES environment variable to add additional features
EXTRA_FEATURES ?=

build:
	cargo build --features stm32f413,$(EXTRA_FEATURES) --release --bin demo_signer

run: build
	probe-run --chip $(CHIP) $(TARGET)

rerun:
	probe-run --chip $(CHIP) $(TARGET) --no-flash

install-testnet: build
	sudo cp $(TARGET) $(INSTALL_DIR)

load-testnet:
	probe-run --chip $(CHIP) $(INSTALL_DIR)/demo_signer

rerun-testnet:
	probe-run --chip $(CHIP) $(INSTALL_DIR)/demo_signer --no-flash

.PHONY: build run rerun install-testnet load-testnet rerun-testnet
