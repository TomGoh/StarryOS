# Build Options
export RUSTC_BOOTSTRAP := 1
export ARCH := aarch64
export LOG := warn
export BACKTRACE := y
export MEMTRACK := n
export PTRACE := y

# QEMU Options
export BLK := y
export NET := y
export VSOCK := n
export MEM := 1G
export ICOUNT := n

# Generated Options
export A := $(PWD)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu

# Enable ptrace feature by default (can be overridden: make PTRACE=n)
PTRACE ?= y
ifeq ($(PTRACE), y)
	APP_FEATURES += ptrace
endif

ifeq ($(MEMTRACK), y)
	APP_FEATURES += starry-api/memtrack
endif

IMG_URL = https://github.com/Starry-OS/rootfs/releases/download/20250917
IMG = rootfs-$(ARCH).img

img:
	@if [ ! -f $(IMG) ]; then \
		echo "Image not found, downloading..."; \
		curl -f -L $(IMG_URL)/$(IMG).xz -O; \
		xz -d $(IMG).xz; \
	fi
	@cp $(IMG) arceos/disk.img

# Build ptrace test suite binary
ptrace-tests:
	@echo "Building ptrace test suite..."
	@cd userspace/ptrace-tests && cargo build --release --target aarch64-unknown-linux-musl

# Build disk image with ptrace tests
ptrace-tests-disk:
	@echo "Building disk image with ptrace tests..."
	@bash scripts/build-ptrace-tests-disk.sh

# Run ptrace tests in QEMU
test-ptrace: defconfig ptrace-tests-disk
	@echo "Running ptrace tests in QEMU..."
	@# Temporarily replace init.sh with test version
	@cp src/init.sh src/init.sh.backup 2>/dev/null || true
	@cp src/init-test.sh src/init.sh
	@make -C arceos run || (cp src/init.sh.backup src/init.sh 2>/dev/null; exit 1)
	@# Restore original init.sh
	@cp src/init.sh.backup src/init.sh 2>/dev/null || true

defconfig justrun clean:
	@make -C arceos $@

build run debug disasm: defconfig
	@make -C arceos $@

# Aliases
rv:
	$(MAKE) ARCH=riscv64 run

la:
	$(MAKE) ARCH=loongarch64 run

vf2:
	$(MAKE) ARCH=riscv64 APP_FEATURES=vf2 MYPLAT=axplat-riscv64-visionfive2 BUS=dummy build

crosvm:
	$(MAKE) --debug=v ARCH=aarch64 APP_FEATURES=crosvm MYPLAT=axplat-aarch64-crosvm-virt BUS=pci LOG=warn build
.PHONY: build run justrun debug disasm clean img ptrace-tests ptrace-tests-disk test-ptrace
