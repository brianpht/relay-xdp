# Kernel module build Makefile for relay_module.ko
#
# Targets (default: module):
#   module  - build relay_module.ko and reload it on this host
#   clean   - remove all kernel build artifacts
#   load    - insmod an already-built relay_module.ko
#   unload  - rmmod relay_module
#
# Requirements (Ubuntu 24.04 Noble, kernel 6.6+):
#   sudo apt install linux-headers-$(uname -r) build-essential gcc-13 dwarves kmod
#
# Notes:
#   CC=gcc-13 must match the compiler used to build the running kernel. On
#   Ubuntu 24.04 the AWS kernel (6.17-aws) is built with gcc-13. Using a
#   different major version triggers "compiler differs from the one used to
#   build the kernel" and will fail insmod with EINVAL on strict kernels.
#
#   PAHOLE is passed explicitly because the kernel Makefile may not resolve it
#   via PATH when invoked from a restricted environment (e.g. sudo).
#
#   chacha20 and poly1305 are statically linked into the kernel on Ubuntu 24.04
#   Noble (CONFIG_CRYPTO_LIB_CHACHA=y). modprobe will fail with "not found" -
#   this is expected and intentionally ignored (see -modprobe lines).

KERNEL := $(shell uname -r)
KBUILD := /lib/modules/$(KERNEL)/build
# Override on the command line if your distro uses a different gcc version:
#   make CC=gcc-14
CC     ?= gcc-13
PAHOLE ?= /usr/bin/pahole

obj-m += relay_module.o

.PHONY: module clean load unload

module: relay_module.c
	@echo "--- building relay_module.ko (kernel $(KERNEL), CC=$(CC)) ---"
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(KERNEL)/build/vmlinux
	$(MAKE) -C $(KBUILD) M=$(CURDIR) CC=$(CC) PAHOLE=$(PAHOLE) modules
	@echo "--- reloading relay_module ---"
	-sudo modprobe chacha20   2>/dev/null
	-sudo modprobe poly1305   2>/dev/null
	-sudo rmmod relay_module  2>/dev/null
	sudo insmod relay_module.ko
	@echo "--- verifying load ---"
	lsmod | grep relay_module
	@echo "--- dmesg (last relay entries) ---"
	sudo dmesg | grep -i relay | tail -8

clean:
	$(MAKE) -C $(KBUILD) M=$(CURDIR) clean

load:
	sudo insmod relay_module.ko
	lsmod | grep relay_module
	sudo dmesg | grep -i relay | tail -5

unload:
	sudo rmmod relay_module
