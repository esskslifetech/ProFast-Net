# ProFast-Net XDP program and loader.
#
#   make            build profast_xdp.bpf.o and the profast-xdp loader
#   make load IF=eth0
#   make unload IF=eth0
#
# Needs clang with BPF support (clang >= 12), libbpf >= 1.0 and the kernel
# headers matching the running kernel (linux-headers / kernel-devel).

CLANG ?= clang
CC ?= cc
IF ?= eth0
BPFTOOL ?= bpftool

# Debian and Ubuntu keep asm/ under the multiarch tuple and clang does not
# search there when it targets bpf; Fedora and Arch have it under /usr/include.
MULTIARCH := /usr/include/$(shell uname -m)-linux-gnu
ifneq ($(wildcard $(MULTIARCH)/asm),)
BPF_CFLAGS += -I$(MULTIARCH)
endif

BPF_CFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_x86
CFLAGS := -O2 -g -Wall -Wextra
LIBS := -lbpf -lelf -lz

.PHONY: all clean load unload stats

all: profast_xdp.bpf.o profast-xdp

profast_xdp.bpf.o: profast_xdp.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

profast-xdp: profast_loader.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

load: all
	sudo ./profast-xdp attach $(IF)

unload:
	sudo ./profast-xdp detach $(IF)

stats:
	./profast-xdp stats $(IF)

clean:
	rm -f profast_xdp.bpf.o profast-xdp vmlinux.h
