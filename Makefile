ARCH := $(shell uname -m | sed "s/x86_64/x86/;s/aarch64/arm64/")
MACHINE := $(shell uname -m)

.PHONY: all bpf build test clean

all: build

bpf: firewall_kernel.bpf.o

firewall_kernel.bpf.o: firewall_kernel.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(MACHINE)-linux-gnu -c $< -o $@

build: bpf
	cargo build --release --locked

test:
	cargo test --locked

clean:
	cargo clean
	rm -f firewall_kernel.bpf.o
