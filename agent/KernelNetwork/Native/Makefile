CLANG ?= clang
CC ?= cc
LD ?= ld
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
BUILD_DIR ?= build

.PHONY: all clean test

all: $(BUILD_DIR)/challenger-siem-ebpf-helper

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/challenger_network_bpf.o: challenger_network.bpf.c challenger_network_shared.h challenger_network_parser.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

$(BUILD_DIR)/challenger_network_embedded.o: $(BUILD_DIR)/challenger_network_bpf.o
	cd $(BUILD_DIR) && $(LD) -r -b binary -o challenger_network_embedded.o challenger_network_bpf.o

$(BUILD_DIR)/challenger-siem-ebpf-helper: challenger-siem-ebpf-helper.c challenger_network_shared.h challenger_network_time.h $(BUILD_DIR)/challenger_network_embedded.o
	$(CC) $(CFLAGS) -I. challenger-siem-ebpf-helper.c $(BUILD_DIR)/challenger_network_embedded.o -lbpf -lelf -lz -o $@

clean:
	rm -rf -- $(BUILD_DIR)

$(BUILD_DIR)/challenger-network-parser-tests: challenger-network-parser-tests.c challenger_network_parser.h challenger_network_time.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. challenger-network-parser-tests.c -o $@

test: $(BUILD_DIR)/challenger-network-parser-tests
	$(BUILD_DIR)/challenger-network-parser-tests
