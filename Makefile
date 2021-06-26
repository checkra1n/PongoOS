#
#  Copyright (C) 2019-2021 checkra1n team
#  This file is part of pongoOS.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

ifeq ($(HOST_OS),Darwin)
	EMBEDDED_CC         ?= xcrun -sdk iphoneos clang
	STRIP               ?= strip
	STAT                ?= stat -L -f %z
else
ifeq ($(HOST_OS),Linux)
	EMBEDDED_CC         ?= clang
	EMBEDDED_LDFLAGS    ?= -fuse-ld=/usr/bin/ld64
	STRIP               ?= cctools-strip
	STAT                ?= stat -L -c %s
endif
endif

PONGO_VERSION           := 2.5.1-$(shell git log -1 --pretty=format:"%H" | cut -c1-8)
SRC                     := src
AUX                     := tools
DEP                     := newlib
LIB                     := $(DEP)/aarch64-none-darwin
INC                     := include
BUILD                   := build
RA1N                    := checkra1n/kpf

# General options
EMBEDDED_LD_FLAGS       ?= -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z $(EMBEDDED_LDFLAGS)
EMBEDDED_CC_FLAGS       ?= --target=arm64-apple-ios12.0 -std=gnu17 -Wall -Wunused-label -Werror -O3 -flto -ffreestanding -U__nonnull -nostdlibinc -DTARGET_OS_OSX=0 -DTARGET_OS_MACCATALYST=0 -I$(LIB)/include $(EMBEDDED_LD_FLAGS) $(EMBEDDED_CFLAGS)

# Pongo options
PONGO_LDFLAGS           ?= -L$(LIB)/lib -lc -lm -Wl,-preload -Wl,-no_uuid -Wl,-e,start -Wl,-order_file,$(SRC)/sym_order.txt -Wl,-image_base,0x100000000 -Wl,-sectalign,__DATA,__common,0x8 -Wl,-segalign,0x4000
PONGO_CC_FLAGS          ?= -DPONGO_VERSION='"$(PONGO_VERSION)"' -DAUTOBOOT -DPONGO_PRIVATE=1 -I$(SRC)/lib -I$(INC) -Iapple-include -I$(INC)/modules/linux/ -I$(SRC)/kernel -I$(SRC)/drivers -I$(SRC)/modules/linux/libfdt $(PONGO_LDFLAGS) -DDER_TAG_SIZE=8

# KPF options
CHECKRA1N_LDFLAGS       ?= -Wl,-kext
CHECKRA1N_CC_FLAGS      ?= -DCHECKRAIN_VERSION='"0.12.4"' -I$(INC) -Iapple-include -I$(SRC)/kernel -I$(SRC)/drivers $(CHECKRA1N_LDFLAGS) $(KPF_CFLAGS) -DDER_TAG_SIZE=8 -I$(SRC)/lib -DPONGO_PRIVATE=1

STAGE3_ENTRY_C          := $(patsubst %, $(SRC)/boot/%, stage3.c clearhook.S patches.S demote_patch.S jump_to_image.S main.c)
PONGO_C                 := $(wildcard $(SRC)/kernel/*.c) $(wildcard $(SRC)/kernel/support/*.c) $(wildcard $(SRC)/dynamic/*.c) $(wildcard $(SRC)/kernel/*.S) $(wildcard $(SRC)/shell/*.c)
PONGO_DRIVERS_C         := $(wildcard $(SRC)/drivers/*/*.c) $(wildcard $(SRC)/drivers/*/*.S) $(wildcard $(SRC)/modules/linux/*/*.c) $(wildcard $(SRC)/modules/linux/*.c) $(wildcard $(SRC)/lib/*/*.c)

CHECKRA1N_C             := $(RA1N)/main.c $(RA1N)/shellcode.S
CHECKRA1N_NOSTRIP       := $(RA1N)/not_strip.txt

ifeq ($(OBF),yes)
	ifeq ($(HOST_OS),Darwin)
		CHECKRA1N_CC    ?= hikari -arch arm64
	else
	ifeq ($(HOST_OS),Linux)
		CHECKRA1N_CC_FLAGS += -Xclang -load -Xclang /usr/local/lib64/libLLVMObfuscation.so
	endif
	endif
	CHECKRA1N_CC_FLAGS  += -Xclang -mllvm -Xclang -enable-bcfobf -Xclang -mllvm -Xclang -bcf_prob=50 -Xclang -mllvm -Xclang -enable-strcry -Xclang -mllvm -Xclang -enable-cffobf -Xclang -mllvm -Xclang -enable-subobf -Xclang -mllvm -Xclang -enable-indibran -Xclang -mllvm -Xclang -enable-splitobf -Xclang -mllvm -Xclang -enable-funcwra -Xclang -mllvm -Xclang -enable-fco -DSEP_AUTO_ONLY=1
endif
ifeq ($(SEP_AUTO_ONLY),yes)
	CHECKRA1N_CC_FLAGS  += -DSEP_AUTO_ONLY=1
endif
CHECKRA1N_CC            ?= $(EMBEDDED_CC)


.PHONY: all always clean distclean

all: $(BUILD)/PongoConsolidated.bin | $(BUILD)

$(BUILD)/PongoConsolidated.bin: $(BUILD)/Pongo.bin $(BUILD)/checkra1n-kpf-pongo | $(BUILD)
	bash -c "echo 6175746F626F6F740000200000000000 | xxd -ps -r | cat $(BUILD)/Pongo.bin <(dd if=/dev/zero bs=1 count="$$(((8 - ($$($(STAT) $(BUILD)/Pongo.bin) % 8)) % 8))") /dev/stdin $(BUILD)/checkra1n-kpf-pongo > $@"

$(BUILD)/Pongo.bin: $(BUILD)/vmacho $(BUILD)/Pongo | $(BUILD)
	$(BUILD)/vmacho -f $(BUILD)/Pongo $@

$(BUILD)/Pongo: Makefile $(SRC)/boot/entry.S $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C) $(LIB)/lib/libc.a | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(EMBEDDED_CC_FLAGS) $(PONGO_CC_FLAGS) $(SRC)/boot/entry.S $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C)

$(BUILD)/checkra1n-kpf-pongo: Makefile $(CHECKRA1N_C) $(LIB)/lib/libc.a | $(BUILD)
	$(CHECKRA1N_CC) -o $@ $(EMBEDDED_CC_FLAGS) $(CHECKRA1N_CC_FLAGS) $(CHECKRA1N_C)
	$(STRIP) -x $@ -s $(CHECKRA1N_NOSTRIP)
	$(STRIP) -u $@ -s $(CHECKRA1N_NOSTRIP)

$(BUILD)/vmacho: Makefile $(AUX)/vmacho.c | $(BUILD)
	$(CC) -Wall -O3 -o $@ $(AUX)/vmacho.c $(CFLAGS)

$(BUILD):
	mkdir -p $@

$(DEP)/Makefile:
	git submodule update --init --recursive

$(LIB)/lib/libc.a: always | $(DEP)/Makefile
	$(MAKE) $(AM_MAKEFLAGS) -C $(DEP) all

clean:
	rm -rf $(BUILD)

distclean: | clean $(DEP)/Makefile
	$(MAKE) $(AM_MAKEFLAGS) -C $(DEP) distclean
