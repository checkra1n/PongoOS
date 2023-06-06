#
#  Copyright (C) 2019-2023 checkra1n team
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

CHECKRA1N_VERSION           ?= beta 0.12.4
PONGO_VERSION               ?= 2.6.2-$(shell git rev-parse HEAD | cut -c1-8)
PONGO_BUILD                 := $(shell git rev-parse HEAD)

ifdef CHECKRA1N_EXTRAVERSION
    CHECKRA1N_VERSION       := $(CHECKRA1N_VERSION)-$(CHECKRA1N_EXTRAVERSION)
endif

ifdef PONGO_DISPLAY_NAME
    PONGO_BUILD             += $(PONGO_DISPLAY_NAME)
else
    PONGO_BUILD             += ($(shell git rev-parse --abbrev-ref HEAD), $(shell if test -n "$$(git status --porcelain)"; then echo "dirty"; else echo "clean"; fi))
endif

SRC                         := src
AUX                         := tools
DEP                         := newlib
LIB                         := $(DEP)/aarch64-none-darwin
INC                         := include
BUILD                       := build
RA1N                        := checkra1n/kpf

ifndef HOST_OS
    ifeq ($(OS),Windows_NT)
        HOST_OS             := Windows
    else
        HOST_OS             := $(shell uname -s)
    endif
endif

# Submodules
# NOTE: Do not use &> or <<< here. Systems with annoying default shells will throw a fit if you do.
ifndef IGNORE_SUBMODULE_HEAD
UNSYNCED_SUBMODULES         := $(shell git config --file .gitmodules --get-regexp path | awk '{ print $$2 }' | while read -r module; do commit="$$(git ls-tree HEAD "$$module" | awk '{ print $$3 }')"; if [ -e "$$module/.git" ] && ! git --git-dir "$$module/.git" --work-tree "$$module" merge-base --is-ancestor "$$commit" HEAD; then printf '%s, ' "$$module"; fi; done | sed -E 's/, $$//')
ifneq ($(UNSYNCED_SUBMODULES),)
    $(error The following submodules are out of date: $(UNSYNCED_SUBMODULES). Either run "git submodule update" or set IGNORE_SUBMODULE_HEAD)
endif
endif

# Toolchain
ifdef LLVM_CONFIG
    EMBEDDED_LLVM_CONFIG    ?= $(LLVM_CONFIG)
endif

# ifdef+ifndef is ugly, but we really don't wanna use ?= when shell expansion is involved
ifdef EMBEDDED_LLVM_CONFIG
ifndef EMBEDDED_LLVM_BINDIR
    EMBEDDED_LLVM_BINDIR    := $(shell $(EMBEDDED_LLVM_CONFIG) --bindir)
endif
endif

ifdef LLVM_BINDIR
    EMBEDDED_LLVM_BINDIR    ?= $(LLVM_BINDIR)
endif

ifdef EMBEDDED_LLVM_BINDIR
    EMBEDDED_CC             ?= $(EMBEDDED_LLVM_BINDIR)/clang
#   EMBEDDED_LD             ?= $(EMBEDDED_LLVM_BINDIR)/ld64.lld
endif

CLANG                       ?= clang

ifeq ($(HOST_OS),Darwin)
    CC                      ?= $(CLANG)
    EMBEDDED_CC             ?= xcrun -sdk iphoneos clang
    STAT                    ?= stat -L -f %z
else
ifeq ($(HOST_OS),Linux)
    CC                      ?= $(CLANG)
    EMBEDDED_CC             ?= $(CLANG)
#   EMBEDDED_LD             ?= lld
ifndef EMBEDDED_LD
    EMBEDDED_LD             := $(shell which ld64)
endif
    STAT                    ?= stat -L -c %s
endif
endif

ifdef EMBEDDED_LD
    EMBEDDED_LDFLAGS        ?= -fuse-ld='$(EMBEDDED_LD)'
endif

# General options
EMBEDDED_LD_FLAGS           ?= -nostdlib -Wl,-dead_strip -Wl,-Z $(EMBEDDED_LDFLAGS)
EMBEDDED_CC_FLAGS           ?= --target=arm64-apple-ios12.0 -std=gnu17 -Wall -Wstrict-prototypes -Werror=incompatible-function-pointer-types -flto -ffreestanding -nostdlibinc -fno-blocks -U__nonnull -DTARGET_OS_OSX=0 -DTARGET_OS_MACCATALYST=0 -D_GNU_SOURCE -D__DYNAMIC_REENT__ -DDER_TAG_SIZE=8 -I$(LIB)/include $(EMBEDDED_LD_FLAGS) $(EMBEDDED_CFLAGS)

ifdef DEV_BUILD
    EMBEDDED_CC_FLAGS       += -DDEV_BUILD
endif

# Pongo options
PONGO_LD_FLAGS              ?= -static -L$(LIB)/fixup -lc -Wl,-preload -Wl,-no_uuid -Wl,-e,start -Wl,-order_file,$(SRC)/sym_order.txt -Wl,-image_base,0x100000000 -Wl,-sectalign,__DATA,__common,0x8 -Wl,-segalign,0x4000 $(PONGO_LDFLAGS)
PONGO_CC_FLAGS              ?= -Os -moutline -DPONGO_VERSION='"$(PONGO_VERSION)"' -DPONGO_BUILD='"$(PONGO_BUILD)"' -DPONGO_PRIVATE=1 -I$(SRC)/lib -I$(INC) -Iapple-include -I$(INC)/modules/linux/ -I$(SRC)/kernel -I$(SRC)/drivers -I$(SRC)/modules/linux/libfdt $(PONGO_LD_FLAGS) $(PONGO_CFLAGS)

# KPF options
KPF_LD_FLAGS                ?= -Wl,-kext $(KPF_LDFLAGS)
KPF_CC_FLAGS                ?= -O3 -DCHECKRA1N_VERSION='"$(CHECKRA1N_VERSION)"' -I$(INC) -Iapple-include -I$(SRC)/kernel -I$(SRC)/drivers -I$(SRC)/lib $(KPF_CFLAGS) $(KPF_LD_FLAGS)

PONGO_C                     := $(wildcard $(SRC)/*/*.S) $(wildcard $(SRC)/*/*/*.S) $(wildcard $(SRC)/*/*.c) $(wildcard $(SRC)/*/*/*.c) $(wildcard $(SRC)/*/*/*/*.c)
PONGO_H                     := $(wildcard $(SRC)/*/*.h) $(wildcard $(SRC)/*/*/*.h) $(wildcard $(SRC)/*/*/*/*.h)

KPF_H                       := $(wildcard $(RA1N)/*.h)
KPF_C                       := $(wildcard $(RA1N)/*.c) $(wildcard $(RA1N)/*.S)


.PHONY: all always clean distclean

# Preserve all dependencies, and rebuild if they're missing
.NOTINTERMEDIATE:

all: $(BUILD)/Pongo.bin $(BUILD)/checkra1n-kpf-pongo | $(BUILD)

$(BUILD)/Pongo.bin: $(BUILD)/vmacho $(BUILD)/Pongo | $(BUILD)
	$(BUILD)/vmacho -fM 0x80000 $(BUILD)/Pongo $@

$(BUILD)/Pongo: Makefile $(PONGO_C) $(PONGO_H) $(LIB)/fixup/libc.a | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(PONGO_C) $(EMBEDDED_CC_FLAGS) $(PONGO_CC_FLAGS)

$(BUILD)/checkra1n-kpf-pongo: Makefile $(KPF_C) $(KPF_H) $(PONGO_H) $(LIB)/fixup/libc.a | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(KPF_C) $(EMBEDDED_CC_FLAGS) $(KPF_CC_FLAGS)

$(BUILD)/vmacho: Makefile $(AUX)/vmacho.c | $(BUILD)
	$(CC) -Wall -O3 -o $@ $(AUX)/vmacho.c $(CFLAGS)

$(BUILD):
	mkdir -p $@

$(DEP)/Makefile:
	git submodule update --init --recursive

$(LIB)/fixup/libc.a: always | $(DEP)/Makefile
	$(MAKE) -C $(DEP) all

clean:
	rm -rf $(BUILD)

distclean: | clean $(DEP)/Makefile
	$(MAKE) -C $(DEP) distclean
