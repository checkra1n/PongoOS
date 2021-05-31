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

DEP                     := ../../newlib
LIB                     := $(DEP)/aarch64-none-darwin
BUILD                   := build

# General options
EMBEDDED_LD_FLAGS       ?= -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z $(EMBEDDED_LDFLAGS)
EMBEDDED_CC_FLAGS       ?= --target=arm64-apple-ios12.0 -Wall -Wunused-label -Werror -O3 -flto -ffreestanding -U__nonnull -nostdlibinc -DTARGET_OS_OSX=0 -DTARGET_OS_MACCATALYST=0 -I$(LIB)/include $(EMBEDDED_LD_FLAGS) $(EMBEDDED_CFLAGS)

# Module options
MODULE_LDFLAGS       ?= -Wl,-kext
MODULE_CC_FLAGS      ?= -I../../apple-include/ -I../include/ $(MODULE_LDFLAGS)

MODULE_C             := main.c

.PHONY: all clean

all: $(BUILD)/testmodule

$(BUILD)/testmodule: Makefile $(MODULE_C)
	$(EMBEDDED_CC) -o $@ $(EMBEDDED_CC_FLAGS) $(MODULE_CC_FLAGS) $(MODULE_C)

clean:
	rm -rf $(BUILD)