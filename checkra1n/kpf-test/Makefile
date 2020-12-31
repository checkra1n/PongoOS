ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

PONGO_VERSION           := 1.2.1-$(shell git log -1 --pretty=format:"%H" | cut -c1-8)
ROOT                    := $(shell dirname $(shell dirname $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))))
SRC                     := $(ROOT)/src
INC                     := $(ROOT)/include
RA1N                    := $(ROOT)/checkra1n/kpf

CHECKRA1N_C             := main.c $(RA1N)/main.c $(RA1N)/shellcode.S $(SRC)/drivers/xnu/xnu.c $(SRC)/drivers/xnu/xnu.S
CHECKRA1N_LDFLAGS       := -Wl,-fatal_warnings -Wl,-dead_strip
CHECKRA1N_FLAGS         := -Wall -Wunused-label -Werror -O3 -flto -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers -DCHECKRAIN_VERSION='' -Diprintf=printf -Dpanic=realpanic -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL -DDEV_BUILD=1 $(CHECKRA1N_LDFLAGS) $(KPF_CFLAGS) $(CFLAGS)

ifeq ($(HOST_OS),Darwin)
	EMBEDDED_CC         ?= xcrun -sdk iphoneos clang -arch arm64
	EMBEDDED_SIGN       ?= codesign -s - --entitlements ent.plist
	CHECKRA1N_FLAGS     += -miphoneos-version-min=7.0
else
ifeq ($(HOST_OS),Linux)
	EMBEDDED_CC         ?= arm64-apple-ios12.0.0-clang -arch arm64
	EMBEDDED_SIGN       ?= ldid -Sent.plist
endif
endif


.PHONY: all clean

all: kpf-test

kpf-test: $(CHECKRA1N_C)
	$(EMBEDDED_CC) -o $@ $(CHECKRA1N_C) $(CHECKRA1N_FLAGS) $(MODULE_CC_FLAGS)
	$(EMBEDDED_SIGN) $@

clean:
	rm -f kpf-test
