ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

PONGO_VERSION           := x.y.z-$(shell git log -1 --pretty=format:"%H" | cut -c1-8)
ROOT                    := ../..
SRC                     := $(ROOT)/src
INC                     := $(ROOT)/include
RA1N                    := $(ROOT)/checkra1n/kpf

CHECKRA1N_C             := main.c $(RA1N)/main.c $(RA1N)/shellcode.S $(SRC)/drivers/xnu/xnu.c $(SRC)/drivers/xnu/xnu.S
CHECKRA1N_LDFLAGS       := -Wl,-fatal_warnings -Wl,-dead_strip
CHECKRA1N_FLAGS         := -std=gnu17 -Wall -Wunused-label -Werror -O3 -flto -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers -DCHECKRAIN_VERSION='' -Diprintf=printf -Dpanic=realpanic -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL -DDEV_BUILD=1 $(CHECKRA1N_LDFLAGS) $(KPF_CFLAGS) $(CFLAGS)

ifeq ($(HOST_OS),Darwin)
	IOS_CC              ?= xcrun -sdk iphoneos clang -arch arm64
	MACOS_CC            ?= clang -arch arm64
	IOS_FLAGS           ?= -miphoneos-version-min=7.0
	MACOS_FLAGS         ?= -mmacosx-version-min=11.0 '-Djit_set_exec(m)=void pthread_jit_write_protect_np(int); pthread_jit_write_protect_np(m)'
	SIGN                ?= codesign -s - --entitlements ent.plist
else
ifeq ($(HOST_OS),Linux)
# TODO: macOS target
	IOS_CC              ?= arm64-apple-ios12.0.0-clang -arch arm64
	SIGN                ?= ldid -Sent.plist
endif
endif


.PHONY: all clean

all: kpf-test.ios kpf-test.macos

kpf-test.ios: $(CHECKRA1N_C)
	$(IOS_CC) -o $@ $(CHECKRA1N_C) $(CHECKRA1N_FLAGS) $(IOS_FLAGS)
	$(SIGN) $@

kpf-test.macos: $(CHECKRA1N_C)
	$(MACOS_CC) -o $@ $(CHECKRA1N_C) $(CHECKRA1N_FLAGS) $(MACOS_FLAGS)

clean:
	rm -f kpf-test.ios kpf-test.macos
