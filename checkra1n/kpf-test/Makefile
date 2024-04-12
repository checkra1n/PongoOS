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

KPF_H                   := $(wildcard $(RA1N)/*.h) $(wildcard $(INC)/*.h) $(wildcard $(SRC)/kernel/*.h) $(wildcard $(SRC)/drivers/*.h)
KPF_C                   := main.c $(wildcard $(RA1N)/*.c) $(wildcard $(RA1N)/*.S) $(SRC)/drivers/xnu/xnu.c $(SRC)/drivers/xnu/xnu.S
KPF_LD_FLAGS            := -Wl,-fatal_warnings -Wl,-dead_strip $(KPF_LDFLAGS)
KPF_CC_FLAGS            := -std=gnu17 -Wall -Wno-strict-prototypes -Werror=incompatible-function-pointer-types -O3 -flto -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers -DCHECKRA1N_VERSION='"x.y.z"' -Diprintf=printf -Dpanic=realpanic \
                           '-Djit_set_exec(m)=void pthread_jit_write_protect_np(int); pthread_jit_write_protect_np(m)' -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL -DDEV_BUILD -D_GNU_SOURCE -DKPF_TEST $(KPF_CFLAGS) $(KPF_LD_FLAGS)
KPF_LD_FLAGS_LINUX      := 
KPF_CC_FLAGS_LINUX      := -std=gnu17 -Wall -Wno-strict-prototypes -O3 -flto -I$(INC) -I$(SRC)/kernel -I$(SRC)/drivers -DCHECKRA1N_VERSION='"x.y.z"' -Diprintf=printf -Dpanic=realpanic \
                           -DOVERRIDE_CACHEABLE_VIEW=0x800000000ULL '-Djit_set_exec(m)=void pthread_jit_write_protect_np(int);' -DDEV_BUILD -D_GNU_SOURCE -DKPF_TEST -Iinclude $(KPF_CFLAGS) $(KPF_LD_FLAGS_LINUX)

ifeq ($(HOST_OS),Darwin)
	IOS_CC              ?= xcrun -sdk iphoneos clang --target=arm64-apple-ios7.0
	MACOS_CC            ?= clang --target=arm64-apple-macos11.0
	SIGN                ?= codesign -s - --entitlements ent.plist
else
ifeq ($(HOST_OS),Linux)
# TODO: macOS target
	IOS_CC              ?= arm64-apple-ios12.0.0-clang -arch arm64
	LINUX_CC            ?= clang
	SIGN                ?= ldid -Sent.plist
endif
endif


.PHONY: all clean

all: kpf-test.ios kpf-test.macos

kpf-test.ios: Makefile $(KPF_C) $(KPF_H)
	$(IOS_CC) -o $@ $(KPF_C) $(KPF_CC_FLAGS)
	$(SIGN) $@

kpf-test.macos: Makefile $(KPF_C) $(KPF_H)
	$(MACOS_CC) -o $@ $(KPF_C) $(KPF_CC_FLAGS)

shellcode_S_linux.S: $(RA1N)/shellcode.S Makefile
	sed -e 's/_pf_jit/pf_jit/g' -e 's/_dyld_shc/dyld_shc/g' -e 's/_sandbox/sandbox/g' \
	-e 's/_fsctl_shc/fsctl_shc/g' -e 's/_kdi_shc/kdi_shc/g' -e 's/_nvram_shc/nvram_shc/g' \
	-e 's/_launchd_execve_hook/launchd_execve_hook/g' $< > $@

xnu_S_linux.S: $(SRC)/drivers/xnu/xnu.S Makefile
	sed -e 's/_pf_jit/pf_jit/g' $< > $@

kpf-test.linux: Makefile $(KPF_C) $(KPF_H) shellcode_S_linux.S xnu_S_linux.S
	$(LINUX_CC) -o $@ main.c -lbsd -g $(wildcard $(RA1N)/*.c) $(SRC)/drivers/xnu/xnu.c shellcode_S_linux.S xnu_S_linux.S $(KPF_CC_FLAGS_LINUX)

clean:
	rm -f kpf-test.ios kpf-test.macos kpf-test.linux
	rm -f shellcode_S_linux.S xnu_S_linux.S
