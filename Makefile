ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

ifeq ($(HOST_OS),Darwin)
	EMBEDDED_CC         ?= xcrun -sdk iphoneos clang -arch arm64
	STRIP               ?= strip
	STAT                ?= stat -L -f %z
else
ifeq ($(HOST_OS),Linux)
	EMBEDDED_CC         ?= arm64-apple-ios12.0.0-clang -arch arm64
	STRIP               ?= cctools-strip
	STAT                ?= stat -L -c %s
endif
endif

PONGO_VERSION           := 1.3.0-$(shell git log -1 --pretty=format:"%H" | cut -c1-8)
ROOT                    := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
SRC                     := $(ROOT)/src
LIB                     := $(ROOT)/aarch64-none-darwin
INC                     := $(ROOT)/include
BUILD                   := $(ROOT)/build
RA1N                    := $(ROOT)/checkra1n-kpf

# General options
EMBEDDED_LDFLAGS        ?= -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z
EMBEDDED_CC_FLAGS       ?= -Wall -Wunused-label -Werror -O3 -flto -ffreestanding -U__nonnull -nostdlibinc -I$(LIB)/include $(EMBEDDED_LDFLAGS)

# Pongo options
PONGO_LDFLAGS           ?= -L$(LIB)/lib -lc -lm -lg -Wl,-preload -Wl,-no_uuid -Wl,-e,start -Wl,-order_file,$(SRC)/sym_order.txt -Wl,-image_base,0x418000000 -Wl,-sectalign,__DATA,__common,0x8
PONGO_CC_FLAGS          ?= -DPONGO_VERSION='"$(PONGO_VERSION)"' -DAUTOBOOT -Djit_alloc=calloc -Djit_free=free -D'OBFUSCATE_C_FUNC(F)'='F' -I$(INC) -Iapple-include -I$(INC)/linux/ -I$(SRC)/kernel -I$(SRC)/drivers -I$(SRC)/linux/libfdt $(PONGO_LDFLAGS) $(CFLAGS)

STAGE3_ENTRY_C          := $(patsubst %, $(SRC)/boot/%, stage3.c clearhook.S patches.S demote_patch.S jump_to_image.S main.c)
PONGO_C                 := $(wildcard $(SRC)/kernel/*.c) $(wildcard $(SRC)/dynamic/*.c) $(wildcard $(SRC)/kernel/*.S) $(wildcard $(SRC)/shell/*.c)
PONGO_DRIVERS_C         := $(wildcard $(SRC)/drivers/usb/*.c) $(wildcard $(SRC)/drivers/framebuffer/*.c)  $(wildcard $(SRC)/drivers/uart/*.c) $(wildcard $(SRC)/drivers/timer/*.c) $(wildcard $(SRC)/drivers/gpio/*.c) $(wildcard $(SRC)/linux/lzma/*.c) $(wildcard $(SRC)/linux/libfdt/*.c) $(wildcard $(SRC)/linux/*.c) $(wildcard $(SRC)/drivers/xnu/*.c) $(wildcard $(SRC)/drivers/xnu/*.S)

CHECKRA1N_CC            ?= $(EMBEDDED_CC)


.PHONY: all clean

all: $(BUILD)/Pongo.bin | $(BUILD)

$(BUILD)/Pongo.bin: $(BUILD)/vmacho $(BUILD)/Pongo | $(BUILD)
	$(BUILD)/vmacho -f $(BUILD)/Pongo $@

$(BUILD)/Pongo: $(SRC)/boot/entry.S $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C) | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(EMBEDDED_CC_FLAGS) $(PONGO_CC_FLAGS) $(SRC)/boot/entry.S $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C)

$(BUILD)/vmacho: $(SRC)/vmacho.c | $(BUILD)
	$(CC) -Wall -O3 -o $@ $^ $(CFLAGS)

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)
