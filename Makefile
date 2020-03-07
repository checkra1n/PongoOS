ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

PONGO_VERSION           := 1.0.3-$(shell git log -1 --pretty=format:"%H" | cut -c1-8)
ROOT                    := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
SRC                     := $(ROOT)/src
INC                     := $(ROOT)/include
BUILD                   := $(ROOT)/build

EMBEDDED_CC             ?= aarch64-none-elf-gcc
EMBEDDED_OBJCOPY        ?= aarch64-none-elf-objcopy
EMBEDDED_LDFLAGS        ?= -static -lc -lm -lg -Xlinker -T -Xlinker Pongo.ld -Wl,--gc-sections -Wl,--build-id=none
EMBEDDED_CC_FLAGS       ?= -Wunused-label -D'OBFUSCATE_C_FUNC(F)'='F' -DDEV_BUILD=1 -DPONGO_VERSION='"$(PONGO_VERSION)"' $(EMBEDDED_LDFLAGS) -pie -O2 -flto -ffunction-sections -fdata-sections -mcpu=cortex-a57 -mtune=cortex-a57 -DAUTOBOOT

STAGE3_ENTRY_C          := $(patsubst %, $(SRC)/boot/%, stage3.c clearhook.s patches.s demote_patch.s jump_to_image.s main.c)
PONGO_C                 := $(wildcard $(SRC)/kernel/*.c) $(wildcard $(SRC)/dynamic/*.c) $(wildcard $(SRC)/kernel/*.s) $(wildcard $(SRC)/shell/*.c)
PONGO_DRIVERS_C         := $(wildcard $(SRC)/drivers/usb/*.c) $(wildcard $(SRC)/drivers/framebuffer/*.c)  $(wildcard $(SRC)/drivers/uart/*.c) $(wildcard $(SRC)/drivers/timer/*.c) $(wildcard $(SRC)/drivers/gpio/*.c) $(wildcard $(SRC)/linux/lzma/*.c) $(wildcard $(SRC)/linux/libfdt/*.c) $(wildcard $(SRC)/linux/*.c)
PONGO_FLAGS             := -ffreestanding -Iinclude -Iapple-include -Iinclude/linux/ -I$(SRC)/kernel -I$(SRC)/drivers -Wl,-e,_main -I$(SRC)/linux/libfdt

# CLANG_SPECIFIC should be $(BUILD)/entry.o, because of LLD builds.
# Note that we do not officially support building pongoOS with Clang for this early release.

.PHONY: all clean

all: $(BUILD)/Pongo.bin | $(BUILD)

$(BUILD)/Pongo.bin: $(BUILD)/Pongo.elf | $(BUILD)
	$(EMBEDDED_OBJCOPY) -O binary  $(BUILD)/Pongo.elf $@

$(BUILD)/Pongo.elf: $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C) $(BUILD)/entry.o | $(BUILD)
	$(EMBEDDED_CC) -o $@ $(EMBEDDED_CC_FLAGS) $(PONGO_FLAGS) $(STAGE3_ENTRY_C) $(PONGO_C) $(PONGO_DRIVERS_C) $(CLANG_SPECIFIC)

$(BUILD)/entry.o: $(SRC)/boot/entry.s | $(BUILD)
	$(EMBEDDED_CC) -c -o $@ $(SRC)/boot/entry.s -pie -flto

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)
