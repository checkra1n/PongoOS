OUT=arm_abi_example
# from theos toolchain, you have to have theos iphone toolchain in your path
CC=arm64-apple-darwin14-clang

XCRUNFLAGS=-arch arm64 -Xlinker -kext -Xlinker -fatal_warnings -Xlinker -v
CCFLAGS=-I../include -I../../apple-include/ -I/usr/local/aarch64-none-elf/aarch64-none-elf/include/ -nostdlib -D_SECURE__STRING_H_ -O3 -ffreestanding

SOURCES=printf.c main.c
HEADERS=printf.h
OBJECTS=${SOURCES:.c=.o}

all: $(OUT)

objects: $(OBJECTS)

link: $(OUT)

%.o: %.c $(HEADERS)
	$(CC) $(CCFLAGS) -arch arm64 -oformat=binary -c $< -o $@ 

$(OUT): $(OBJECTS)
	xcrun -sdk iphoneos gcc -o $@ $(XCRUNFLAGS) $(CCFLAGS) $^

clean:
	rm -rf *.o $(OUT)