# Newlib

This folder contains [Newlib](https://sourceware.org/newlib/) headers and static libraries built for arm64 with the Darwin ABI. This provides the runtime standard library for PongoOS.

### Building

The current build is based on Newlib 3.3.0 and requires a [custom patch](darwin.patch) to work with Apple's toolchain / the Darwin ABI.  
It can be built as follows (where `/path/to/PongoOS` should be replaced with the path to this repository):

    curl -O -J ftp://sourceware.org/pub/newlib/newlib-3.3.0.tar.gz
    tar -xf newlib-3.3.0.tar.gz
    cd newlib-3.3.0/newlib
    git apply /path/to/PongoOS/aarch64-none-darwin/darwin.patch
    ./configure --prefix=/tmp/build --host=aarch64-none-darwin --enable-newlib-io-c99-formats --enable-newlib-io-long-long --disable-newlib-io-float --disable-newlib-supplied-syscalls --disable-shared --enable-static CC='xcrun -sdk iphoneos clang' CFLAGS='-arch arm64 -Wall -O3 -nostdlib -nostdlibinc -fno-blocks -U__nonnull' LDFLAGS='-Wl,-preload,-e,_main'
    make
    make install

The headers and static libraries will be placed in `/tmp/build/aarch64-none-darwin`. If you'd like to use them with PongoOS, simply move them from there to this directory.
