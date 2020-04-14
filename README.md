pongoOS
=======
![Docker](https://github.com/checkra1n/pongoOS/workflows/Docker/badge.svg)
![CI](https://github.com/checkra1n/pongoOS/workflows/CI/badge.svg)

An experimental pre-boot execution environment for Apple boards built on top of checkra1n.

Building on macOS
-----------
* Install Docker for macOS
* Either build or pull the builder image
  + `docker build --tag checkra1n/build-pongo .`
  + `docker pull docker.pkg.github.com/checkra1n/pongoos/build-pongo:latest`
* Perform a build inside the container with `./build.sh`

Building on Linux
-----------

Either use the Arm reference toolchain from arm.com (aarch64-none-elf), or:

    # binutils
    ./configure --prefix="$PREFIX" --target=aarch64-none-elf --program-prefix=aarch64-none-elf- --build=x86_64-apple-darwin19.3.0 --with-gmp="$PREFIX" --with-mpfr="$PREFIX" --with-mpc="$PREFIX" --enable-lto --enable-plugins --disable-gdb --disable-sim --disable-libdecnumber --with-newlib
    # GMP
    ./configure --prefix="$PREFIX" --build=x86_64-apple-darwin19.3.0
    # MPFR
    ./configure --prefix="$PREFIX" --build=x86_64-apple-darwin19.3.0 --with-gmp="$PREFIX"
    # MPC
    ./configure --prefix="$PREFIX" --build=x86_64-apple-darwin19.3.0 --with-gmp="$PREFIX" --with-mpfr="$PREFIX"
    # gcc
    ../gcc-arm-src-snapshot-9.2-2019.12/configure --prefix="$PREFIX" --build=x86_64-apple-darwin19.3.0 --target=aarch64-none-elf --program-prefix=aarch64-none-elf- --with-gmp="$PREFIX" --with-mpfr="$PREFIX" --with-mpc="$PREFIX" --enable-lto --disable-libstdcxx --disable-libquadmath --disable-libquadmath-support --disable-libada --disable-libssp --disable-liboffloadmic --enable-languages=c,c++,lto --with-newlib

Contributions
-------------

By submitting a pull request, you certify that this contribution is coming from you and no one else. If you want to import third-party code, that shall be noted prominently for us to evaluate it appropriately.

Module
------
You can build the module at example/ with an iOS cross-compiler on Linux or a Mac. Refer to scripts/ to see how to load modules.

Kernel patchfinder
------------------

Note that the checkra1n patchfinder is not currently open-source. However, the KPF JIT that will ship on checkra1n 0.10.0 onwards is part of this repository. That means that pongoOS builds from this repository will always boot to the shell by default instead of XNU.
