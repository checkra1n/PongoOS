pongoOS
=======

A pre-boot execution environment for Apple boards built on top of checkra1n.

Building on macOS
-----------

- Install Xcode + command-line utilities
- `make clean all`

Building on Linux
-----------

- Download [Sam Bingner's iOS Toolchain](https://github.com/sbingner/llvm-project/releases/download/v10.0.0-1/linux-ios-arm64e-clang-toolchain.tar.lzma)
- Copy `scripts/arm64-apple-ios12.0.0-clang` to a directory in `$PATH`
- Adjust the `TOOLCHAIN` variable to point to the downloaded toolchain
- `make clean all`

Contributions
-------------

By submitting a pull request, you certify that this contribution is coming from you and no one else. If you want to import third-party code, that shall be noted prominently for us to evaluate it appropriately.

Module
------
You can build the module at example/ with an iOS cross-compiler on Linux or a Mac. Refer to scripts/ to see how to load modules.

Kernel patchfinder
------------------

Note that the checkra1n patchfinder is not currently open-source. However, the KPF JIT that will ship on checkra1n 0.10.0 onwards is part of this repository. That means that pongoOS builds from this repository will always boot to the shell by default instead of XNU.
