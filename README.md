# pongoOS

A pre-boot execution environment for Apple boards built on top of checkra1n.

## Building on macOS

- Install Xcode + command-line utilities
- Run `make all`

## Building on Linux

- Install clang (if in doubt, from [apt.llvm.org](https://apt.llvm.org))
- Install `ld64` and cctools' `strip`.
  - On Debian/Ubuntu these can be installed from the checkra1n repo:
    ```
    echo 'deb https://assets.checkra.in/debian /' | sudo tee /etc/apt/sources.list.d/checkra1n.list
    sudo apt-key adv --fetch-keys https://assets.checkra.in/debian/archive.key
    sudo apt-get update
    sudo apt-get install -y ld64 cctools-strip
    ```
  - On other Linux flavours you'll likely have to build them yourself. Maybe [this repo](https://github.com/Siguza/ld64) will help you.
- Run `make all`

If `clang`, `ld64` or `cctools-strip` don't have their default names/paths, you'll want to change their invocation. For reference, the default variables are equivalent to:

    EMBEDDED_CC=clang EMBEDDED_LDFLAGS=-fuse-ld=/usr/bin/ld64 STRIP=cctools-strip make all

## Build artifacts

The Makefile will create four binaries in `build/`:

- `Pongo` - A Mach-O of the main PongoOS
- `Pongo.bin` - Same as the above, but as a bare metal binary that can be jumped to
- `checkra1n-kpf-pongo` - The checkra1n kernel patchfinder, as a Pongo module (Mach-O/kext)
- `PongoConsolidated.bin` - PongoOS and the KPF merged into a single binary

## Usage

    checkra1n -k Pongo.bin                  # Boots to Pongo shell, KPF not available
    checkra1n -k PongoConsolidated.bin      # Auto-runs KPF and boots to XNU
    checkra1n -k PongoConsolidated.bin -p   # Loads KPF, but boots to Pongo shell

## Contributions

By submitting a pull request, you agree to license your contributions under the [MIT License](https://github.com/checkra1n/pongoOS/blob/master/LICENSE.md) and you certify that you have the right to do so.  
If you want to import third-party code that cannot be licensed as such, that shall be noted prominently for us to evaluate accordingly.

## Structure

- The core PongoOS and drivers are in `src/`.
  - Build-time helper tools are in `tools/`.
- The stdlib used by PongoOS (Newlib) is in `aarch64-none-darwin`.
  - This includes a custom patch for Newlib to work with the Darwin ABI.
- An example module exists in `example/`.
- Scripts to communicate with the PongoOS shell are in `scripts/`.
  - This includes `pongoterm`, an interactive shell client for macOS.
- The checkra1n kernel patchfinder (KPF) is in `checkra1n/kpf`.
  - This currently includes the SEP exploit, though that is to be moved into mainline PongoOS in the future.
- A userland version of the KPF can be built from `checkra1n/kpf-test` (can only be run on arm64).
