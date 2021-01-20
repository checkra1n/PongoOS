#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../apple-include/mach-o/loader.h"

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        puts("usage: machopack [in (PongoConsolidated.bin)] [out (PongoAppleSilicon)] [optional, module to autoboot]");
        return -1;
    }
    
    int pongo = open(argv[1], O_RDONLY);
    if (pongo < 0) {
        puts("in file could not be opened!");
        return -2;
    }
    int out = open(argv[2], O_RDWR | O_TRUNC | O_CREAT, 0755);
    if (out < 0) {
        puts("out file could not be opened!");
        return -2;
    }
    struct stat ms;
    int module = -1;
    
    uint64_t pongoimgsz = 0;
    uint32_t modulesize = 0;

    if (argc == 4) {
        module = open(argv[3], O_RDONLY);
        if (module < 0) {
            puts("module file could not be opened!");
            return -3;
        }
        
        if (fstat(module, &ms) == -1) {
            perror("fstat");
            return -4;
        }
        
        pongoimgsz += ms.st_size + 0x20;
        modulesize = ms.st_size + 0x20;
    }

    struct stat s;
    if (fstat(pongo, &s) == -1) {
        perror("fstat");
        return -4;
    }
    pongoimgsz += s.st_size;
    
    struct mach_header_64 mh = {0};
    mh.magic = MH_MAGIC_64;
    mh.cputype = CPU_TYPE_ARM64;
    mh.cpusubtype = 0x00000002;
    mh.filetype = 12;
    mh.ncmds = 3;
    mh.flags = MH_DYLDLINK;
    
    uint32_t siz = 0;
    
    struct {
        struct segment_command_64 sh;
        struct segment_command_64 sc;
        struct section_64 se[1];
    } sc = {0};
    
#define VPOFFS (0xfffffe0004000000ull - 0x800000000ull)
#define BASE_ADDR (0x818000000 + VPOFFS)
    
    sc.sh.cmd = LC_SEGMENT_64;
    sc.sh.cmdsize = sizeof(struct segment_command_64);
    sc.sh.initprot = 1;
    sc.sh.maxprot = 1;
    sc.sh.nsects = 0;
    sc.sh.fileoff = 0;
    sc.sh.filesize = 0x4000;
    sc.sh.vmsize = 0x4000;
    sc.sh.vmaddr = BASE_ADDR;
    strcpy(sc.sh.segname, "__HEADER");

    sc.sc.cmd = LC_SEGMENT_64;
    sc.sc.cmdsize = sizeof(struct section_64) + sizeof(struct segment_command_64);
    sc.sc.initprot = 7;
    sc.sc.maxprot = 7;
    sc.sc.nsects = 1;
    sc.sc.fileoff = 0x4000;
    sc.sc.filesize = pongoimgsz;
    sc.sc.vmsize = pongoimgsz + (64 * 1024 * 1024); // reserve at least 64M of kerneldata
    sc.sc.vmsize += 0x3fff;
    sc.sc.vmsize &= ~0x3fff;
    sc.sc.vmaddr = BASE_ADDR + 0x4000;
    strcpy(sc.sc.segname, "__TEXT");

    sc.se[0].flags = S_ATTR_SOME_INSTRUCTIONS;
    sc.se[0].align = 16;
    sc.se[0].addr = sc.sc.vmaddr;
    sc.se[0].size = pongoimgsz;
    sc.se[0].offset = 0x4000;
    strcpy(sc.se[0].sectname, "__pongo");
    strcpy(sc.se[0].segname, "__TEXT");

    siz += sizeof(sc);

    struct __attribute__ ((packed)) __arm_thread_state64 {
        uint64_t x[29];
        uint64_t fp;
        uint64_t lr;
        uint64_t sp;
        uint64_t pc;
        uint32_t cpsr;
        uint32_t _pad;
    };
    
    struct thread_command_arm64 {
        uint32_t    cmd;        /* LC_THREAD or  LC_UNIXTHREAD */
        uint32_t    cmdsize;    /* total size of this command */
        uint32_t    flavor;        /*  flavor of thread state */
        uint32_t    count;         /*  count of uint32_t's in thread state */
        struct __arm_thread_state64 s64;
    };

    struct thread_command_arm64 tc = { 0 };

    tc.cmd = LC_UNIXTHREAD;
    tc.cmdsize = sizeof(tc);
    tc.flavor = ARM_THREAD_STATE64;
    tc.count = 68;
    tc.s64.pc = sc.se[0].addr + 0x1100; // pongo entrypoint for macho is at +0x1004 in order to leave space for IORVBAR
    
    siz += sizeof(tc);
    
    mh.sizeofcmds = siz;
    
    write(out, &mh, sizeof(mh));
    write(out, &sc, sizeof(sc));
    write(out, &tc, sizeof(tc));

    lseek(out, 0x4000, SEEK_SET);
    
    char* buf = malloc(s.st_size);
    assert(s.st_size == read(pongo, buf, s.st_size));
    write(out, buf, s.st_size);
    free(buf);
    
    if (module != -1) {
        uint64_t autoboot_block[2] = {0x746F6F626F747561, ms.st_size};
        
        write(out, &autoboot_block, 0x10);

        char* buf = malloc(ms.st_size);
        assert(ms.st_size == read(module, buf, ms.st_size));
        write(out, buf, ms.st_size);
        free(buf);
    }
    
    return 0;
}
