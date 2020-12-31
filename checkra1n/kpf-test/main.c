/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */
#undef panic
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

#define MACH_MAGIC   MH_MAGIC_64
#define MACH_SEGMENT LC_SEGMENT_64
typedef struct fat_header         fat_hdr_t;
typedef struct fat_arch           fat_arch_t;
typedef struct mach_header_64     mach_hdr_t;
typedef struct load_command       mach_lc_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct thread_command     mach_th_t;

typedef struct boot_args
{
    uint16_t Revision;
    uint16_t Version;
    uint64_t virtBase;
    uint64_t physBase;
    uint64_t memSize;
    uint64_t topOfKernelData;
    uint64_t Video[6];
    uint32_t machineType;
    void    *deviceTreeP;
    uint32_t deviceTreeLength;
    char     CommandLine[256];
    uint64_t bootFlags;
    uint64_t memSizeActual;
} boot_args;

extern kern_return_t mach_vm_protect(vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t set_max, vm_prot_t prot);

extern void module_entry(void);
extern void (*preboot_hook)(void);

void realpanic(const char *str, ...)
{
    char *ptr = NULL;
    va_list va;

    va_start(va, str);
    vasprintf(&ptr, str, va);
    va_end(va);

    panic(ptr);
}

void *ramdisk_buf = NULL;
uint32_t ramdisk_size = 0;
void *gEntryPoint;
boot_args *gBootArgs;

static boot_args BootArgs;

#define NUM_JIT 1
static struct {
    void *addr;
    size_t size;
} jits[NUM_JIT];

uint64_t get_ticks(void)
{
    return __builtin_arm_rsr64("cntpct_el0");
}

void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args))
{
    // nop
}

void sep_setup(void)
{
    // nah, we good
}

void invalidate_icache(void)
{
    // Kinda jank, but we know we're only gonna clean the JIT areas...
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr)
        {
            register uint64_t addr __asm__("x0") = (uint64_t)jits[i].addr;
            register uint64_t size __asm__("x1") = (uint64_t)jits[i].size;
            register uint32_t selector __asm__("w3") = 0;
            register uint32_t trap_no __asm__("w16") = 0x80000000;
            __asm__ volatile("svc 0x80" :: "r"(addr), "r"(size), "r"(selector), "r"(trap_no));
        }
    }
}

void* jit_alloc(size_t count, size_t size)
{
    // overflow, but not my problem
    size_t len = count * size;
    if(!len)
    {
        fprintf(stderr, "jit_alloc: bad size\n");
        exit(-1);
    }

    // No MAP_JIT, I guess...
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(mem == MAP_FAILED)
    {
        fprintf(stderr, "mmap(JIT): %s\n", strerror(errno));
        exit(-1);
    }

    bzero(mem, len);

    kern_return_t ret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)mem, len, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if(ret != KERN_SUCCESS)
    {
        fprintf(stderr, "mach_vm_protect(JIT): %s\n", mach_error_string(ret));
        exit(-1);
    }

    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(!jits[i].addr)
        {
            jits[i].addr = mem;
            jits[i].size = len;
            return mem;
        }
    }
    fprintf(stderr, "jit_alloc: no space in jit array\n");
    exit(-1);
}

void jit_free(void *mem)
{
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr == mem)
        {
            munmap(mem, jits[i].size);
            jits[i].addr = 0;
            jits[i].size = 0;
            return;
        }
    }
    fprintf(stderr, "jit_free: bad addr: %p\n", mem);
    exit(-1);
}

static void __attribute__((noreturn)) process_kernel(int fd)
{
    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        fprintf(stderr, "fstat: %s\n", strerror(errno));
        exit(-1);
    }
    size_t flen = s.st_size;
    if(flen < sizeof(mach_hdr_t))
    {
        fprintf(stderr, "File too short for header.\n");
        exit(-1);
    }
    void *file = mmap(NULL, flen, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if(file == MAP_FAILED)
    {
        fprintf(stderr, "mmap(file): %s\n", strerror(errno));
        exit(-1);
    }

    fat_hdr_t *fat = file;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64)
            {
                uint32_t offset = SWAP32(arch[i].offset);
                uint32_t newsize = SWAP32(arch[i].size);
                if(offset > flen || newsize > flen - offset)
                {
                    fprintf(stderr, "Fat arch out of bounds.\n");
                    exit(-1);
                }
                if(newsize < sizeof(mach_hdr_t))
                {
                    fprintf(stderr, "Fat arch is too short to contain a Mach-O.\n");
                    exit(-1);
                }
                file = (void*)((uintptr_t)file + offset);
                flen = newsize;
                found = true;
                break;
            }
        }
        if(!found)
        {
            fprintf(stderr, "No arm64 slice in fat binary.\n");
            exit(-1);
        }
    }

    mach_hdr_t *hdr = file;
    if(hdr->magic != MACH_MAGIC)
    {
        fprintf(stderr, "Bad magic: %08x\n", hdr->magic);
        exit(-1);
    }
    if(flen < sizeof(mach_hdr_t) + hdr->sizeofcmds)
    {
        fprintf(stderr, "File too short for load commands.\n");
        exit(-1);
    }

    uintptr_t base        = ~0,
              lowest      = ~0,
              highest     =  0,
              entry       =  0;
    for(mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if((uintptr_t)cmd + sizeof(*cmd) > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize < (uintptr_t)cmd)
        {
            fprintf(stderr, "Bad LC: 0x%lx\n", (uintptr_t)cmd - (uintptr_t)hdr);
            exit(-1);
        }
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            size_t off = seg->fileoff + seg->filesize;
            if(off > flen || off < seg->fileoff)
            {
                fprintf(stderr, "Bad segment: 0x%lx\n", (uintptr_t)cmd - (uintptr_t)hdr);
                exit(-1);
            }
            uintptr_t start = seg->vmaddr;
            if(start < lowest)
            {
                lowest = start;
            }
            uintptr_t end = start + seg->vmsize;
            if(end > highest)
            {
                highest = end;
            }
            if(seg->fileoff == 0 && seg->filesize > 0)
            {
                base = start;
            }
        }
        else if(cmd->cmd == LC_UNIXTHREAD)
        {
            struct
            {
                uint32_t cmd;
                uint32_t cmdsize;
                uint32_t flavor;
                uint32_t count;
                _STRUCT_ARM_THREAD_STATE64 state;
            } *th = (void*)cmd;
            if(th->flavor != ARM_THREAD_STATE64)
            {
                fprintf(stderr, "Bad thread state flavor.\n");
                exit(-1);
            }
            entry = th->state.__pc;
        }
    }

    if(base == ~0 || highest < lowest || entry == 0)
    {
        fprintf(stderr, "Bad memory layout, base: 0x%lx, lowest: 0x%lx, highest: 0x%lx, entry: 0x%lx\n", base, lowest, highest, entry);
        exit(-1);
    }
    size_t mlen = highest - lowest;
    void *mem = mmap(NULL, mlen, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(mem == MAP_FAILED)
    {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        exit(-1);
    }
    for(mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            size_t size = seg->filesize < seg->vmsize ? seg->filesize : seg->vmsize;
            memcpy((void*)((uintptr_t)mem + (seg->vmaddr - lowest)), (void*)((uintptr_t)hdr + seg->fileoff), size);
        }
    }

    BootArgs.Revision           = 0x1337;
    BootArgs.Version            = 0x1469;
    BootArgs.virtBase           = lowest;
    BootArgs.physBase           = (uint64_t)mem;
    BootArgs.memSize            = mlen;
    BootArgs.topOfKernelData    = (uint64_t)mem + mlen;
    BootArgs.machineType        = 0x1984;
    BootArgs.memSizeActual      = mlen;
    strcpy(BootArgs.CommandLine, "-yeet");

    gBootArgs = &BootArgs;
    gEntryPoint = (void*)((uintptr_t)mem + (entry - lowest));

    printf("Kernel at 0x%llx, entry at 0x%llx", (uint64_t)mem, (uint64_t)gEntryPoint);

    module_entry();
    preboot_hook();

    exit(0);
}

int main(int argc, const char **argv)
{
    int verbose = 1;
    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-') break;
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            char c = argv[aoff][i];
            switch(c)
            {
                case 'q':
                    --verbose;
                    break;
                case 'v':
                    ++verbose;
                    break;
                default:
                    fprintf(stderr, "Bad arg: -%c\n", c);
                    return -1;
            }
        }
    }
    if(argc - aoff != 1)
    {
        fprintf(stderr, "Usage: %s [-qv] [file | dir]\n", argv[0]);
        return -1;
    }
    int fd = open(argv[aoff], O_RDONLY);
    if(fd == -1)
    {
        fprintf(stderr, "open(%s): %s\n", argv[aoff], strerror(errno));
        return -1;
    }
    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        fprintf(stderr, "fstat(%s): %s\n", argv[aoff], strerror(errno));
        return -1;
    }
    switch(s.st_mode & S_IFMT)
    {
        case S_IFDIR:
            {
                size_t num_bad = 0;
                DIR *dir = fdopendir(fd);
                struct dirent *ent;
                while((ent = readdir(dir)))
                {
                    if(ent->d_type == DT_REG || ent->d_type == DT_LNK)
                    {
                        int kfd = openat(fd, ent->d_name, O_RDONLY);
                        if(kfd == -1)
                        {
                            fprintf(stderr, "open(%s): %s\n", ent->d_name, strerror(errno));
                            return -1;
                        }
                        pid_t pid = fork();
                        if(pid == 0)
                        {
                            if(verbose < 2)
                            {
                                int f = open("/dev/null", O_WRONLY);
                                if(f == -1)
                                {
                                    fprintf(stderr, "open(/dev/null): %s\n", strerror(errno));
                                    exit(-1);
                                }
                                if(dup2(f, STDOUT_FILENO) == -1)
                                {
                                    fprintf(stderr, "dup2(stdout): %s\n", strerror(errno));
                                    exit(-1);
                                }
                                close(f);
                                if(verbose < 1)
                                {
                                    if(dup2(STDOUT_FILENO, STDERR_FILENO) == -1)
                                    {
                                        fprintf(stderr, "dup2(stderr): %s\n", strerror(errno));
                                        exit(-1);
                                    }
                                }
                            }
                            process_kernel(kfd);
                        }
                        close(kfd);
                        int retval = 0;
                        pid_t wpid = waitpid(pid, &retval, 0);
                        if(wpid != pid)
                        {
                            fprintf(stderr, "waitpid: %s\n", strerror(errno));
                            return -1;
                        }
                        printf("%s: %d\n", ent->d_name, retval);
                        if(retval != 0)
                        {
                            ++num_bad;
                        }
                    }
                }
                if(num_bad > 0)
                {
                    printf("Failed on %lu kernels.\n", num_bad);
                }
                return num_bad == 0 ? 0 : -1;
            }

        case S_IFREG:
            process_kernel(fd);
            return 0;

        default:
            fprintf(stderr, "Bad file type.\n");
            return -1;
    }
}
