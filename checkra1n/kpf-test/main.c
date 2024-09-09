/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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
#define _DEFAULT_SOURCE
#undef panic
#ifndef __APPLE__
#include "./mach-o/loader.h"
#include <time.h>
#endif
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
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <libkern/OSCacheControl.h>
#include <TargetConditionals.h>
#endif
#if TARGET_OS_OSX
#   include <pthread.h>
#endif

#include <paleinfo.h>
extern palerain_option_t palera1n_flags;

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

#define MACH_MAGIC   MH_MAGIC_64
#define MACH_SEGMENT LC_SEGMENT_64
typedef struct fat_header         fat_hdr_t;
typedef struct fat_arch           fat_arch_t;
typedef struct mach_header_64     mach_hdr_t;
typedef struct load_command       mach_lc_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct thread_command     mach_th_t;

uint32_t socnum = 0x8015;

typedef struct boot_args
{
    uint16_t Revision;
    uint16_t Version;
    uint32_t __pad0;
    uint64_t virtBase;
    uint64_t physBase;
    uint64_t memSize;
    uint64_t topOfKernelData;
    uint64_t Video[6];
    uint32_t machineType;
    uint32_t __pad1;
    void    *deviceTreeP;
    uint32_t deviceTreeLength;
    union
    {
        struct
        {
            char     CommandLine[0x100];
            uint32_t __pad;
            uint64_t bootFlags;
            uint64_t memSizeActual;
        } iOS12;
        struct
        {
            char     CommandLine[0x260];
            uint32_t __pad;
            uint64_t bootFlags;
            uint64_t memSizeActual;
        } iOS13;
    };
} __attribute__((packed)) boot_args;

#ifdef __APPLE__
extern kern_return_t mach_vm_protect(vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t set_max, vm_prot_t prot);
#else
void sys_icache_invalidate(void* a, size_t b) {}
#endif

extern void module_entry(void);
extern void (*preboot_hook)(void);

void realpanic(const char *str, ...)
{
    va_list va;
#ifdef __APPLE__
    char *ptr = NULL;

    va_start(va, str);
    vasprintf(&ptr, str, va);
    va_end(va);
    panic(ptr);
#else
    printf("panic: ");
    va_start(va, str);
    vprintf(str, va);
    va_end(va);
    printf("\n");
    fflush(stdout);
    exit(6);
#endif
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
#ifdef __APPLE__
    return __builtin_arm_rsr64("cntpct_el0");
#else
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    return (uint64_t)((spec.tv_sec*1000+spec.tv_nsec/1e6)*24000);
#endif
}

void* dt_get(const char *name)
{
    return NULL;
}

uint32_t dt_node_u32(void *node, const char *prop, uint32_t idx) {
    return 0;
}

void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args))
{
    // nop
}

void* alloc_static(uint32_t size)
{
    return malloc(size);
}

void invalidate_icache(void)
{
    // Kinda jank, but we know we're only gonna clean the JIT areas...
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr)
        {
            sys_icache_invalidate(jits[i].addr, jits[i].size);
        }
    }
}

#if !TARGET_OS_OSX && defined(__APPLE__)
void pthread_jit_write_protect_np(int exec)
{
    for(uint32_t i = 0; i < NUM_JIT; ++i)
    {
        if(jits[i].addr)
        {
            kern_return_t ret = mach_vm_protect(mach_task_self(), (mach_vm_address_t)jits[i].addr, jits[i].size, 0, VM_PROT_READ | (exec ? VM_PROT_EXECUTE : VM_PROT_WRITE));
            if(ret != KERN_SUCCESS)
            {
                fprintf(stderr, "mach_vm_protect(JIT): %s\n", mach_error_string(ret));
                exit(-1);
            }
        }
    }
}
#elif !defined(__APPLE__)
void pthread_jit_write_protect_np(int exec) {}
#endif

void* jit_alloc(size_t count, size_t size)
{
    // overflow, but not my problem
    size_t len = count * size;
    if(!len)
    {
        fprintf(stderr, "jit_alloc: bad size\n");
        exit(-1);
    }

#if defined(__APPLE__)
    int prot  = PROT_READ | PROT_WRITE | PROT_EXEC;
#else
    int prot  = PROT_READ | PROT_WRITE | PROT_EXEC;
#endif
    int flags = MAP_ANON | MAP_PRIVATE;
#if TARGET_OS_OSX
    prot  |= PROT_EXEC;
    flags |= MAP_JIT;
#endif
    void *mem = mmap(NULL, len, prot, flags, -1, 0);
    if(mem == MAP_FAILED)
    {
        fprintf(stderr, "mmap(JIT): %s\n", strerror(errno));
        exit(-1);
    }

    pthread_jit_write_protect_np(0);

    bzero(mem, len);

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
    uint32_t fatoff = 0;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64)
            {
                fatoff = SWAP32(arch[i].offset);
                uint32_t newsize = SWAP32(arch[i].size);
                if(fatoff > flen || newsize > flen - fatoff)
                {
                    fprintf(stderr, "Fat arch out of bounds.\n");
                    exit(-1);
                }
                if(newsize < sizeof(mach_hdr_t))
                {
                    fprintf(stderr, "Fat arch is too short to contain a Mach-O.\n");
                    exit(-1);
                }
                file = (void*)((uintptr_t)file + fatoff);
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
    bool use_mmap = (fatoff & 0x3fff) == 0;
    printf("%s mmap\n", use_mmap ? "Using" : "Not using");

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
            if(off > flen || off < seg->fileoff || (seg->fileoff & 0x3fff) || (seg->vmaddr & 0x3fff))
            {
                fprintf(stderr, "Bad segment: %.16s\n", seg->segname);
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
    void *mem = mmap(NULL, mlen, use_mmap ? PROT_NONE : PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
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
            if(!seg->vmsize)
            {
                continue;
            }
            uintptr_t segbase = (uintptr_t)mem + (seg->vmaddr - lowest);
            if(use_mmap)
            {
                size_t segsize = (seg->vmsize + 0x3fff) & ~0x3fff;
                if(seg->filesize > 0)
                {
                    size_t mapsize = (seg->filesize + 0x3fff) & ~0x3fff;
                    void *map = mmap((void*)segbase, seg->filesize, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_FILE | MAP_PRIVATE, fd, fatoff + seg->fileoff);
                    if(map == MAP_FAILED)
                    {
                        fprintf(stderr, "mmap(%.16s): %s\n", seg->segname, strerror(errno));
                        exit(-1);
                    }
                    segbase += mapsize;
                    segsize -= mapsize;
                }
                if(segsize > 0)
                {
                    void *map = mmap((void*)segbase, segsize, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
                    if(map == MAP_FAILED)
                    {
                        fprintf(stderr, "mmap(%.16s zerofill): %s\n", seg->segname, strerror(errno));
                        exit(-1);
                    }
                }
            }
            else
            {
                memcpy((void*)segbase, (void*)((uintptr_t)hdr + seg->fileoff), seg->filesize);
            }
        }
    }

    BootArgs.Revision           = 0x1337;
    BootArgs.Version            = 0x1469;
    BootArgs.virtBase           = lowest;
    BootArgs.physBase           = (uint64_t)mem;
    BootArgs.memSize            = mlen;
    BootArgs.topOfKernelData    = (uint64_t)mem + mlen;
    BootArgs.machineType        = 0x1984;
    //BootArgs.memSizeActual      = mlen;
    strcpy(BootArgs.iOS12.CommandLine, "-yeet");

    gBootArgs = &BootArgs;
    gEntryPoint = (void*)((uintptr_t)mem + (entry - lowest));

    printf("Kernel at 0x%" PRIx64 ", entry at 0x%" PRIx64 "", (uint64_t)mem, (uint64_t)gEntryPoint);

    module_entry();
    preboot_hook();

    exit(0);
}

// Consider the per-process file descriptor limit before touching this.
// Last I checked, it was at 256. We keep 2 file pipe ends for each process,
// 3 temp ones that we close after forking, 3 for std[in|out|err], and 1 for
// the dir handle. Probably some more by dyld and whatnot.
#define NUM_PROC 16

typedef struct
{
    char *file;
    pid_t pid;
    int fdout;
    int fderr;
} child_t;

static const char *color_red    = "\e[1;91m";
static const char *color_yellow = "\e[1;93m";
static const char *color_blue   = "\e[1;96m";
static const char *color_reset  = "\e[0m";

// 5 = full stdout, stderr and exit codes of all children
// 4 = full stderr and exit codes of all children
// 3 = only exit codes of children
// 2 = stderr and errornous exit codes of children
// 1 = only errornous exit codes of children
// 0 = only things that should never happen
static int verbose = 4;

static int copy_output(int *fdin, int fdout, FILE *f)
{
    if(*fdin == -1)
    {
        return 0;
    }
    if(fflush(f) != 0)
    {
        fprintf(stderr, "fflush: %s\n", strerror(errno));
        return -1;
    }
    char buf[0x1000];
    while(1)
    {
        ssize_t s = read(*fdin, buf, sizeof(buf));
        if(s < 0)
        {
            fprintf(stderr, "read: %s\n", strerror(errno));
            return -1;
        }
        if(s == 0)
        {
            break;
        }
        ssize_t w = 0;
        while(w < s)
        {
            ssize_t r = write(fdout, buf + w, s - w);
            if(r <= 0)
            {
                fprintf(stderr, "write: %s\n", strerror(errno));
                return -1;
            }
            w += r;
        }
    }
    close(*fdin);
    *fdin = -1;
    return 0;
}

static int wait_for_child(child_t *children, size_t *num_bad, child_t **slot)
{
    int retval = 0;
    pid_t pid = wait(&retval);
    for(size_t i = 0; i < NUM_PROC; ++i)
    {
        child_t *child = &children[i];
        if(child->pid == pid)
        {
            int r;
            child->pid = 0;
            r = copy_output(&child->fdout, STDOUT_FILENO, stdout);
            if(r != 0) return r;
            fputs(color_yellow, stderr);
            r = copy_output(&child->fderr, STDERR_FILENO, stderr);
            fputs(color_reset, stderr);
            if(r != 0) return r;
            if(verbose >= 3 || (verbose >= 1 && retval != 0))
            {
                printf("%s%s: %d%s\n", retval == 0 ? color_blue : color_red, child->file, retval, color_reset);
            }
            free(child->file);
            child->file = NULL;
            if(retval != 0)
            {
                ++*num_bad;
            }
            if(slot)
            {
                *slot = child;
            }
            return 0;
        }
    }
    fprintf(stderr, "wait: %d, %s\n", pid, strerror(errno));
    return -1;
}

bool test_force_rootful = 0;

int main(int argc, const char **argv)
{
    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-') break;
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            char c = argv[aoff][i];
            switch(c)
            {
                case 'n':
                    color_red    = "";
                    color_yellow = "";
                    color_blue   = "";
                    color_reset  = "";
                    break;
                case 'q':
                    --verbose;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'f':
                    palera1n_flags |= palerain_option_rootful;
                    test_force_rootful = 1;
                    break;
                default:
                    fprintf(stderr, "Bad arg: -%c\n", c);
                    return -1;
            }
        }
    }
    if(argc - aoff != 1)
    {
        fprintf(stderr, "Usage: %s [-nqvf] [file | dir]\n", argv[0]);
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
                child_t children[NUM_PROC] = {};
                for(size_t i = 0; i < NUM_PROC; ++i)
                {
                    children[i].fdout = -1;
                    children[i].fderr = -1;
                }
                size_t num_bad = 0;
                DIR *dir = fdopendir(fd);
                struct dirent *ent;
                while((ent = readdir(dir)))
                {
                    if(ent->d_type == DT_REG || ent->d_type == DT_LNK)
                    {
                        child_t *slot = NULL;
                        for(size_t i = 0; i < NUM_PROC; ++i)
                        {
                            if(children[i].pid == 0)
                            {
                                slot = &children[i];
                                break;
                            }
                        }
                        if(!slot)
                        {
                            int r = wait_for_child(children, &num_bad, &slot);
                            if(r != 0)
                            {
                                return r;
                            }
                        }
                        int kfd = openat(fd, ent->d_name, O_RDONLY);
                        if(kfd == -1)
                        {
                            fprintf(stderr, "open(%s): %s\n", ent->d_name, strerror(errno));
                            return -1;
                        }
                        int fdout[2];
                        int fderr[2];
                        if(verbose < 5)
                        {
                            fdout[0] = fdout[1] = -1;
                        }
                        else if(pipe(fdout) != 0)
                        {
                            fprintf(stderr, "pipe(fdout): %s\n", strerror(errno));
                            return -1;
                        }
                        if(verbose == 3 || verbose < 2)
                        {
                            fderr[0] = fderr[1] = -1;
                        }
                        else if(pipe(fderr) != 0)
                        {
                            fprintf(stderr, "pipe(fderr): %s\n", strerror(errno));
                            return -1;
                        }
                        pid_t pid = fork();
                        if(pid == 0)
                        {
                            for(size_t i = 0; i < NUM_PROC; ++i)
                            {
                                if(children[i].fdout != -1) close(children[i].fdout);
                                if(children[i].fderr != -1) close(children[i].fderr);
                            }
                            if(fdout[0] != -1) close(fdout[0]);
                            if(fderr[0] != -1) close(fderr[0]);
                            if(fdout[1] == -1)
                            {
                                fdout[1] = open("/dev/null", O_WRONLY);
                                if(fdout[1] == -1)
                                {
                                    fprintf(stderr, "open(/dev/null): %s\n", strerror(errno));
                                    exit(-1);
                                }
                            }
                            if(fderr[1] == -1)
                            {
                                fderr[1] = open("/dev/null", O_WRONLY);
                                if(fderr[1] == -1)
                                {
                                    fprintf(stderr, "open(/dev/null): %s\n", strerror(errno));
                                    exit(-1);
                                }
                            }
                            if(dup2(fdout[1], STDOUT_FILENO) == -1)
                            {
                                fprintf(stderr, "dup2(stdout): %s\n", strerror(errno));
                                exit(-1);
                            }
                            if(dup2(fderr[1], STDERR_FILENO) == -1)
                            {
                                fprintf(stderr, "dup2(stdout): %s\n", strerror(errno));
                                exit(-1);
                            }
                            close(fdout[1]);
                            close(fderr[1]);
                            process_kernel(kfd);
                            __builtin_unreachable();
                        }
                        close(kfd);
                        if(fdout[1] != -1) close(fdout[1]);
                        if(fderr[1] != -1) close(fderr[1]);
                        slot->pid = pid;
                        slot->fdout = fdout[0];
                        slot->fderr = fderr[0];
                        slot->file = strdup(ent->d_name);
                    }
                }
                size_t num_wait = 0;
                for(size_t i = 0; i < NUM_PROC; ++i)
                {
                    if(children[i].pid != 0)
                    {
                        ++num_wait;
                    }
                }
                for(size_t i = 0; i < num_wait; ++i)
                {
                    int r = wait_for_child(children, &num_bad, NULL);
                    if(r != 0)
                    {
                        return r;
                    }
                }
                if(num_bad > 0)
                {
                    fprintf(stderr, "%sFailed on %lu kernels.%s\n", color_red, num_bad, color_reset);
                }
                return num_bad == 0 ? 0 : -1;
            }

        case S_IFREG:
            process_kernel(fd);
            __builtin_unreachable();

        default:
            fprintf(stderr, "Bad file type.\n");
            return -1;
    }
}
