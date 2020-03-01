// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
#ifndef __MACHO_H
#define __MACHO_H

#include <stdint.h>

typedef uintptr_t vm_offset_t;
typedef vm_offset_t vm_address_t;

typedef int cpu_type_t;
typedef int cpu_subtype_t;

struct mach_header_64 {
	uint32_t        magic;
        cpu_type_t      cputype;
        cpu_subtype_t   cpusubtype;
	uint32_t        filetype;
	uint32_t        ncmds;
	uint32_t        sizeofcmds;
	uint32_t        flags;
	uint32_t        reserved;
};

#define MH_MAGIC_64 0xfeedfacf

struct load_command {
	uint32_t cmd;
	uint32_t cmdsize;
};

#define LC_REQ_DYLD 0x80000000
#define LC_SEGMENT_64   0x19
#define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */

typedef int		vm_prot_t;

struct segment_command_64 {
	uint32_t        cmd;            /* LC_SEGMENT_64 */
	uint32_t        cmdsize;        /* includes sizeof section_64 structs */
	char            segname[16];    /* segment name */
	uint64_t        vmaddr;         /* memory address of this segment */
	uint64_t        vmsize;         /* memory size of this segment */
	uint64_t        fileoff;        /* file offset of this segment */
	uint64_t        filesize;       /* amount to map from the file */
	vm_prot_t       maxprot;        /* maximum VM protection */
	vm_prot_t       initprot;       /* initial VM protection */
	uint32_t        nsects;         /* number of sections in segment */
	uint32_t        flags;          /* flags */
};

struct entry_point_command {
	uint32_t  cmd;      /* LC_MAIN only used in MH_EXECUTE filetypes */
	uint32_t  cmdsize;  /* 24 */
	uint64_t  entryoff; /* file (__TEXT) offset of main() */
	uint64_t  stacksize;/* if not zero, initial stack size */
};

#endif
