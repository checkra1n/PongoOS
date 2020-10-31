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
#include <errno.h>
#include <stdlib.h>
#include <pongo.h>

#define MAX_WANT_PAGES_IN_FREELIST 512
uint64_t pages_in_freelist;
void* free_list;
bool is_16k_v = false;
void* alloc_contig_direct(uint32_t size); // to avoid reentrance
uint64_t alloc_phys_direct(uint32_t size);
void* page_alloc_from_freelist() {
    void* page = NULL;
    disable_interrupts();
    if (free_list) {
        pages_in_freelist--;
        page = free_list;
        free_list = *(void**)page;
    }
    enable_interrupts();
    return page;
}
void* page_alloc() {
    disable_interrupts();
    void* page = page_alloc_from_freelist();
    if (!page) {
        page = (void*)alloc_contig_direct(PAGE_SIZE);
    }
    enable_interrupts();
    
    if (!page)
        panic("page_alloc: returning NULL, memory leak?");
    
    bzero(page, 0x4000); // page_alloc guarantees zero'd memory
    return page;
}
void page_free(void* page) {
    disable_interrupts();
    pages_in_freelist++;
    *(void**)page = free_list;
    free_list = page;
    enable_interrupts();
}
uint64_t ppage_alloc_from_freelist() {
    void* page = page_alloc_from_freelist();
    if (!page) return 0;
    return vatophys_static(page);
}
uint64_t ppage_alloc() {
    return vatophys_static(page_alloc());
}
void ppage_free(uint64_t page) {
    page_free(phystokv(page));
}
void* ttb_freelist;
void ttbpage_free(uint64_t page) {
    disable_interrupts();
    void * ttbp = (phystokv(page));
    *(void**)ttbp = ttb_freelist;
    ttb_freelist = ttbp;
    enable_interrupts();
}

uint64_t ttbpage_alloc() {
    disable_interrupts();
    if (ttb_freelist) {
        void* page = ttb_freelist;
        ttb_freelist = *(void**)page;
        bzero(page, is_16k() ? 0x4000 : 0x1000);
        enable_interrupts();
        return vatophys_static(page);
    }
    enable_interrupts();
    if (is_16k()) {
        return ppage_alloc();
    } else {
        uint64_t page = ppage_alloc();
        for (uint32_t i=0x1000; i < 0x4000; i+=0x1000) {
            ttbpage_free(page + i);
        }
        return page;
    }
}
uint64_t ram_phys_off;
uint64_t ram_phys_size;

uint64_t tt_bits, tg0, t0sz, t1sz;
uint64_t ttb_alloc_base;
volatile uint64_t *ttbr0, *ttbr1;

volatile uint64_t* (*ttb_alloc)(void);

volatile uint64_t* ttb_alloc_early(void)
{
    uint64_t pgsz = 1ULL << (tt_bits + 3ULL);
    ttb_alloc_base -= pgsz;
    volatile uint64_t* rv = (volatile uint64_t*) ttb_alloc_base;
    for(size_t i = 0; i < (pgsz / 8); i++)
    {
        rv[i] = 0;
    }
    return rv;
}

void map_range_map(uint64_t* tt0, uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite, uint64_t paging_info, vm_protect_t prot, bool is_tt1)
{
    // NOTE: Blind assumption that all TT levels support block mappings.
    // Currently we configure TCR that way, we just need to ensure that we will continue to do so.

    uint64_t bits = 64ULL;
    if (is_tt1) {
        bits -= t1sz;
        va -= (0xffffffffffffffff - ((1ULL << (65 - t1sz)) - 1));
        va &= (1ULL << bits) - 1;
    } else {
        bits -= t0sz;
        va &= (1ULL << bits) - 1;
    }

    uint64_t pgsz = 1ULL << (tt_bits + 3ULL);
    if((va & (pgsz - 1ULL)) || (pa & (pgsz - 1ULL)) || (size & (pgsz - 1ULL)) || size < pgsz || (va + size < va) || (pa + size < pa))
    {
        panic("map_range: called with bad arguments (0x%llx, 0x%llx, 0x%llx, ...)", va, pa, size);
    }

    union tte tte;

    volatile uint64_t *tt = (volatile uint64_t*)tt0;
    if((bits - 3) % tt_bits != 0)
    {
        bits += tt_bits - ((bits - 3) % tt_bits);
    }
    while(true)
    {
        uint64_t blksz = 1ULL << (bits - tt_bits),
                 lo = va & ~(blksz - 1ULL),
                 hi = (va + size + (blksz - 1ULL)) & ~(blksz - 1ULL);

        if(size < blksz && hi - lo == blksz) // Sub-block, but fits into single TT
        {
            uint64_t idx = (va >> (bits - tt_bits)) & ((1ULL << tt_bits) - 1ULL);
            tte.u64 = tt[idx];
            if(tte.valid && tte.table)
            {
                tt = (volatile uint64_t*)((uint64_t)tte.oa << 12);
            }
            else if(!tte.valid || overwrite)
            {
                volatile uint64_t *newtt = ttb_alloc();
                tte.u64 = 0;
                tte.valid = 1;
                tte.table = 1;
                tte.oa = (uint64_t)newtt >> 12;
                tt[idx] = tte.u64;
                tt = newtt;
            }
            else
            {
                panic("map_range: trying to map table over existing entry");
            }
            bits -= tt_bits;
            continue;
        }

        while(lo < hi)
        {
            uint64_t sz = blksz;
            if(lo < va)
            {
                sz -= va - lo;
            }
            if(sz > size)
            {
                sz = size;
            }
            if(sz < blksz) // Need to traverse anew
            {
                map_range_map((uint64_t*)tt0, va, pa, sz, sh, attridx, overwrite, paging_info, prot, is_tt1);
            }
            else if((pa & (blksz - 1ULL))) // Cursed case
            {
                uint64_t frag = pa & (blksz - 1ULL);
                map_range_map((uint64_t*)tt0, va, pa, sz - frag, sh, attridx, overwrite, paging_info, prot, is_tt1);
                map_range_map((uint64_t*)tt0, va + sz - frag, pa + sz - frag, frag, sh, attridx, overwrite, paging_info, prot, is_tt1);
            }
            else
            {
                uint64_t idx = (va >> (bits - tt_bits)) & ((1ULL << tt_bits) - 1);
                union tte otte;
                otte.u64 = tt[idx];
                if(otte.valid)
                {
                    if (!overwrite)
                        panic("map_range: trying to map block over existing entry");
                }
                if (prot & PROT_PAGING_INFO) {
                    tte.u64 = paging_info;
                    tte.valid = 0;
                    tte.table = 1;
                    tt[idx] = tte.u64;
                } else {
                    tte.u64 = 0;
                    tte.valid = 1;
                    tte.table = blksz == pgsz ? 1 : 0; // L3
                    tte.attr = attridx;
                    tte.sh = sh;
                    tte.af = 1;

                    tte.oa = pa >> 12;
                    tte.uxn = 1;

                    if (is_tt1) {
                        if (!(prot & PROT_EXEC)) {
                            tte.pxn = 1;
                            tte.uxn = 1;
                        } else {
                            tte.pxn = 0;
                            tte.uxn = 0;
                        }

                        if (!(prot & PROT_WRITE)) {
                            tte.ap |= 0b10;
                        }

                        if (!(prot & PROT_KERN_ONLY)) {
                            tte.ap |= 0b01;
                            tte.pxn = 1;
                        }
                        tte.nG = 1;
                    }
                    if (pa && (prot & PROT_READ)) {
                        if (is_tt1) {
                            phys_reference((tte.oa << 12) & (~0x3fff), (((tte.oa << 12) - ((tte.oa << 12) & (~0x3fff)) + blksz) + 0x3fff) & ~0x3fff);
                        }
                        tt[idx] = tte.u64;
                    } else {
                        tt[idx] = 0;
                    }
                }
                if (otte.valid && otte.table == (blksz == pgsz ? 1 : 0))
                {
                    if (is_tt1) {
                        phys_dereference((otte.oa << 12) & (~0x3fff), (((otte.oa << 12) - ((otte.oa << 12) & (~0x3fff)) + blksz) + 0x3fff) & ~0x3fff);
                    }
                }
            }
            lo += blksz;
            va += sz;
            pa += sz;
            size -= sz;
        }
        break;
    }


}
void map_range_noflush(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite) {
    map_range_map((void*)ttbr0, va, pa, size, sh, attridx, overwrite, 0, PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY, false);
}


void map_range(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite)
{
    map_range_noflush(va, pa, size, sh, attridx, overwrite);
    flush_tlb();
}

void map_full_ram(uint64_t phys_off, uint64_t phys_size) {
    // Round up to make sure the framebuffer is in range
    uint64_t pgsz = 1ULL << (tt_bits + 3);
    phys_size = (phys_size + pgsz - 1) & ~(pgsz - 1);

    map_range_noflush(kCacheableView + phys_off, 0x800000000 + phys_off, phys_size, 3, 1, true);
    map_range_noflush(0x800000000ULL + phys_off, 0x800000000 + phys_off, phys_size, 2, 0, true);
    ram_phys_off = kCacheableView + phys_off;
    ram_phys_size = phys_size;
    flush_tlb();
}

void lowlevel_setup(uint64_t phys_off, uint64_t phys_size)
{
    if (is_16k()) {
        tt_bits = 11;
        tg0 = 0b10;
        t0sz = 28;
        t1sz = 28;
    } else {
        tt_bits = 9;
        tg0 = 0b00;
        t0sz = 25;
        t1sz = 25;
    }
    uint64_t pgsz = 1ULL << (tt_bits + 3);
    ttb_alloc = ttb_alloc_early;

    ttb_alloc_base = MAGIC_BASE - 0x4000;

    ttbr0 = ttb_alloc();
    ttbr1 = ttb_alloc();
    map_range_noflush(0x200000000, 0x200000000, 0x100000000, 2, 0, false);
    phys_off += (pgsz-1);
    phys_off &= ~(pgsz-1);
    map_range_noflush(kCacheableView + phys_off, 0x800000000 + phys_off, phys_size, 3, 1, false);
    map_range_noflush(0x800000000ULL + phys_off, 0x800000000 + phys_off, phys_size, 2, 0, false);
    // TLB flush is done by enable_mmu_el1

    ram_phys_off = kCacheableView + phys_off;
    ram_phys_size = phys_size;

    if (!(get_el() == 1)) panic("pongoOS runs in EL1 only! did you skip pongoMon?");

    set_vbar_el1((uint64_t)&exception_vector);
    enable_mmu_el1((uint64_t)ttbr0, 0x13A402A00 | (tg0 << 14) | (tg0 << 30) | (t1sz << 16) | t0sz, 0x04ff00, (uint64_t)ttbr1);

    kernel_vm_space.ttbr0 = (uint64_t)ttbr0;
    kernel_vm_space.ttbr1 = (uint64_t)ttbr1;
}

void lowlevel_cleanup(void)
{
    cache_clean_and_invalidate((void*)ram_phys_off, ram_phys_size);
    disable_mmu_el1();
}
struct vm_space* task_vm_space(struct task* task) {
    return task->vm_space;
}
err_t map_physical_range(struct vm_space* vmspace, uint64_t* va, uint64_t pa, uint32_t size, vm_flags_t flags, vm_protect_t prot) {
    uint64_t addr = *va;
    err_t rv = vm_allocate(vmspace, &addr, size, flags | VM_FLAGS_NOMAP);
    if (rv) return rv;
    
    uint32_t pagecount = ((size + PAGE_MASK) & ~PAGE_MASK) / PAGE_SIZE;
    for (uint32_t i=0; i < pagecount; i ++) {
        vm_space_map_page_physical_prot(vmspace, addr + i * PAGE_SIZE, pa + i * PAGE_SIZE, prot);
    }
    
    return KERN_SUCCESS;
}

err_t vm_allocate(struct vm_space* vmspace, uint64_t* addr, uint64_t size, vm_flags_t flags) {
    err_t retn = KERN_VM_OOM;
    
    uint32_t pagecount = ((size + PAGE_MASK) & ~PAGE_MASK) / PAGE_SIZE;
    if (!pagecount) return 0;
    disable_interrupts();
    uint32_t vm_scan_base = 0;
    uint64_t vm_scan_size = (VM_SPACE_SIZE / PAGE_SIZE);
    uint32_t found_pages = 0;
    uint32_t vm_index_start = 0;
    
    if (flags & VM_FLAGS_FIXED) {
        uint64_t vm_offset = *addr - vmspace->vm_space_base;
        if (vm_offset > vmspace->vm_space_end) vm_scan_size = 0;
        else {
            vm_index_start = vm_offset / PAGE_SIZE;
            vm_scan_size = ((size + PAGE_MASK) & ~PAGE_MASK) / PAGE_SIZE;
        }
    } else {
        // VM_FLAGS_ANYWHERE
    }
    
    for (uint32_t i=0; i < vm_scan_size; i ++) {
        uint8_t is_alloc = ((vmspace->vm_space_table[i >> 3]) >> (i & 7)) & 1;
        if (!is_alloc) {
            if (!found_pages) {
                vm_scan_base = i;
            }
            found_pages++;
        } else {
            found_pages = 0;
        }
        
        if (found_pages == pagecount) {
            retn = KERN_SUCCESS;
            break;
        }
    }

    if (retn == KERN_SUCCESS) {
        for (uint32_t i=vm_scan_base; i < vm_scan_base + pagecount; i ++) {
            if (!(flags & VM_FLAGS_NOMAP))
                vm_space_map_page_physical_prot(vmspace, vmspace->vm_space_base + i * PAGE_SIZE, PAGING_INFO_ALLOC_ON_FAULT_MAGIC, PROT_PAGING_INFO);
            vmspace->vm_space_table[i >> 3] |= 1 << (i & 7);
        }
        *addr = vmspace->vm_space_base + vm_scan_base * PAGE_SIZE;
    } else {
        *addr = 0;
    }
    
    enable_interrupts();
    return retn;
}
err_t vm_deallocate(struct vm_space* vmspace, uint64_t addr, uint64_t size) {
    err_t retn = KERN_VM_OOM;
    disable_interrupts();
    uint64_t vm_offset = addr - vmspace->vm_space_base;
    if (!((vm_offset + size) > vmspace->vm_space_end)) {
        uint32_t pagecount = ((size + PAGE_MASK) & ~PAGE_MASK) / PAGE_SIZE;
        retn = KERN_SUCCESS;
        uint32_t vm_scan_base = vm_offset / PAGE_SIZE;
        for (uint32_t i=vm_scan_base; i < vm_scan_base + pagecount; i ++) {
            uint8_t is_alloc = ((vmspace->vm_space_table[i >> 3]) >> (i & 7)) & 1;
            if (!is_alloc) {
                retn = KERN_FAILURE;
                break;
            }
        }
        if (retn == KERN_SUCCESS) {
            for (uint32_t i=vm_scan_base; i < vm_scan_base + pagecount; i ++) {
                vm_space_map_page_physical_prot(vmspace, vmspace->vm_space_base + i * PAGE_SIZE, 0, 0); // free physical
                vmspace->vm_space_table[i >> 3] &= ~(1 << (i & 7));
            }
        }
    }
    enable_interrupts();
    return retn;
}
struct vm_space kernel_vm_space = {
    .refcount = TASK_REFCOUNT_GLOBAL,
    .vm_space_base = VM_SPACE_BASE,
    .vm_space_end = VM_SPACE_BASE + VM_SPACE_SIZE
};
err_t vm_space_map_page_physical_prot(struct vm_space* vmspace, uint64_t vaddr, uint64_t physical, vm_protect_t prot) {
    disable_interrupts();

    if (vmspace == &kernel_vm_space) prot |= PROT_KERN_ONLY;

    if (vaddr & 0x7000000000000000) {
        if ((physical & 0x3fff) && !(prot & PROT_PAGING_INFO)) {
            panic("passed unaligned PA %llx to vm_space_map_page_physical_prot", physical);
        }
        map_range_map((uint64_t*)vmspace->ttbr1, vaddr, prot & PROT_PAGING_INFO ? 0 : physical, 0x4000, prot & PROT_DEVICE ? 3 : 2, prot & PROT_DEVICE ? 0 : 1, 1, prot & PROT_PAGING_INFO ? physical : 0, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY|PROT_PAGING_INFO), true);
        if (!(prot & PROT_PAGING_INFO))
            phys_dereference(physical, 0x4000); // consume reference (map_range_map will take a reference if successful)
    } else {
        map_range_map((uint64_t*)vmspace->ttbr0, vaddr, prot & PROT_PAGING_INFO ? 0 : physical, 0x4000, prot & PROT_DEVICE ? 3 : 2, prot & PROT_DEVICE ? 0 : 1, 1, prot & PROT_PAGING_INFO ? physical : 0, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY|PROT_PAGING_INFO), false);
        // do not dereference the phys, ttbr0 does not keep track of references in map_range_map.
    }
    if (is_16k_v) {
        vm_flush_by_addr(vmspace, vaddr);
    } else {
        for (uint32_t i=0; i < 0x4000; i+=0x1000) {
            vm_flush_by_addr(vmspace, vaddr + i);
        }
    }
    
    enable_interrupts();
    return KERN_SUCCESS;
}
uint8_t asid_table[256/8];
uint64_t asid_alloc() {
    disable_interrupts();
    for (uint32_t i=0; i < 256; i++) {
        bool is_alloc = !!(asid_table[i>>3] & (1 << (i&0x7)));
        if (!is_alloc) {
            asid_table[i>>3] |= (1 << (i&0x7));
            enable_interrupts();
            //fiprintf(stderr, "allocating asid: %llx\n", ((uint64_t) i) << 48ULL);

            return ((uint64_t) i) << 48ULL;
        }
    }
    panic("asid_alloc: out of ASIDs, are we leaking vm_spaces?");
    return 0;
}
void asid_free(uint64_t asid) {
    uint32_t index = ((uint64_t) asid) >> 48ULL;
    index &= 0xff;
    
    bool is_alloc = !!(asid_table[index>>3] & (1 << (index&0x7)));
    if (!is_alloc) panic("ASID was not allocated?!");
#if DEBUG_REFCOUNT
    fiprintf(stderr, "freeing asid: %llx\n", asid);
#endif
    asid_table[index >> 3] &= ~(1 << (index&0x7));
    asm volatile("ISB");
    asm volatile("TLBI ASIDE1IS, %0" : : "r"(asid));
    asm volatile("DSB SY");
}
void vm_flush(struct vm_space* fl) {
    asm volatile("ISB");
    asm volatile("TLBI ASIDE1IS, %0" : : "r"(fl->asid));
    asm volatile("DSB SY");
}
void vm_flush_by_addr(struct vm_space* fl, uint64_t va) {
    asm volatile("ISB");
    asm volatile("TLBI ASIDE1IS, %0" : : "r"(fl->asid | (va & 0xfffffffff000)));
    asm volatile("DSB SY");
}
void vm_init() {
    if(kernel_vm_space.vm_space_table) panic("vm_init misuse");
    
    asid_table[0] |= 1; // reserve kernel ASID
    is_16k_v = is_16k();
    
    task_current()->vm_space = &kernel_vm_space;
    kernel_vm_space.vm_space_table = alloc_contig((VM_SPACE_SIZE / PAGE_SIZE) / 8);
    bzero(kernel_vm_space.vm_space_table, (VM_SPACE_SIZE / PAGE_SIZE) / 8);
    extern volatile uint64_t* (*ttb_alloc)(void);
    ttb_alloc =  (void*)ttbpage_alloc;
}
struct vm_space* vm_create(struct vm_space* parent) {
    struct vm_space* space = malloc(sizeof(struct vm_space));
    bzero(space, sizeof(*space));
    space->vm_space_base = VM_SPACE_BASE;
    space->vm_space_end = VM_SPACE_BASE + VM_SPACE_SIZE;
    if (parent) {
        space->ttbr0 = parent->ttbr0;
    } else {
        space->ttbr0 = kernel_vm_space.ttbr0;
    }
    space->ttbr1 = ttbpage_alloc();
    space->asid = asid_alloc();
    space->parent = vm_reference(parent); // consume ref
    space->vm_space_table = malloc((VM_SPACE_SIZE / PAGE_SIZE) / 8);
    bzero(space->vm_space_table, (VM_SPACE_SIZE / PAGE_SIZE) / 8);
    space->refcount = 1;
    return space;
}
struct vm_space* vm_reference(struct vm_space* vmspace) {
    if (!vmspace) return vmspace;
    if (vmspace->refcount == TASK_REFCOUNT_GLOBAL) return vmspace;
    __atomic_fetch_add(&vmspace->refcount, 1, __ATOMIC_SEQ_CST);
    return vmspace;
}

#define PAGE_FREE 0
#define PAGE_WIRED 0xffffff
#define PAGE_REFBITS 0xffffff

uint32_t* ppage_list;

uint64_t alloc_static_base = 0;
uint64_t alloc_static_current = 0;
uint64_t alloc_static_end = 0;
uint64_t topkd = 0;
uint64_t ppages = 0;
uint64_t free_pages = 0;
uint64_t wired_pages = 0;
uint32_t phys_get_entry(uint64_t pa) {
    pa -= gBootArgs->physBase;
    if (pa & 0x3fff) panic("mark_phys_wired only works with aligned PAs");
    pa >>= 14;
    if (pa > ppages) panic("OOB phys_get_entry: 0x%llx", pa << 14ULL);
    return ppage_list[pa];
}
void phys_set_entry(uint64_t pa, uint32_t val) {
    pa -= gBootArgs->physBase;
    if (pa & 0x3fff) panic("mark_phys_wired only works with aligned PAs");
    pa >>= 14;
    if (pa > ppages) panic("OOB phys_set_entry: 0x%llx", pa << 14ULL);
    ppage_list[pa] = val;
}
void mark_phys_wired(uint64_t pa, uint64_t size) {
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("mark_phys_wired only works with aligned PAs");
    pa >>= 14;
    
    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB mark_phys_wired: 0x%llx", i << 14ULL);
        ppage_list[i] = (ppage_list[i] & ~PAGE_REFBITS) | PAGE_WIRED;
        free_pages--;
        wired_pages++;
    }
    enable_interrupts();
}
void phys_force_free(uint64_t pa, uint64_t size) {
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("phys_force_free only works with aligned PAs");
    pa >>= 14;
    
    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_force_free: 0x%llx", i << 14ULL);
        if ((ppage_list[i] & PAGE_REFBITS) == PAGE_WIRED) {
            wired_pages--;
        }
        if ((ppage_list[i] & PAGE_REFBITS) != PAGE_FREE) {
            free_pages ++;
        }
        ppage_list[i] = PAGE_FREE;
    }
    enable_interrupts();
}
void phys_reference(uint64_t pa, uint64_t size) {
    if (!pa) return;
    if (pa < gBootArgs->physBase) return; // ignore for I/O map, sram, etc...
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("phys_reference only works with aligned PAs");
    pa >>= 14;
    
    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_reference: 0x%llx", i << 14ULL);
        if ((ppage_list[i] & PAGE_REFBITS) != PAGE_WIRED) {
            if ((ppage_list[i] & PAGE_REFBITS) == PAGE_FREE) {
                free_pages--;
            }
            ppage_list[i] = (ppage_list[i] & ~PAGE_REFBITS) | ((ppage_list[i] + 1) & PAGE_REFBITS);
        }
    }
    enable_interrupts();
}
void phys_dereference(uint64_t pa, uint64_t size) {
    if (!pa) return;
    if (pa < gBootArgs->physBase) return; // ignore for I/O map, sram, etc...
    uint64_t fpa = pa;
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14ULL;
    if (pa & 0x3fff) panic("phys_dereference only works with aligned PAs (was passed %llx)", pa + gBootArgs->physBase);
    pa >>= 14ULL;

    disable_interrupts();
    
    if (fpages == 1) { // fastpath: if we are freeing a single page, and there's place in the page_alloc() freelist, push it there. we avoid larger allocations to avoid fragmentation, if we have less than a given threshold.
        if (pages_in_freelist < MAX_WANT_PAGES_IN_FREELIST) {
            if (pa > ppages) panic("OOB phys_reference: 0x%llx", pa << 14ULL);
            if ((ppage_list[pa] & PAGE_REFBITS) == 1) {
                ppage_free(fpa);
                enable_interrupts();
                return;
            }
        }
    }
    
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_dereference: 0x%llx", i << 14ULL);
        if ((ppage_list[i] & PAGE_REFBITS) != PAGE_FREE) {
            ppage_list[i] = (ppage_list[i] & ~PAGE_REFBITS) | ((ppage_list[i] - 1) & PAGE_REFBITS);
            if ((ppage_list[i] & PAGE_REFBITS) == PAGE_FREE) {
                free_pages++;
            }
        } else panic("phys_dereference called on PAGE_FREE page @ 0x%llx", i << 14ULL);
    }
    enable_interrupts();
}


void alloc_init() {
    if (alloc_static_base) return;
    
    extern uint64_t __bss_end[] __asm__("segment$end$__DATA");
    uint64_t memory_size = gBootArgs->memSize;
    ppages = memory_size >> 14;
    
    uint64_t early_heap = ((((uint64_t)__bss_end) + 0x7fff) & (~0x3fff));
#ifdef AUTOBOOT
    uint64_t* _autoboot_block = (uint64_t*)0x419000000;
    extern uint64_t* autoboot_block;
    if (_autoboot_block[0] == 0x746F6F626F747561) {
        autoboot_block = (void*) early_heap;
        memcpy(autoboot_block, _autoboot_block, _autoboot_block[1] + 0x20);
        early_heap += _autoboot_block[1] + 0x20;
        early_heap = ((early_heap + 0x3fff) & (~0x3fff));
        bzero(_autoboot_block, _autoboot_block[1] + 0x20);
    }
#endif
    
    ppage_list = (uint32_t*)early_heap;
    early_heap += 4 * ppages;
    early_heap = ((early_heap + 0x3fff) & (~0x3fff));
    for (uint64_t i=0; i < ppages; i++) {
        wired_pages++;
        ppage_list[i] = PAGE_WIRED; // wire all pages, carve out later.
    }
    if (0x817fe0000ULL > vatophys_static((void*)(__bss_end))) {
        panic("invalid pongo setup!!");
    }

    alloc_static_current = alloc_static_base = (kCacheableView - 0x800000000 + gBootArgs->topOfKernelData) & (~0x3fff);
    alloc_static_end = 0x417fe0000;
    uint64_t alloc_static_hardcap = alloc_static_base + (1024 * 1024 * 64);
    if (alloc_static_end > alloc_static_hardcap) {
        phys_force_free(vatophys_static((void*)alloc_static_hardcap), alloc_static_end - alloc_static_hardcap);
        alloc_static_end = alloc_static_hardcap;
    }
    
    uint64_t alloc_heap_base = (((uint64_t)early_heap) + 0x7fff) & (~0x3fff);
    uint64_t alloc_heap_end = (((uint64_t)(phystokv(gBootArgs->physBase) + gBootArgs->memSize)) + 0x3fff) & (~0x3fff) - 1024*1024;

    phys_force_free(vatophys_static((void*)alloc_heap_base), alloc_heap_end - alloc_heap_base);
}
void* alloc_static(uint32_t size) { // memory returned by this will be added to the xnu static region, thus will persist after xnu boot
    if (!alloc_static_base) {
        alloc_init();
    }
    void* rv = (void*)alloc_static_current;
    alloc_static_current += (size + 0x3fff) & (~0x3fff);
    if (alloc_static_current > alloc_static_end) panic("ran out of static region");
    gBootArgs->topOfKernelData += (size + 0x3fff) & (~0x3fff);
    return rv;
}
uint64_t alloc_phys_direct(uint32_t size) {
    if (!alloc_static_base) {
        alloc_init();
    }
    size = (size + 0x3fff) & ~0x3fff;
    uint32_t npages = size / 0x4000;
    uint32_t found_pages = 0;

    bool found = false;
    uint64_t rv = 0;
    disable_interrupts();
    
    for (uint64_t i=0; i < ppages; i++) {
        if (ppage_list[i] == PAGE_FREE) {
            if (!found_pages) {
                rv = (i << 14ULL) + gBootArgs->physBase;
            }
            found_pages ++;
        } else {
            found_pages = 0;
        }
        if (found_pages == npages) {
            // found
            found = true;
            break;
        }
    }
    if (!found) panic("alloc_phys: OOM");
    if (!rv) panic("alloc_phys: returning NULL?? (size %llx, npages %llx, found_pages %llx)", size, npages, found_pages);
    phys_reference(rv, size);
    enable_interrupts();
    return rv;
}
uint64_t alloc_phys(uint32_t size) {
    size = (size + 0x3fff) & ~0x3fff;
    uint32_t npages = size / 0x4000;
    uint64_t rv = 0;
    disable_interrupts();
    if (npages == 1) {
        rv = ppage_alloc_from_freelist();
        if (rv) {
            enable_interrupts();
            return rv;
        }
    }
    rv = alloc_phys_direct(size);
    enable_interrupts();
    return rv;
}
void free_phys(uint64_t pa, uint32_t size) {
    phys_dereference(pa, size);
}
void* alloc_contig(uint32_t size) {
    return phystokv(alloc_phys(size));
}
void* alloc_contig_direct(uint32_t size) {
    return phystokv(alloc_phys_direct(size));
}
void free_contig(void* base, uint32_t size) {
    free_phys(vatophys_static(base), size);
}
void* phystokv(uint64_t paddr) {
    return (void*)(paddr - 0x800000000 + kCacheableView);
}
uint64_t vatophys_static(void* kva) {
    uint64_t kva_check = (uint64_t) kva;
    if (!((kva_check >= kCacheableView) && (kva_check < (kCacheableView + 0x100000000)))) {
        panic("vatophys_static must be called on kCacheableView map addresses");
    }
    return (((uint64_t)kva) - kCacheableView + 0x800000000);
}

void ttbpage_free_walk_recursive(uint64_t base, bool is_tt1, int levels, int ttcount) {
    uint64_t* tt = phystokv(base);
    union tte tte;
    for (int i=0; i < ttcount; i++) {
        tte.u64 = tt[i];
        if (tte.valid) {
            if (tte.table == 1 && levels) {
                // table mapping, keep walking
                ttbpage_free_walk_recursive(tte.oa << 12, is_tt1, levels - 1, ttcount);
                ttbpage_free(tte.oa << 12);
            } else if (tte.table == (levels ? 0 : 1)) {
                // block mapping, free phys
                uint64_t blksz = is_16k_v ? 14 : 12;
                blksz += levels * tt_bits;
                blksz = 1ULL << blksz;
                phys_dereference((tte.oa << 12) & (~0x3fff), (((tte.oa << 12) - ((tte.oa << 12) & (~0x3fff)) + blksz) + 0x3fff) & ~0x3fff);
            }
        }
    }
}
void ttbpage_free_walk(uint64_t base, bool is_tt1) {
    int ttcount = is_16k_v ? 0x4000/8 : 0x1000/8;
    int obits = is_16k_v ? 14 : 12;
    uint32_t bits = 64 - (is_tt1 ? t1sz : t0sz);
    bits -= obits; // remove offset
    ttbpage_free_walk_recursive(base, is_tt1, (bits / tt_bits) - 1, ttcount);
    ttbpage_free(base);
}
bool tte_walk_get(struct vm_space* vmspace, uint64_t va, uint64_t** tte_out) {
    uint64_t bits = 64ULL;
    bool is_tt1 = false;
    uint64_t* ttb = NULL;
    if (va & 0x7000000000000000) {
        bits -= t1sz;
        va -= (0xffffffffffffffff - ((1ULL << (65 - t1sz)) - 1));
        va &= (1ULL << bits) - 1;
        is_tt1 = true;
        ttb = phystokv(vmspace->ttbr1);
    } else {
        bits -= t0sz;
        va &= (1ULL << bits) - 1;
        is_tt1 = false;
        ttb = phystokv(vmspace->ttbr0);
    }
    uint32_t levels = ((bits - (tt_bits + 3ULL)) / tt_bits);
    union tte tte;
    while (levels) {
        uint64_t idx = (va >> (bits - tt_bits)) & ((1ULL << tt_bits) - 1);
        tte.u64 = ttb[idx];
        if (tte.valid && tte.table == 1 && levels != 1) {
            ttb = phystokv(tte.oa << 12);
        } else if (tte.valid == 0 && tte.table == 1) {
            // tte with PAGING_INFO!
            *tte_out = &ttb[idx];
            return true;
        } else if (tte.valid && tte.table == (levels == 1 ? 1 : 0)) {
            // block tte
            *tte_out = &ttb[idx];
            return true;
        }
        bits -= tt_bits;
        levels--;
    }
    return false;
}
uint64_t paging_requests = 0;
bool vm_fault(struct vm_space* vmspace, uint64_t vma, vm_protect_t fault_prot) {
    disable_interrupts();
    if (vma >= vmspace->vm_space_base && vma < vmspace->vm_space_end) {
        // only MM managed ranges may handle page faults gracefully
        uint64_t vm_offset = vma - vmspace->vm_space_base;
        bool is_vm_mapped = vmspace->vm_space_table[vm_offset >> 3] |= 1 << (vm_offset & 7);
        if (is_vm_mapped) {
            // optimization: don't do a page walk if the VM is not mapped.
            union tte tte;
            uint64_t* ttep;
            if (tte_walk_get(vmspace, vma & ~0x3fff, &ttep) == true) {
                tte.u64 = *ttep;
                if (tte.valid == 0 && tte.table == 1) {
                    tte.table = 0;
                    if (tte.u64 == PAGING_INFO_ALLOC_ON_FAULT_MAGIC) {
                        //fiprintf(stderr, "should allocate physical for %llx\n", vma);
                        paging_requests++;
                        vm_space_map_page_physical_prot(vmspace, vma & ~0x3fff, ppage_alloc(), PROT_READ|PROT_WRITE|PROT_EXEC);
                        enable_interrupts();
                        return true;
                    }
                }
            }
        }
    }
    enable_interrupts();
    return false;
}
void vm_release(struct vm_space* vmspace) {
    if (!vmspace) return;
    if (vmspace->refcount == TASK_REFCOUNT_GLOBAL) return;
    uint32_t refcount = __atomic_fetch_sub(&vmspace->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
        if (vmspace->parent == vmspace) panic("circular reference");
#if DEBUG_REFCOUNT
        fiprintf(stderr, "freeing vmspace: %p\n", vmspace);
#endif
        vm_release(vmspace->parent);
        ttbpage_free_walk(vmspace->ttbr1 & 0xfffffffff000, true);
        asid_free(vmspace->asid);
        free(vmspace->vm_space_table);
        free(vmspace);
    }
}
