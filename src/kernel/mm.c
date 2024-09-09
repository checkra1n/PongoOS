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
#include <errno.h>
#include <stdlib.h>
#include <pongo.h>

#define MAX_WANT_PAGES_IN_FREELIST 512
void* free_list;
bool is_16k_v = false;
void* page_alloc() {
    return phystokv(ppage_alloc());
}
void page_free(void* page) {
    phys_dereference(vatophys_static(page), PAGE_SIZE);
}
void ppage_free(uint64_t page) {
    phys_dereference(page, PAGE_SIZE);
}
void* ttb_freelist;
void ttbpage_free(uint64_t page) {
    disable_interrupts();
    void * ttbp = (phystokv(page));
    *(void**)ttbp = ttb_freelist;
    ttb_freelist = ttbp;
    enable_interrupts();
}

uint64_t ttbpage_alloc(void) {
    disable_interrupts();
    if (ttb_freelist) {
        void* page = ttb_freelist;
        ttb_freelist = *(void**)page;
        enable_interrupts();

        bzero(page, is_16k() ? 0x4000 : 0x1000);
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
uint64_t tt_bits, tg0, tg1, t0sz, t1sz;
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
        panic("map_range: called with bad arguments (0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", ...)", va, pa, size);
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

                    if (!(prot & PROT_EXEC)) {
                        tte.pxn = 1;
                    } else {
                        tte.pxn = 0;
                    }

                    if (!(prot & PROT_WRITE)) {
                        tte.ap |= 0b10;
                    }

                    if (is_tt1) {
                        if (!(prot & PROT_KERN_ONLY)) {
                            tte.ap |= 0b01;
                            tte.pxn = 1;
                        }
                        if (prot & PROT_EXEC) {
                            tte.uxn = 0;
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
    map_range_map((void*)ttbr0, va, pa, size, sh, attridx, overwrite, 0, PROT_READ|PROT_WRITE|PROT_KERN_ONLY, false);
}

void map_range_noflush_rw(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite) {
    map_range_map((void*)ttbr0, va, pa, size, sh, attridx, overwrite, 0, PROT_READ|PROT_WRITE|PROT_KERN_ONLY, false);
}

void map_range_noflush_rwx(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite) {
    map_range_map((void*)ttbr0, va, pa, size, sh, attridx, overwrite, 0, PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY, false);
}

void map_range_noflush_rx(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite) {
    map_range_map((void*)ttbr0, va, pa, size, sh, attridx, overwrite, 0, PROT_READ|PROT_EXEC|PROT_KERN_ONLY, false);
}


void map_range(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite)
{
    map_range_noflush(va, pa, size, sh, attridx, overwrite);
    flush_tlb();
}

uint64_t g_phys_off;
void map_full_ram(uint64_t phys_off, uint64_t phys_size) {
    // Round up to make sure the framebuffer is in range
    uint64_t pgsz = 1ULL << (tt_bits + 3);
    phys_size = (phys_size + pgsz - 1) & ~(pgsz - 1);

    map_range_noflush_rw(kCacheableView + phys_off, 0x800000000 + phys_off, phys_size, 3, 1, true);
    map_range_noflush_rw(0x800000000ULL + phys_off, 0x800000000 + phys_off, phys_size, 2, 0, true);
    ram_phys_off = kCacheableView + phys_off;
    ram_phys_size = phys_size;
    g_phys_off = phys_off;
    flush_tlb();
}
uint64_t gPongoSlide;
void lowlevel_setup(uint64_t phys_off, uint64_t phys_size)
{
    if (is_16k()) {
        tt_bits = 11;
        tg0 = 0b10; // 16K
        tg1 = 0b01; // 16K
        t0sz = 28;
        t1sz = 28;
    } else {
        tt_bits = 9;
        tg0 = 0b00; // 4K
        tg1 = 0b10; // 4K
        t0sz = 25;
        t1sz = 25;
    }
    uint64_t pgsz = 1ULL << (tt_bits + 3);
    ttb_alloc = ttb_alloc_early;
    volatile extern uint64_t start[] __asm__("start");
    volatile uint64_t pongo_base = ((uint64_t) start);
    volatile extern uint64_t __bss_end[] __asm__("segment$end$__DATA");
    volatile uint64_t pongo_size = ((uint64_t) __bss_end) - pongo_base;
    volatile extern uint64_t __text_end[] __asm__("segment$start$__DATA");
    volatile uint64_t pongo_text_size = ((uint64_t) __text_end) - pongo_base;

    ttb_alloc_base = (gBootArgs->physBase + gBootArgs->memSize) & ~(pgsz-1);

    ttbr0 = ttb_alloc();
    ttbr1 = ttb_alloc();
    map_range_noflush_rwx(0x180000000, 0x180000000, 0x80000, 2, 0, false);
    map_range_noflush_rw(0x200000000, 0x200000000, 0x100000000, 2, 0, false);
    phys_off += (pgsz-1);
    phys_off &= ~(pgsz-1);
    map_range_noflush_rw(kCacheableView + phys_off, 0x800000000 + phys_off, phys_size, 3, 1, false);
    map_range_noflush_rwx(0x800000000ULL + phys_off, 0x800000000 + phys_off, phys_size, 2, 0, false);
    // TLB flush is done by enable_mmu_el1

    map_range_noflush_rx(0x100000000ULL, pongo_base, pongo_text_size, 3, 1, false);
    map_range_noflush_rw(0x100000000ULL + pongo_text_size, pongo_base + pongo_text_size, (pongo_size - pongo_text_size + 0x3fff) & ~0x3fff, 3, 1, false);
    gPongoSlide = 0x100000000ULL - pongo_base;
    ram_phys_off = kCacheableView + phys_off;
    ram_phys_size = phys_size;

    if (!(get_el() == 1)) panic("pongoOS runs in EL1 only! did you skip pongoMon?");

    set_vbar_el1((uint64_t)&exception_vector);
    enable_mmu_el1((uint64_t)ttbr0, 0x13A402A00 | (tg0 << 14) | (tg1 << 30) | (t1sz << 16) | t0sz, 0x04ff00, (uint64_t)ttbr1);

    kernel_vm_space.ttbr0 = (uint64_t)ttbr0;
    kernel_vm_space.ttbr1 = (uint64_t)ttbr1;
}
void lowlevel_set_identity(void)
{
    map_range_noflush_rwx(0x180000000, 0x180000000, 0x80000, 2, 0, true);
    map_range_noflush_rwx(0x800000000ULL + g_phys_off, 0x800000000 + g_phys_off, ram_phys_size, 2, 0, true);
    flush_tlb();
}
void lowlevel_cleanup(void)
{
    cache_clean_and_invalidate_all();
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
    //uint32_t vm_index_start = 0;

    if (flags & VM_FLAGS_FIXED) {
        uint64_t vm_offset = *addr - vmspace->vm_space_base;
        if (vm_offset > vmspace->vm_space_end) vm_scan_size = 0;
        else {
            //vm_index_start = vm_offset / PAGE_SIZE;
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

uint64_t linear_kvm_base   = 0x120000000;
uint64_t linear_kvm_cursor = 0x120000000;
uint64_t linear_kvm_end    = 0x180000000;
uint64_t linear_kvm_alloc(uint32_t size) {
    uint64_t va = 0;
    size +=  0x3FFF;
    size &= ~0x3FFF;

    if ((linear_kvm_cursor + size) > linear_kvm_end) panic("linear_kvm_alloc: OOM");

    disable_interrupts();
    va = linear_kvm_cursor;
    linear_kvm_cursor += size;
    enable_interrupts();
    return va;
}
void* jit_alloc(uint32_t size) {
    size +=  8;
    size +=  0x3FFF;
    size &= ~0x3FFF;
    uint64_t va = linear_kvm_alloc(size);

    uint64_t mapped_so_far = 0;
    while (size) {
        uint64_t page = ppage_alloc();
        vm_space_map_page_physical_prot(&kernel_vm_space, va + mapped_so_far, page, PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY);
        size -= 0x4000;
        mapped_so_far += 0x4000;
    }

    *(uint32_t*)(va) = size;

    return (void*)(va + 4);
}
void jit_free(void* alloc) {
    if ((((uint64_t)alloc) & 0x3fff) != 0x4) panic("jit_free: invalid pointer passed");
    uint32_t size = *(uint32_t*)(alloc - 4);
    if ((((uint64_t)size) & 0x3fff) != 0) panic("jit_free: invalid pointer passed: misaligned size in header");

    uint64_t va = (uint64_t)(alloc);
    va -= 4;

    uint64_t mapped_so_far = 0;
    while (size) {
        vm_space_map_page_physical_prot(&kernel_vm_space, va + mapped_so_far, 0, 0);
        size -= 0x4000;
        mapped_so_far += 0x4000;
    }
}
err_t vm_space_map_page_physical_prot(struct vm_space* vmspace, uint64_t vaddr, uint64_t physical, vm_protect_t prot) {
    disable_interrupts();

    if (vmspace == &kernel_vm_space) prot |= PROT_KERN_ONLY;

    if (vaddr & 0x7000000000000000) {
        if ((physical & 0x3fff) && !(prot & PROT_PAGING_INFO)) {
            panic("passed unaligned PA %" PRIx64 " to vm_space_map_page_physical_prot", physical);
        }
        map_range_map((uint64_t*)vmspace->ttbr1, vaddr, prot & PROT_PAGING_INFO ? 0 : physical, 0x4000, prot & PROT_DEVICE ? 3 : 2, prot & PROT_DEVICE ? 0 : 1, 1, prot & PROT_PAGING_INFO ? physical : 0, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY|PROT_PAGING_INFO), true);
        if (!(prot & PROT_PAGING_INFO))
            phys_dereference(physical, 0x4000); // consume reference (map_range_map will take a reference if successful)

        if (is_16k_v) {
            vm_flush_by_addr(vmspace, vaddr);
        } else {
            for (uint32_t i=0; i < 0x4000; i+=0x1000) {
                vm_flush_by_addr(vmspace, vaddr + i);
            }
        }
    } else {
        map_range_map((uint64_t*)vmspace->ttbr0, vaddr, prot & PROT_PAGING_INFO ? 0 : physical, 0x4000, prot & PROT_DEVICE ? 3 : 2, prot & PROT_DEVICE ? 0 : 1, 1, prot & PROT_PAGING_INFO ? physical : 0, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY|PROT_PAGING_INFO), false);
        // do not dereference the phys, ttbr0 does not keep track of references in map_range_map.
        if (is_16k_v) {
            vm_flush_by_addr_all_asid(vaddr);
        } else {
            for (uint32_t i=0; i < 0x4000; i+=0x1000) {
                vm_flush_by_addr_all_asid(vaddr + i);
            }
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
            //fiprintf(stderr, "allocating asid: %" PRIx64 "\n", ((uint64_t) i) << 48ULL);

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
    fiprintf(stderr, "freeing asid: %" PRIx64 "\n", asid);
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
    asm volatile("TLBI VAE1, %0" : : "r"(fl->asid | ((va >> 12) & 0xFFFFFFFFFFF)));
    asm volatile("DSB SY");
}
void vm_flush_by_addr_all_asid(uint64_t va) {
    asm volatile("ISB");
    asm volatile("TLBI VAAE1, %0" : : "r"((va >> 12) & 0xFFFFFFFFFFF));
    asm volatile("DSB SY");
}
void vm_init() {
    if(kernel_vm_space.vm_space_table) panic("vm_init misuse");

    asid_table[0] |= 1; // reserve kernel ASID
    is_16k_v = is_16k();

    task_current()->vm_space = &kernel_vm_space;
    kernel_vm_space.vm_space_table = alloc_contig((VM_SPACE_SIZE / PAGE_SIZE) / 8);
    bzero(kernel_vm_space.vm_space_table, (VM_SPACE_SIZE / PAGE_SIZE) / 8);
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
uint64_t ppages = 0;
uint64_t free_pages = 0;
uint64_t wired_pages = 0;
uint32_t phys_get_entry(uint64_t pa) {
    pa -= gBootArgs->physBase;
    if (pa & 0x3fff) panic("phys_get_entry only works with aligned PAs (pa: %" PRIx64 ")", pa);
    pa >>= 14;
    if (pa > ppages) panic("OOB phys_get_entry: 0x%" PRIx64 "", pa << 14ULL);
    return ppage_list[pa];
}
void phys_set_entry(uint64_t pa, uint32_t val) {
    pa -= gBootArgs->physBase;
    if (pa & 0x3fff) panic("phys_get_entry only works with aligned PAs (pa: %" PRIx64 ")", pa);
    pa >>= 14;
    if (pa > ppages) panic("OOB phys_set_entry: 0x%" PRIx64 "", pa << 14ULL);
    ppage_list[pa] = val;
}
uint64_t pa_head;
void phys_unlink_contiguous(uint64_t pa, uint64_t size) {
    if (!pa) return;
    if (pa < gBootArgs->physBase) return; // ignore for I/O map, sram, etc...
    pa -= gBootArgs->physBase;

    size += 0x3fff;
    size &= ~0x3fff;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("phys_unlink_contiguous only works with aligned PAs");
    pa >>= 14;

    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_unlink_contiguous: 0x%" PRIx64 "", i << 14ULL);
        uint64_t* pa_v = phystokv((i << 14ULL) + gBootArgs->physBase);

        if ((phys_get_entry((i << 14ULL) + gBootArgs->physBase) & PAGE_REFBITS) != PAGE_FREE) panic("phys_unlink_contiguous: ppage (pa: %" PRIx64 ") is not free!", (i << 14ULL) + gBootArgs->physBase);

        uint64_t pa_next = pa_v[0];
        uint64_t pa_prev = pa_v[1];

        if (pa_next) {
            if ((phys_get_entry(pa_next) & PAGE_REFBITS) != PAGE_FREE) panic("phys_unlink_contiguous: ppage (next: %" PRIx64 ") is not free!", pa_next);
            uint64_t* pa_next_v = phystokv(pa_next);
            pa_next_v[1] = pa_prev; // unlink
        }
        if (pa_prev) {
            if ((phys_get_entry(pa_prev) & PAGE_REFBITS) != PAGE_FREE) panic("phys_unlink_contiguous: ppage (prev: %" PRIx64 ") is not free!", pa_prev);
            uint64_t* pa_prev_v = phystokv(pa_prev);
            pa_prev_v[0] = pa_next;
        } else {
            pa_head = pa_next;
        }
    }
    enable_interrupts();
}
void mark_phys_wired(uint64_t pa, uint64_t size) {
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("mark_phys_wired only works with aligned PAs (pa: %" PRIx64 ")", pa);
    pa >>= 14;

    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if ((phys_get_entry((i << 14ULL) + gBootArgs->physBase) & PAGE_REFBITS) != PAGE_FREE) panic("mark_phys_wired: ppage (pa: %" PRIx64 ") is not free!", (i << 14ULL) + gBootArgs->physBase);
        if (i > ppages) panic("OOB mark_phys_wired: 0x%" PRIx64 "", i << 14ULL);
        ppage_list[i] = (ppage_list[i] & ~PAGE_REFBITS) | PAGE_WIRED;
        free_pages--;
        wired_pages++;
    }
    enable_interrupts();
}
uint64_t ppage_alloc() {
    uint64_t rv = 0;
    disable_interrupts();
    if (!ppage_list) {
        void alloc_init(void);
        alloc_init();
    }
    if (pa_head) {
        rv = pa_head;
        uint64_t* rv_v = phystokv(rv);
        pa_head = rv_v[0];
        if (pa_head) {
            uint64_t* pa_head_v = phystokv(pa_head);
            pa_head_v[1] = 0;
        }
        bzero(rv_v, PAGE_SIZE);
        phys_reference(rv, PAGE_SIZE);
    } else panic("ppage_alloc: OOM");
    enable_interrupts();
    return rv;
}
void phys_page_was_freed(uint64_t pa) {
    disable_interrupts();
    uint64_t* pa_v = phystokv(pa);
    if (pa_head) {
        uint64_t* pa_head_v = phystokv(pa_head);
        pa_head_v[1] = pa; // head->prev = new
    }
    pa_v[0] = pa_head; // new->next = head
    pa_v[1] = 0; // new->prev == null
    pa_head = pa; // head = new
    free_pages ++;
    enable_interrupts();
}
void phys_force_free(uint64_t pa, uint64_t size) {
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14;
    if (pa & 0x3fff) panic("phys_force_free only works with aligned PAs");
    pa >>= 14;

    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_force_free: 0x%" PRIx64 "", i << 14ULL);
        if ((ppage_list[i] & PAGE_REFBITS) == PAGE_WIRED) {
            wired_pages--;
        }
        if ((ppage_list[i] & PAGE_REFBITS) != PAGE_FREE) {
            phys_page_was_freed((i << 14ULL) + gBootArgs->physBase);
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
        if (i > ppages) panic("OOB phys_reference: 0x%" PRIx64 "", i << 14ULL);
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
    pa -= gBootArgs->physBase;

    uint64_t fpages = size >> 14ULL;
    if (pa & 0x3fff) panic("phys_dereference only works with aligned PAs (was passed %" PRIx64 ")", pa + gBootArgs->physBase);
    pa >>= 14ULL;

    disable_interrupts();
    for (uint64_t i=pa; i < pa+fpages; i++) {
        if (i > ppages) panic("OOB phys_dereference: 0x%" PRIx64 "", i << 14ULL);
        if ((ppage_list[i] & PAGE_REFBITS) != PAGE_FREE) {
            ppage_list[i] = (ppage_list[i] & ~PAGE_REFBITS) | ((ppage_list[i] - 1) & PAGE_REFBITS);
            if ((ppage_list[i] & PAGE_REFBITS) == PAGE_FREE) {
                phys_page_was_freed((i << 14ULL) + gBootArgs->physBase);
            }
        } else panic("phys_dereference called on PAGE_FREE page @ 0x%" PRIx64 "", i << 14ULL);
    }
    enable_interrupts();
}

void alloc_init() {
    if (ppage_list) {
        return;
    }

    uint64_t memory_size = gBootArgs->memSize;
    ppages = memory_size >> 14;

    ttb_alloc = (volatile uint64_t* (*)(void))ttbpage_alloc;
    uint64_t early_heap = ttb_alloc_base - 0x800000000 + kCacheableView;

    early_heap = (early_heap - 4 * ppages) & ~0x3fffULL;
    ppage_list = (uint32_t*)early_heap;
    for (uint64_t i = 0; i < ppages; i++) {
        wired_pages++;
        ppage_list[i] = PAGE_WIRED; // wire all pages, carve out later.
    }

    uint64_t alloc_heap_base = ((gTopOfKernelData - 0x800000000 + kCacheableView) + 0x3fffULL) & ~0x3fffULL;
    uint64_t alloc_heap_end = early_heap;

    phys_force_free(vatophys_static((void*)alloc_heap_base), alloc_heap_end - alloc_heap_base);
}
void* alloc_static(uint32_t size) { // memory returned by this will be added to the xnu static region, thus will persist after xnu boot
    if (!ppage_list) {
        alloc_init();
    }

    size = (size + 0x3fffULL) & ~0x3fffULL;
    disable_interrupts();
    uint64_t base = (gTopOfKernelData + 0x3fffULL) & ~0x3fffULL;
    uint32_t idx = (base - gBootArgs->physBase) >> 14;
    for (uint32_t i = 0; i < (size >> 14); ++i) {
        if (ppage_list[idx + i] != PAGE_FREE) {
            panic("alloc_static: ran out of static region");
        }
        ppage_list[idx + i] = PAGE_WIRED;
        wired_pages++;
    }
    gTopOfKernelData = base + size;
    enable_interrupts();

    return (void*)(base - 0x800000000 + kCacheableView);
}
uint64_t alloc_phys(uint32_t size) {
    if (!ppage_list) {
        alloc_init();
    }
    size = (size + 0x3fff) & ~0x3fff;
    uint32_t npages = size / 0x4000;
    uint32_t found_pages = 0;

    uint64_t rv = 0;
    disable_interrupts();

    if (size == PAGE_SIZE) {
        // O(1) fastpath
        rv = ppage_alloc();
        enable_interrupts();
        return rv;
    }
    for (uint32_t i = 1; i <= ppages; ++i) {
        uint64_t idx = ppages - i;
        if (ppage_list[idx] != PAGE_FREE) {
            found_pages = 0;
        } else if(++found_pages == npages) {
            rv = gBootArgs->physBase + (idx << 14);
            break;
        }
    }
    if (!rv) panic("alloc_phys: OOM");
    phys_unlink_contiguous(rv, size);
    phys_reference(rv, size);
    enable_interrupts();
    return rv;
}
void free_phys(uint64_t pa, uint32_t size) {
    phys_dereference(pa, size);
}
void* alloc_contig(uint32_t size) {
    return phystokv(alloc_phys(size));
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
    //bool is_tt1 = false;
    uint64_t* ttb = NULL;
    if (va & 0x7000000000000000) {
        bits -= t1sz;
        va -= (0xffffffffffffffff - ((1ULL << (65 - t1sz)) - 1));
        va &= (1ULL << bits) - 1;
        //is_tt1 = true;
        ttb = phystokv(vmspace->ttbr1);
    } else {
        bits -= t0sz;
        va &= (1ULL << bits) - 1;
        //is_tt1 = false;
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
        uint64_t vm_offset = (vma - vmspace->vm_space_base) / PAGE_SIZE;
        bool is_vm_mapped = !!(vmspace->vm_space_table[vm_offset >> 3] & (1 << (vm_offset & 7)));
        if (is_vm_mapped) {
            // optimization: don't do a page walk if the VM is not mapped.
            union tte tte;
            uint64_t* ttep;
            if (tte_walk_get(vmspace, vma & ~0x3fff, &ttep) == true) {
                tte.u64 = *ttep;
                if (tte.valid == 0 && tte.table == 1) {
                    tte.table = 0;
                    if (tte.u64 == PAGING_INFO_ALLOC_ON_FAULT_MAGIC) {
                        //fiprintf(stderr, "should allocate physical for %" PRIx64 "\n", vma);
                        paging_requests++;
                        vm_space_map_page_physical_prot(vmspace, vma & ~0x3fff, ppage_alloc(), PROT_READ|PROT_WRITE);
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
