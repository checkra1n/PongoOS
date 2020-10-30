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

void* free_list;

void* page_alloc() {
    void* page = NULL;
    disable_interrupts();
    if (free_list) {
        page = free_list;
        free_list = *(void**)page;
    } else {
        page = (void*)alloc_contig(PAGE_SIZE);
    }
    enable_interrupts();
    if (!page)
        panic("page_alloc: returning NULL, memory leak?");
    bzero(page, 0x4000);
    return page;
}
void page_free(void* page) {
    disable_interrupts();
    *(void**)page = free_list;
    free_list = page;
    enable_interrupts();
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

err_t vm_space_allocate(struct vm_space* vmspace, uint64_t* addr, uint64_t size, vm_flags_t flags) {
    err_t retn = KERN_VM_OOM;
    
    uint32_t pagecount = ((size + PAGE_MASK) & ~PAGE_MASK) / PAGE_SIZE;
    if (!pagecount) return 0;
    lock_take(&vmspace->vm_space_lock);
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
            vmspace->vm_space_table[i >> 3] |= 1 << (i & 7);
        }
        *addr = vmspace->vm_space_base + vm_scan_base * PAGE_SIZE;
    } else {
        *addr = 0;
    }
    
    lock_release(&vmspace->vm_space_lock);
    
    return retn;
}
err_t vm_space_deallocate(struct vm_space* vmspace, uint64_t addr, uint64_t size) {
    err_t retn = KERN_VM_OOM;
    lock_take(&vmspace->vm_space_lock);
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
    flush_tlb();
    lock_release(&vmspace->vm_space_lock);
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
        map_range_map((uint64_t*)vmspace->ttbr1, vaddr, physical, 0x4000, 3, prot & PROT_DEVICE ? 0 : 1, 1, false, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY), true);
    } else {
        map_range_map((uint64_t*)vmspace->ttbr0, vaddr, physical, 0x4000, 3, prot & PROT_DEVICE ? 0 : 1, 1, false, prot & (PROT_READ|PROT_WRITE|PROT_EXEC|PROT_KERN_ONLY), false);
    }
    vm_flush_by_addr(vmspace, vaddr);
    enable_interrupts();
    return KERN_SUCCESS;
}
err_t vm_allocate(struct task* task, uint64_t* addr, uint64_t size, vm_flags_t flags) {
    return vm_space_allocate(task->vm_space, addr, size, flags);
}
err_t vm_deallocate(struct task* task, uint64_t addr, uint64_t size) {
    return vm_space_deallocate(task->vm_space, addr, size);
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
    //fiprintf(stderr, "freeing asid: %llx\n", asid);

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
    space->ttbr0 = parent->ttbr0;
    space->ttbr1 = ttbpage_alloc();
    space->asid = asid_alloc();
    space->parent = parent; // consume ref
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
void vm_release(struct vm_space* vmspace) {
    if (!vmspace) return;
    if (vmspace->refcount == TASK_REFCOUNT_GLOBAL) return;
    uint32_t refcount = __atomic_fetch_sub(&vmspace->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
        if (vmspace->parent == vmspace) panic("circular reference");
        //fiprintf(stderr, "freeing vmspace: %p\n", vmspace);
        vm_release(vmspace->parent);
        uint64_t vm_scan_size = (VM_SPACE_SIZE / PAGE_SIZE);
        for (uint32_t i=0; i < vm_scan_size; i ++) {
            uint8_t is_alloc = ((vmspace->vm_space_table[i >> 3]) >> (i & 7)) & 1;
            if (is_alloc) {
                vm_space_map_page_physical_prot(vmspace, vmspace->vm_space_base + i * PAGE_SIZE, 0, 0); // free physical
            }
        }
        asid_free(vmspace->asid);
        free(vmspace->vm_space_table);
        free(vmspace);
    }
}
