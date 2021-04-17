/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2021 checkra1n team
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
#include <pongo.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

// to replace with dlsym perhaps later on
void* resolve_symbol(const char* name);

void link_exports(struct pongo_exports* export);

void modload_cmd() {
        iprintf("[modload_macho:i] Attempting to load a module\n");
        if (loader_xfer_recv_count >= 0x4000) {
            //iprintf("enough bytes! %x\n", loader_xfer_recv_count);
            struct mach_header_64* mh = (void*) loader_xfer_recv_data;
            struct load_command* lc = (struct load_command*) (mh + 1);
            if (mh->magic == MH_MAGIC_64) {
                //puts("it's a mach-o!");
                if (mh->filetype == MH_KEXT_BUNDLE) {
                    uint64_t filesz_expected = 0;
                    uint64_t vmsz_needed = 0;
                    uint64_t base_vmaddr = -1;
                    uint32_t segmentCount = 0;
                    const struct symtab_command *symtab = NULL;
                    const struct dysymtab_command *dysymtab;
                    for (int i=0; i<mh->ncmds; i++) {
                        if (lc->cmd == LC_SEGMENT_64) {
                            segmentCount++;
                            struct segment_command_64 * sg = (struct segment_command_64*) lc;
                            //iprintf("found %s, vmaddr %llx, vmsz %llx, fileoff %llx, filesize %llx\n", sg->segname, sg->vmaddr, sg->vmsize, sg->fileoff, sg->filesize);
                            if (sg->vmaddr < base_vmaddr) base_vmaddr = sg->vmaddr;
                            if (sg->fileoff + sg->filesize > filesz_expected)
                                filesz_expected = sg->fileoff + sg->filesize;
                            if (sg->vmaddr + sg->vmsize > vmsz_needed)
                                vmsz_needed = sg->vmaddr + sg->vmsize;
                        } else if (lc->cmd == LC_DYSYMTAB) {
                            dysymtab = (struct dysymtab_command *)lc;
                        } else if (lc->cmd == LC_SYMTAB) {
                            symtab = (struct symtab_command *)lc;
                        }
                        lc = (struct load_command*)(((char*)lc) + lc->cmdsize);
                    }
                    vmsz_needed -= base_vmaddr;
                    //iprintf("need %llx, got %llx\n", filesz_expected, loader_xfer_recv_count);
                    if (!(filesz_expected > loader_xfer_recv_count)) {
                        uint64_t entrypoint = 0;
                        uint8_t * allocto = alloc_contig((vmsz_needed + 0x3FFF) & ~0x3FFF);
                        uint64_t vma_base = linear_kvm_alloc(vmsz_needed);
                        struct pongo_module_info* module = pongo_module_create(segmentCount);
                        module->vm_base = vma_base;
                        module->vm_end = vma_base + vmsz_needed;
                        uint32_t segmentIndex = 0;
                        
                        //iprintf("need vm %llx, got %p, base %llx\n", vmsz_needed, allocto, base_vmaddr);
                        struct load_command* lc = (struct load_command*) (mh + 1);
                        for (int i=0; i<mh->ncmds; i++) {
                            if (lc->cmd == LC_SEGMENT_64) {
                                struct segment_command_64 * sg = (struct segment_command_64*) lc;
                                struct pongo_module_segment_info* info = &module->segments[segmentIndex++];
                                info->name = strdup(sg->segname);
                                info->vm_addr = sg->vmaddr;
                                info->vm_size = sg->vmsize;

                                memset(allocto + sg->vmaddr - base_vmaddr, 0, sg->vmsize);
                                memcpy(allocto + sg->vmaddr - base_vmaddr, loader_xfer_recv_data + sg->fileoff, sg->filesize);
                                
                                vm_protect_t prots = 0;
                                prots |= sg->initprot & VM_PROT_READ ? PROT_READ : 0;
                                prots |= sg->initprot & VM_PROT_WRITE ? PROT_WRITE : 0;
                                prots |= sg->initprot & VM_PROT_EXECUTE ? PROT_EXEC : 0;

                                info->prot = prots;

                                for (uint32_t page = 0; page < sg->vmsize; page += PAGE_SIZE) {
                                    //fiprintf(stderr, "mapping %llx (%llx, %llx), %x\n", vma_base + page + sg->vmaddr - base_vmaddr, sg->vmaddr, sg->vmsize, prots);
                                    uint64_t ppage = vatophys((uint64_t)(allocto + page + sg->vmaddr - base_vmaddr));
                                    vm_space_map_page_physical_prot(&kernel_vm_space, vma_base + page + sg->vmaddr - base_vmaddr, ppage, prots | PROT_KERN_ONLY);
                                }

                            }
                            lc = (struct load_command*)(((char*)lc) + lc->cmdsize);
                        }
                        
                        const struct relocation_info *extrel = (void *)((uintptr_t)mh + dysymtab->extreloff);
                        const struct relocation_info *locrel = (void *)((uintptr_t)mh + dysymtab->locreloff);
                        const struct nlist_64 *nlist = (struct nlist_64 *)((uintptr_t)mh + symtab->symoff);
                        const char** modname = NULL;
                        struct pongo_exports* exports = NULL;
                        for (uint32_t sym_idx = 0; sym_idx < symtab->nsyms; sym_idx++) {
                            const struct nlist_64 *nl = &nlist[sym_idx];
                            uint32_t strx = nl->n_un.n_strx;
                            const char *name = (const char *)((uintptr_t)mh + symtab->stroff + strx);
                            // Check to see if this is the entry point symbol.
                            int cmp = strcmp(name, "_module_entry");
                            if (cmp == 0) {
                                entrypoint = nl->n_value + (uint64_t)vma_base;
                            }
                                cmp = strcmp(name, "_module_name");
                            if (cmp == 0) {
                                modname = (const char**)(nl->n_value + (uint64_t)vma_base);
                            }
                            cmp = strcmp(name, "_exported_symbols");
                            if (cmp == 0 && !exports) {
                                exports = (struct pongo_exports*)(nl->n_value + (uint64_t)vma_base);
                            }
                        }
                        for (uint32_t extrel_idx = 0; extrel_idx < dysymtab->nextrel; extrel_idx++) {
                            const struct relocation_info *ri = &extrel[extrel_idx];
                            // Skip non-extern or non-8-byte relocations.
                            if (!ri->r_extern || ri->r_length != 3) {
                                continue;
                            }
                            // Get the name of the symbol.
                            const struct nlist_64 *nl = &nlist[ri->r_symbolnum];
                            uint32_t strx = nl->n_un.n_strx;
                            const char *name = (const char *)((uintptr_t)mh + symtab->stroff + strx);
                            // Resolve the symbol to its runtime address.
                            // XXX: line below was added during Linux ABI, is it ok to just drop this?
                            //if (*name == '_') name++;
                            void* symbol_value = resolve_symbol(name);
                            if (symbol_value == 0) {
                                puts("[modload_macho:!] load module: linking failed");
                                return;
                            }
                            // Find the offset of the relocation pointer in the virtually mapped Mach-O and
                            // replace it with the resolved address of the symbol. r_address is the offset from
                            // the first segment's vmaddr to the vmaddr of the pointer. Since we've put the
                            // first segment's vmaddr at offset 0 in the mapping, this means that r_address is
                            // exactly the offset into the mapping of the pointer we want to change.
                            uint64_t vmoff = ri->r_address;
                            *(uint64_t *)((uintptr_t)allocto + vmoff) = (uint64_t) symbol_value;
                        }
                        // Process the dysymtab's local relocations.
                        for (uint32_t locrel_idx = 0; locrel_idx < dysymtab->nlocrel; locrel_idx++) {
                            const struct relocation_info *ri = &locrel[locrel_idx];
                            // Skip extern or non-8-byte relocations.
                            if (ri->r_extern || ri->r_length != 3) {
                                continue;
                            }
                            // Find the offset of the relocation pointer in the virtually mapped Mach-O and
                            // slide it to the new base address.
                            uint64_t vmoff = ri->r_address;
                            uint64_t *reloc_ptr = (uint64_t *)((uintptr_t)allocto + vmoff);
                            *reloc_ptr = *reloc_ptr - base_vmaddr + ((uint64_t)vma_base);
                        }
                        link_exports(exports);
                        if (!entrypoint) panic("no entryp");
                        
                        iprintf("[modload_macho:+] Loaded module %s\n", modname ? *modname ? *modname : "<null>" : "<unknown>");
                        flush_tlb();
                        invalidate_icache();

                        module->name = strdup(modname ? *modname ? *modname : "<null>" : "<unknown>");
                        module->exports = exports;
                        ((void (*)())entrypoint)();
                    } else puts ("[modload_macho:!] load module: truncated load");
                } else puts("[modload_macho:!] load module: need dylib");
            } else puts("[modload_macho:!] load module: not mach-o");
        } else puts("[modload_macho:!] load module: short read");
        loader_xfer_recv_count = 0;
}
