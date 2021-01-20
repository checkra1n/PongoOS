
#import <pongo.h>

#define BOOT_FLAG_JUMP 5
extern char gBootFlag;
extern uint64_t gBootJumpTo;
extern uint64_t gBootJumpArgs[4];
extern uint64_t gBootJumpToReloc;
extern uint64_t gBootJumpToRelocSize;
extern uint64_t gBootJumpToRelocFrom;

extern uint64_t gIORVBAR;
extern uint64_t vatophys_static(void* kva); // only safe to use with phystokva or alloc_contig's return value
extern void* alloc_contig(uint32_t size);

extern void loader_main(void *linux_dtb, void *bootargs, uint64_t rvbar);

extern uint8_t __linux_kernel_start[] __asm__("section$start$__LINUX$__kernel"),
                __linux_kernel_end[] __asm__("section$end$__LINUX$__kernel");
extern uint8_t __linux_dtree_start[] __asm__("section$start$__LINUX$__dtree"),
                __linux_dtree_end[] __asm__("section$end$__LINUX$__dtree");

void module_entry() {
    puts("sandcastle linux loader");
    
    uint64_t linux_size = ((uint64_t)__linux_kernel_end) - ((uint64_t)__linux_kernel_start);
    uint64_t dtree_size = ((uint64_t)__linux_dtree_end) - ((uint64_t)__linux_dtree_start);

    void* rregion = alloc_contig(0x80000 + linux_size);
    
    void* dtb_copy = rregion + 0x60000;
    
    memcpy(dtb_copy, __linux_dtree_start, dtree_size);
    
    loader_main(dtb_copy, (void*)gBootArgs, gIORVBAR);

    puts("... done, booting!");
    sleep(10);
    
    disable_interrupts();

    gBootFlag = BOOT_FLAG_JUMP;

    memcpy(rregion + 0x80000, __linux_kernel_start, linux_size);

    gBootJumpToRelocFrom = vatophys_static(rregion);
    gBootJumpToReloc = 0x880000000;
    gBootJumpToRelocSize = 0x80000 + linux_size;
    
    gBootJumpArgs[0] = 0x880000000 + 0x60000;
    gBootJumpArgs[1] = 0;
    gBootJumpArgs[2] = 0;
    gBootJumpArgs[3] = 0;
    gBootJumpTo = 0x880000000 + 0x80000;

    task_yield_asserted();
}
char* module_name = "sandcastle-loader";

struct pongo_exports exported_symbols[] = {
    {.name = 0, .value = 0}
};

