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
#define LL_KTRW_INTERNAL 1
#include <pongo.h>
uint32_t autoboot_count;
#define BOOT_FLAG_DEFAULT 0
#define BOOT_FLAG_HARD 1
#define BOOT_FLAG_HOOK 2
#define BOOT_FLAG_LINUX 3
#define BOOT_FLAG_RAW 4

extern volatile char gBootFlag;

/*

    Name: pongo_boot_hard
    Description: command handler for bootux

*/

void pongo_boot_hard() {
    gBootFlag = BOOT_FLAG_HARD;
    task_yield();
}

/*

    Name: pongo_boot_hook
    Description: command handler for bootx

*/

void pongo_boot_hook() {
    gBootFlag = BOOT_FLAG_HOOK;
    task_yield();
}

/*

    Name: pongo_boot_raw
    Description: command handler for bootr

*/

void pongo_boot_raw() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a raw image before issuing this command\n");
        return;
    }
    loader_xfer_recv_count = 0;
    gBootFlag = BOOT_FLAG_RAW;
    task_yield();
}

/*

    Name: pongo_copy_xnu
    Description: command handler for copyx

*/

void pongo_copy_xnu() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a raw image before issuing this command\n");
        return;
    }

    uint64_t entryp = (uint64_t) gEntryPoint;
    uint64_t gImagePhys = entryp & (~0xFFF);
    gImagePhys += 0x4000;
#define DEVICE_TO_CACHEABLE(device) (device - 0x800000000 + kCacheableView)
    gImagePhys = DEVICE_TO_CACHEABLE(gImagePhys);
    while (1) {
        if (*(uint32_t*)gImagePhys == 0xfeedfacf) {
            break;
        }
        gImagePhys -= 0x1000;
    }

    memcpy((void*)gImagePhys, loader_xfer_recv_data, loader_xfer_recv_count);
    /* Note that we only do the copying over part here, you are expected to have to modify gEntryPoint
     * TODO: parse Mach-O header and set gEntryPoint value
     */
}
/*

    Name: pongo_boot_linux
    Description: command handler for bootl

*/

void pongo_boot_linux() {
    if (!linux_can_boot()) {
        printf("linux boot not prepared\n");
        return;
    }
    gBootFlag = BOOT_FLAG_LINUX;
    task_yield();
}

/*

    Name: pongo_boot_xargs
    Description: command handler for xargs

*/

void pongo_boot_xargs(const char* cmd, char* args) {
    if (args[0] == 0) {
        // get
        iprintf("xnu boot arg cmdline: [%s]\n", (char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView) );
    } else {
        strcpy((char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView ), args);
        iprintf("set xnu boot arg cmdline to: [%s]\n", (char*)((int64_t)gBootArgs->CommandLine - 0x800000000 + kCacheableView ));
    }
}

/*

    Name: ramdisk_ldr
    Description: preboot hook for ramdisk loading

 */

void* ramdisk_buf;
uint32_t ramdisk_size;

void ramdisk_ldr() {
    if (ramdisk_size) {
        dt_node_t* memory_map = (dt_node_t*)dt_find(gDeviceTree, "memory-map");
        if (!memory_map) panic("invalid devicetree: no memory_map!");
        struct memmap* map = dt_alloc_memmap(memory_map, "RAMDisk");
        if (!map) panic("invalid devicetree: dt_alloc_memmap failed");

        void* rd_static_buf = alloc_static(ramdisk_size);
        iprintf("allocated static region for rdsk: %p, sz: %x\n", rd_static_buf, ramdisk_size);
        memcpy(rd_static_buf, ramdisk_buf, ramdisk_size);

        struct memmap md0map;
        md0map.addr = ((uint64_t)rd_static_buf) + 0x800000000 - kCacheableView;
        md0map.size = ramdisk_size;
        memcpy(map, &md0map, 0x10);
    }
}

/*

    Name: ramdisk_cmd
    Description: command handler for ramdisk

 */

void ramdisk_cmd() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a ramdisk before issuing this command\n");
        return;
    }
    if (ramdisk_buf) free(ramdisk_buf);
    ramdisk_buf = malloc(loader_xfer_recv_count);
    if (!ramdisk_buf) panic("couldn't reserve heap for ramdisk");
    ramdisk_size = loader_xfer_recv_count;
    memcpy(ramdisk_buf, loader_xfer_recv_data, ramdisk_size);
    loader_xfer_recv_count = 0;
}

/*

    Name: fdt_cmd
    Description: command handler for fdt

 */
extern void * fdt;
extern bool fdt_initialized;
#define LINUX_DTREE_SIZE 65536

void fdt_cmd() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a fdt before issuing this command\n");
        return;
    }
    if (fdt_initialized) free(fdt);
    fdt = malloc(LINUX_DTREE_SIZE);
    if (!fdt) panic("couldn't reserve heap for fdt");
    memcpy(fdt, loader_xfer_recv_data, loader_xfer_recv_count);
    fdt_initialized = 1;
    loader_xfer_recv_count = 0;
}


/*

    Name: pongo_spin
    Description: command handler for spin

*/

void pongo_spin() {
    spin(1000000);
}

// DTree printing


typedef struct
{
    const char *name;
    const char *prop;
    size_t size;
} dt_arg_t;
#define LOG(str, args...) do { iprintf(str "\n", ##args); } while(0)
#define REQ(expr) \
    do \
    { \
        if(!(expr)) \
        { \
            ERR("!(" #expr ")"); \
            goto out; \
        } \
    } while(0)

static int dt_cbn(void *a, dt_node_t *node)
{
    if(a != node)
    {
        LOG("--------------------------------------------------------------------------------------------------------------------------------");
    }
    return 0;
}

static int dt_cbp(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len)
{
    int retval = 0;
    dt_arg_t *arg = a;
    const char *prop = arg->prop;
    if(!prop || strncmp(prop, key, DT_KEY_LEN) == 0)
    {
        // Print name, if we're in single-prop mode and recursive
        if(depth >= 0 && prop && strcmp(key, "name") != 0)
        {
            uint32_t l = 0;
            void *v = dt_prop(node, "name", &l);
            if(v)
            {
                dt_arg_t tmp = *arg;
                tmp.prop = NULL;
                retval = dt_cbp(&tmp, node, depth, "name", v, l);
            }
        }
        if(depth < 0) depth = 0;
        bool printable = true;
        char *str = val;
        for(size_t i = 0; i < len; ++i)
        {
            char c = str[i];
            if((c < 0x20 || c >= 0x7f) && c != '\t' && c != '\n')
            {
                if(c == 0x0 && i == len - 1)
                {
                    continue;
                }
                printable = false;
                break;
            }
        }
        if(printable)
        {
            LOG("%*s%-*s %s", depth * 4, "", DT_KEY_LEN, key, str);
        }
        else if(len == 1 || len == 2 || len == 4) // 8 is usually not uint64
        {
            uint64_t v = 0;
            for(size_t i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                v |= (uint64_t)c << (i * 8);
            }
            LOG("%*s%-*s 0x%0*llx", depth * 4, "", DT_KEY_LEN, key, (int)len * 2, v);
        }
        else
        {
            const char *k = key;
            const char *hex = "0123456789abcdef";
            char xs[49] = {};
            char cs[17] = {};
            size_t sz = arg->size;
            if(sz == 8)
            {
                xs[0]  = xs[19] = '0';
                xs[1]  = xs[20] = 'x';
                xs[18] = xs[37] = ' ';
            }
            else if(sz == 4)
            {
                xs[0]  = xs[11] =          xs[23] = xs[34] = '0';
                xs[1]  = xs[12] =          xs[24] = xs[35] = 'x';
                xs[10] = xs[21] = xs[22] = xs[33] = xs[44] = ' ';
            }
            else
            {
                xs[2] = xs[5] = xs[8] = xs[11] = xs[14] = xs[17] = xs[20] = xs[23] = xs[24] = xs[27] = xs[30] = xs[33] = xs[36] = xs[39] = xs[42] = xs[45] = ' ';
            }
            size_t i;
            for(i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix    ] = hex[(c >> 4) & 0xf];
                xs[ix + 1] = hex[(c     ) & 0xf];
                cs[is] = c >= 0x20 && c < 0x7f ? c : '.';
                if(is == 0xf)
                {
                    LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
                    k = "";
                }
            }
            if((i % 0x10) != 0)
            {
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? 19 : 0; iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? 37 : 18;
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? (is >= 0xc ? 34 : 23) : (is >= 0x4 ? 11 : 0); iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? (is > 0xc ? 44 : 33) : (is > 0x4 ? 21 : 10);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix] = '\0';
                cs[is] = '\0';
                LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
            }
        }
    }
    return retval;
}

void log_dtree()
{
    struct boot_args* cBootArgs = (struct boot_args*)((uint64_t)gBootArgs - 0x800000000 + kCacheableView);
    iprintf("gBootArgs:\n\tRevision: %x\n\tVersion: %x\n\tvirtBase: %llx\n\tphysBase %llx\n\tmemSize: %llx\n\ttopOfKernelData: %llx\n\tmachineType: %x\n\tdeviceTreeP: %llx\n\tdeviceTreeLength: %x\n\tCommandLine: %s\n\tbootFlags: %llx\n\tmemSizeActual: %llx\n", cBootArgs->Revision, cBootArgs->Version, cBootArgs->virtBase, cBootArgs->physBase, cBootArgs->memSize, cBootArgs->topOfKernelData, cBootArgs->machineType, (uint64_t)cBootArgs->deviceTreeP, cBootArgs->deviceTreeLength, &cBootArgs->CommandLine, cBootArgs->bootFlags, cBootArgs->memSizeActual);
    dt_arg_t arg =
    {
        .name = NULL,
        .prop = NULL,
        .size = 0xFFFF,
    };

    dt_parse(gDeviceTree, 0, NULL, &dt_cbn, gDeviceTree, &dt_cbp, &arg);
}
extern char is_masking_autoboot;
void start_host_shell() {
    is_masking_autoboot = 1;
    command_unregister("shell");
    command_unregister("autoboot");
    serial_enable_rx();
    screen_puts("Enabling USB");
    usb_init();
    screen_puts("Done!");
}


/*

    Name: shell_main
    Description: shell main function

*/

void shell_main() {
    /*
        Load command handler
    */
    extern void task_list(const char *, char*);
    command_register("ps", "lists current tasks and irq handlers", task_list);
    command_register("xargs", "prints or sets xnu boot-args", pongo_boot_xargs);
    command_register("ramdisk", "loads a ramdisk for xnu", ramdisk_cmd);
    command_register("loadx", "loads xnu", pongo_copy_xnu);
    command_register("bootx", "boots xnu (patched, if such a module is loaded)", pongo_boot_hook);
    command_register("bootux", "boots unpatched xnu", pongo_boot_hard);
    command_register("bootl", "boots linux", pongo_boot_linux);
    command_register("bootr", "boot raw image", pongo_boot_raw);
    command_register("spin", "spins 1 second", pongo_spin);
    command_register("dt", "parses loaded devicetree", log_dtree);
    command_register("fdt", "load linux fdt from usb", fdt_cmd);
    command_register("shell", "starts uart & usb based shell", start_host_shell);
    usbloader_init();
    rdload_hook = ramdisk_ldr;

    /*
        Load USB Loader
    */

    extern void modload_cmd();
    command_register("modload", "loads module", modload_cmd);
    disable_interrupts();
    command_init();
    event_wait_asserted(&command_handler_iter);

#ifdef AUTOBOOT
    extern void pongo_autoboot();
    pongo_autoboot();
#endif

    queue_rx_string("shell\n");

#ifdef LOCK_TESTING
    task_register(&pongo_lock_test1, pongo_lock_test1_entry);
    task_register(&pongo_lock_test2, pongo_lock_test2_entry);
#endif
//    gBootFlag = BOOT_FLAG_HOOK;
}
