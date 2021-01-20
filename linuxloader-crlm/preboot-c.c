#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dtree.h"

#define BOOT_LINE_LENGTH        256
struct iphone_boot_args {
    uint16_t revision;
    uint16_t version;
    uint64_t virt_base;
    uint64_t phys_base;
    uint64_t mem_size;
    uint64_t top_of_kernel;
    struct {
        uint64_t phys, display, stride;
        uint64_t width, height, depth;
    } video;
    uint32_t machine_type;
    uint64_t dtree_virt;
    uint32_t dtree_size;
    char cmdline[BOOT_LINE_LENGTH];
};

void loader_main(void *linux_dtb, struct iphone_boot_args *bootargs, uint64_t rvbar)
{
    dtree *linux_dt;
    dt_node *node;
    dt_prop *prop;
    uint64_t memsize, base;
    unsigned i;

    memsize = (bootargs->mem_size + 0x3ffffffful) & ~0x3ffffffful;

    printf("Starting Linux loader stub.\n");

    linux_dt = dt_parse_dtb(linux_dtb, 0x20000);
    if(!linux_dt) {
        printf("Failed parsing Linux device-tree.\n");
        return;
    }

    node = dt_find_node(linux_dt, "/framebuffer");
    if(node) {
        prop = dt_find_prop(linux_dt, node, "reg");
        if(prop) {
            dt_put64be(prop->buf, bootargs->video.phys);
            dt_put64be(prop->buf + 8, (bootargs->video.height * bootargs->video.stride * 4 + 0x3FFFul) & ~0x3FFFul);
        }

        prop = dt_find_prop(linux_dt, node, "width");
        if(prop)
            dt_put32be(prop->buf, bootargs->video.width);

        prop = dt_find_prop(linux_dt, node, "height");
        if(prop)
            dt_put32be(prop->buf, bootargs->video.height);

        prop = dt_find_prop(linux_dt, node, "stride");
        if(prop)
            dt_put32be(prop->buf, bootargs->video.stride);
    }

    node = dt_find_node(linux_dt, "/memory");
    if(node) {
        prop = dt_find_prop(linux_dt, node, "reg");
        if(prop)
            dt_put64be(prop->buf + 8, memsize);
    }

    for(i=0; ; i++) {
        node = dt_find_node_idx(linux_dt, NULL, "/reserved-memory/fw_area", i);
        if(!node)
            break;

        prop = dt_find_prop(linux_dt, node, "reg");
        if(prop) {
            base = dt_get64be(prop->buf);
            if(base >= 0x900000000ul) {
                base += memsize - 0x200000000ul;
                dt_put64be(prop->buf, base);
            }
        }
    }

    node = dt_find_node(linux_dt, "/reserved-memory/smpentry");
    if(node) {
        prop = dt_find_prop(linux_dt, node, "reg");
        if(prop)
            dt_put64be(prop->buf, rvbar & ~0xfff);
    }

    node = dt_find_node(linux_dt, "/soc/applestart");
    if(node) {
        prop = dt_find_prop(linux_dt, node, "reg");
        if(prop)
            for(i=0; i<prop->size/48; i++)
                dt_put64be(prop->buf + 48 * i + 16, rvbar + 8 * i);
    }

    printf("Loader complete, relocating kernel...\n");
    dt_write_dtb(linux_dt, linux_dtb, 0x20000);
    dt_free(linux_dt);
}
