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
//  Copyright (C) 2019-2022 checkra1n team
//  This file is part of pongoOS.
//
#include <pongo.h>

#define APFS_VOL_ROLE_NONE      0x0000
#define APFS_VOL_ROLE_SYSTEM    0x0001
#define APFS_VOL_ROLE_USER      0x0002
#define APFS_VOL_ROLE_RECOVERY  0x0004
#define APFS_VOL_ROLE_VM        0x0008
#define APFS_VOL_ROLE_PREBOOT   0x0010

static char *gNewEntry;
static int hasChanged = 0;

void dtpatchef(const char* cmd, char* args) {
    
    // newfs: newfs_apfs -A -D -o role=r -v Xystem /dev/disk1
    
    if(!hasChanged) {
        uint32_t len = 0;
        dt_node_t* dev = dt_find(gDeviceTree, "fstab");
        if (!dev) panic("invalid devicetree: no device!");
        uint32_t* val = dt_prop(dev, "max_fs_entries", &len);
        if (!val) panic("invalid devicetree: no prop!");
        uint32_t* patch = (uint32_t*)val;
        printf("fstab max_fs_entries: %016llx: %08x\n", (uint64_t)val, patch[0]);
        uint32_t entries = patch[0];
        entries += 1;
        hasChanged = 1;
        gNewEntry = args;
    }
    
    /*{
        // wat?!
        uint32_t len = 0;
        dt_node_t* dev = dt_find(gDeviceTree, "system-vol");
        if (!dev) panic("invalid devicetree: no device!");
        
        uint32_t* val = dt_prop(dev, "vol.fs_role", &len);
        if (!val) panic("invalid devicetree: no prop!");
        // get role
        uint32_t* patch = (uint32_t*)val;
        printf("old system vol.fs_role: %016llx: %08x\n", (uint64_t)val, patch[0]);
        // change sys -> recv
        patch[0] = APFS_VOL_ROLE_RECOVERY;
        printf("new system vol.fs_role: %016llx: %08x\n", (uint64_t)val, patch[0]);
        
        val = dt_prop(dev, "vol.fs_type", &len);
        if (!val) panic("invalid devicetree: no prop!");
        // get fs_type
        uint8_t* rwpatch = (uint8_t*)val;
        printf("old system vol.fs_type: %016llx: %c\n", (uint64_t)val, rwpatch[1]);
        // change ro -> rw
        rwpatch[1] = 'w';
        printf("new system vol.fs_type: %016llx: %c\n", (uint64_t)val, rwpatch[1]);
        
    }*/
    
    {
        uint32_t len = 0;
        dt_node_t* dev = dt_find(gDeviceTree, "chosen");
        if (!dev) panic("invalid devicetree: no device!");
        uint32_t* val = dt_prop(dev, "root-matching", &len);
        if (!val) panic("invalid devicetree: no prop!");
        
        char str[0x100]; // max size = 0x100
        memset(&str, 0x0, 0x100);
        sprintf(str, "<dict ID=\"0\"><key>IOProviderClass</key><string ID=\"1\">IOService</string><key>BSD Name</key><string ID=\"2\">%s</string></dict>", gNewEntry);
        
        memset(val, 0x0, 0x100);
        memcpy(val, str, 0x100);
        printf("set new entry: %016llx: %s\n", (uint64_t)val, gNewEntry);
    }
    
}

void module_entry() {
    puts("");
    puts("");
    puts("#==================");
    puts("#");
    puts("# dtpatcher");
    puts("#");
    puts("# Made by dora2ios");
    puts("# Modified by Ploosh");
    puts("#");
    puts("# Get it for free at https://github.com/guacaplushy/PongoOS");

    command_register("dtpatch", "run dt patcher", dtpatcher);
}

char* module_name = "dtpatcher-ploosh";

struct pongo_exports exported_symbols[] = {
    {.name = 0, .value = 0}
};
