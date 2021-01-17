/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team
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
#import <pongo.h>
struct hal_device _gRootDevice = {
    .name = "root"
};
struct hal_device* gRootDevice, * gDeviceTreeDevice;

#define HAL_LOAD_XNU_DTREE 0
#define HAL_LOAD_DTREE_CHILDREN 1
#define HAL_CREATE_CHILD_DEVICE 2
#define HAL_GET_MAPPER 3
#define HAL_MAP_REGISTERS 4
#define HAL_GET_IRQNR 5

void hal_probe_hal_services(struct hal_device* device) ;

static int hal_load_dtree_child_node(void* arg, dt_node_t* node) {
    struct hal_device* parentDevice = arg;
    if (parentDevice->node == node) return 0;
    
    uint32_t len = 0;
    void* val = dt_prop(node, "name", &len);
    if (val) {
        struct hal_device* device = malloc(sizeof(struct hal_device));
        device->next = parentDevice->down;
        device->parent = parentDevice;
        parentDevice->down = device;
        device->node = node;
        device->down = NULL;
        device->name = strdup(val);
        
        hal_probe_hal_services(device);
        
        if (0 != hal_invoke_service_op(device, "hal", HAL_LOAD_DTREE_CHILDREN, NULL, 0, NULL, NULL))
            panic("hal_load_dtree_child_node: HAL_LOAD_DTREE_CHILDREN failed!");
    }
    return 0;
}

static int hal_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_LOAD_XNU_DTREE) {
        device->node = gDeviceTree;
        return 0;
    } else if (method == HAL_LOAD_DTREE_CHILDREN && device->node) {
        // int dt_parse(dt_node_t* node, int depth, uint32_t* offp, int (*cb_node)(void*, dt_node_t*), void* cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void* cbp_arg)
        return dt_parse_ex(device->node, 0, NULL, hal_load_dtree_child_node, device, NULL, NULL, 1);
    } else if (method == HAL_CREATE_CHILD_DEVICE && data_out_size && *data_out_size == 8) {
        struct hal_device* ndevice = malloc(sizeof(struct hal_device));
        ndevice->next = device->down;
        ndevice->parent = device;
        device->down = ndevice;
        ndevice->node = NULL;
        ndevice->down = NULL;
        ndevice->name = strdup(data_in);
        
        hal_probe_hal_services(ndevice);
        
        *(void**)data_out = ndevice;
        
        return 0;
    } else if (method == HAL_GET_MAPPER && data_in && data_in_size == 4 && data_out && *data_out_size == 8) {
        uint32_t index = *(uint32_t*)data_in;
        *(void**)data_out = NULL;
        
        uint32_t len = 0;
        dt_node_t* node = device->node;
        if (!node) return -1;
        
        uint32_t* val = dt_prop(node, "iommu-parent", &len);
        if (!val) {
            return -1;
        }
        
        if (index >= len / 4) {
            return -1;
        }
        
        uint32_t phandle = val[index];
        *(struct hal_device **)data_out = hal_get_phandle_device(phandle);
        return 0;
    } else if (method == HAL_MAP_REGISTERS && data_in && data_in_size == 4 && data_out && *data_out_size == 16) {
        uint32_t index = *(uint32_t*)data_in;
        ((void**)data_out)[0] = NULL;
        ((void**)data_out)[1] = NULL;

        uint32_t len = 0;
        dt_node_t* node = device->node;
        if (!node) return -1;
        
        void* val = dt_prop(node, "reg", &len);
        if (!val) {
            return -1;
        }
        
        if (index * 0x10 >= len) {
            return -1;
        }
    
        struct device_regs {
            uint64_t base;
            uint64_t size;
        }* regs = val;
        
        uint64_t regbase = regs[index].base + gIOBase;
        uint64_t size = regs[index].size;

        ((void**)data_out)[0] = (void*)hal_map_physical_mmio(regbase, size);
        ((void**)data_out)[1] = (void*)regs[index].size;

        return 0;
    }
    
    return -1;
}
uint64_t hal_map_physical_mmio(uint64_t regbase, uint64_t size) {
    size +=  0x3FFF;
    size &= ~0x3FFF;
    uint64_t va = linear_kvm_alloc(size);

    map_range_map((uint64_t*)kernel_vm_space.ttbr0, va, regbase, size, 3, 0, 1, 0, PROT_READ|PROT_WRITE, !!va & 0x7000000000000000);

    return va;
}
int32_t hal_get_irqno(struct hal_device* device, uint32_t index) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return -1;

    int32_t* val = dt_prop(node, "interrupts", &len);
    if (!val || index * 4 >= len) {
        return -1;
    }
    return val[index];
}

void * hal_map_registers(struct hal_device* device, uint32_t index, size_t *size) {
    struct {
        void* base;
        size_t size;
    } rv;
    size_t osz = 0x10;
    if (size) *size = 0;
    
    if (hal_invoke_service_op(device, "hal", HAL_MAP_REGISTERS, &index, 4, &rv, &osz)) {
        return NULL;
    }
    if (size) *size = rv.size;
    return rv.base;
}
struct hal_device * hal_get_mapper(struct hal_device* device, uint32_t index) {
    struct hal_device * rv = NULL;
    size_t osz = 8;
    
    if (hal_invoke_service_op(device, "hal", HAL_GET_MAPPER, &index, 4, &rv, &osz)) {
        return NULL;
    }
    return rv;
}

static bool hal_service_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    return true;
}
struct hal_service hal_service = {
    .name = "hal",
    .probe = hal_service_probe,
    .service_op = hal_service_op
};

int hal_invoke_service_op(struct hal_device* device, const char* svc_name, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    struct hal_device_service* svc = device->services;
    while (svc) {
        if (svc_name == svc->name || strcmp(svc_name, svc->name) == 0) {
            if (svc->service->service_op) {
                return svc->service->service_op(svc, device, method, data_in, data_in_size, data_out, data_out_size);
            }
        }
        svc = svc->next;
    }
    return -0xfe;
}

struct hal_service* hal_service_head;
lock hal_service_lock;
void hal_register_hal_service(struct hal_service* svc) {
    lock_take(&hal_service_lock);
    svc->next = hal_service_head;
    hal_service_head = svc;
    lock_release(&hal_service_lock);
}
void hal_probe_hal_services(struct hal_device* device) {
    lock_take(&hal_service_lock);
    
    if (device && device->node) {
        uint32_t llen = 0;
        uint32_t* phandle = dt_prop(device->node, "AAPL,phandle", &llen);
        if (phandle && llen == 4) {
            hal_register_phandle_device(*phandle, device);
            device->phandle = *phandle;
        }
    }
    
    struct hal_service* svc = hal_service_head;
    while (svc) {
        if (svc->probe) {
            void* ctx = NULL;
            if (svc->probe(svc, device, &ctx)) {
                struct hal_device_service* hds = malloc(sizeof(struct hal_device_service));
                hds->name = svc->name;
                hds->service = svc;
                hds->context = ctx;
                hds->next = device->services;
                device->services = hds;
            }
        }
        svc = svc->next;
    }
    lock_release(&hal_service_lock);
}
struct hal_platform _gPlatform;
struct hal_platform* gPlatform;
struct hal_platform_driver* platform_driver_head;

void hal_register_platform_driver(struct hal_platform_driver* driver) {
    driver->next = platform_driver_head;
    platform_driver_head = driver;
}
const char* hal_platform_name() {
    if (!gPlatform) panic("hal_platform_name: no gPlatform!");
    
    return gPlatform->bound_platform_driver->name;
}
bool hal_get_platform_value(const char* name, void* value, size_t* size) {
    if (!gPlatform) panic("hal_get_platform_value: no gPlatform!");
    
    return gPlatform->bound_platform_driver->get_platform_value(name, value, size);
}

static void hal_init_late() {
    extern struct driver drivers[] __asm("section$start$__DATA$__drivers");
    extern struct driver drivers_end[]  __asm("section$end$__DATA$__drivers");
    struct driver* driver = &drivers[0];
    
    while (driver < &drivers_end[0]) {
        if (!(driver->flags & DRIVER_FLAGS_PLATFORM)) {
            driver->initializer(driver);
        }
        driver++;
    }
}
void lsdev_cb(struct hal_device* dev, int depth) {
    iprintf("%*s (%d)\n", depth*4, dev->name, depth);
}
void recurse_device(struct hal_device* dev, int depth, void (*cb)(struct hal_device* dev, int depth)) {
    cb(dev, depth);
    struct hal_device* nxt = dev->down;
    while (nxt) {
        recurse_device(nxt, depth+1, cb);
        nxt = nxt->next;
    }
}
void lsdev_cmd(const char *cmd, char *args)
{
    recurse_device(gRootDevice, 0, lsdev_cb);
}
static struct hal_device * hal_device_by_name_recursive(struct hal_device* dev, int depth, const char* name) {
    struct hal_device* nxt = dev->down;
    if (strcmp(dev->name, name) == 0) {
        return dev;
    }
    
    while (nxt) {
        struct hal_device* rv = hal_device_by_name_recursive(nxt, depth+1, name);
        if (rv) {
            return rv;
        }
        nxt = nxt->next;
    }
    return NULL;
}
struct hal_device * hal_device_by_name(const char* name) {
    return hal_device_by_name_recursive(gRootDevice, 0, name);
}

struct hal_device** phandle_table;
uint32_t phandle_table_size;

void hal_register_phandle_device(uint32_t phandle, struct hal_device* dev) {
    if (!phandle_table_size) {
        phandle_table_size = 0x100;
        phandle_table = calloc(phandle_table_size, 8);
    }

    uint32_t phandle_table_size_new = phandle_table_size;
    while (phandle > phandle_table_size_new) {
        phandle_table_size_new *= 2;
    }
    
    if (phandle_table_size != phandle_table_size_new) {
        struct hal_device** phandle_table_new = calloc(phandle_table_size_new, 8);
        memcpy(phandle_table_new, phandle_table, phandle_table_size_new * 8);
        phandle_table = phandle_table_new;
        phandle_table_size = phandle_table_size_new;
    }
    
    phandle_table[phandle] = dev;
}
struct hal_device* hal_get_phandle_device(uint32_t phandle) {
    while (phandle < phandle_table_size) {
        return phandle_table[phandle];
    }
    return NULL;
}


void hal_init() {
    gPlatform = NULL;
    gRootDevice = &_gRootDevice;
    
    extern struct driver drivers[] __asm("section$start$__DATA$__drivers");
    extern struct driver drivers_end[]  __asm("section$end$__DATA$__drivers");
    struct driver* driver = &drivers[0];
    
    while (driver < &drivers_end[0]) {
        if (driver->flags & DRIVER_FLAGS_PLATFORM) {
            driver->initializer(driver);
        }
        driver++;
    }
    
    _gPlatform.cpid = socnum;
    
    struct hal_platform_driver* plat = platform_driver_head;
    
    while (plat) {
        if (plat->probe(plat, &_gPlatform)) {
            gPlatform = &_gPlatform;
            gPlatform->bound_platform_driver = plat;
            break;
        }
        plat = plat->next;
    }
    
    if (!gPlatform) {
        panic("hal_init: no platform driver for %x", socnum);
    }
    hal_init_late();
    hal_register_hal_service(&hal_service);

    hal_probe_hal_services(gRootDevice);
    size_t ssz = 8;
    
    if (0 != hal_invoke_service_op(gRootDevice, "hal", HAL_CREATE_CHILD_DEVICE, "dtree", 6, &gDeviceTreeDevice, &ssz))
        panic("hal_init: HAL_CREATE_CHILD_DEVICE failed!");
    if (0 != hal_invoke_service_op(gDeviceTreeDevice, "hal", HAL_LOAD_XNU_DTREE, NULL, 0, NULL, NULL))
        panic("hal_init: HAL_LOAD_XNU_DTREE failed!");
    if (0 != hal_invoke_service_op(gDeviceTreeDevice, "hal", HAL_LOAD_DTREE_CHILDREN, NULL, 0, NULL, NULL))
        panic("hal_init: HAL_LOAD_DTREE_CHILDREN failed!");

    
    if (gPlatform->bound_platform_driver->late_init) {
        gPlatform->bound_platform_driver->late_init();
    }
    
    command_register("lsdev", "prints hal devices tree", lsdev_cmd);
}

