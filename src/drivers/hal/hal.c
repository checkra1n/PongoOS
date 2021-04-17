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
#import <pongo.h>
struct hal_device _gRootDevice = {
    .name = "root"
};
struct hal_device* gRootDevice, * gDeviceTreeDevice;

#define HAL_LOAD_XNU_DTREE 0
#define HAL_LOAD_DTREE_CHILDREN 1
#define HAL_CREATE_CHILD_DEVICE 2

void hal_probe_hal_services(struct hal_device* device) ;

static int hal_load_dtree_child_node(void* arg, dt_node_t* node) {
    struct hal_device* parentDevice = arg;
    if (parentDevice->node == node) return 0;
    
    uint32_t len = 0;
    void* val = dt_prop(node, "name", &len);
    if (val) {
        struct hal_device* device = malloc(sizeof(struct hal_device));
        device->next = parentDevice->down;
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

static int hal_service_op(struct hal_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_LOAD_XNU_DTREE) {
        device->node = gDeviceTree;
        return 0;
    } else if (method == HAL_LOAD_DTREE_CHILDREN && device->node) {
        // int dt_parse(dt_node_t* node, int depth, uint32_t* offp, int (*cb_node)(void*, dt_node_t*), void* cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void* cbp_arg)
        return dt_parse(device->node, 0, NULL, hal_load_dtree_child_node, device, NULL, NULL);
    } else if (method == HAL_CREATE_CHILD_DEVICE && data_out_size && *data_out_size == 8) {
        struct hal_device* ndevice = malloc(sizeof(struct hal_device));
        ndevice->next = device->down;
        device->down = ndevice;
        ndevice->node = NULL;
        ndevice->down = NULL;
        ndevice->name = strdup(data_in);
        
        hal_probe_hal_services(ndevice);
        
        *(void**)data_out = ndevice;
        
        return 0;
    }
    
    return -1;
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
            return svc->service->service_op(svc->service, device, method, data_in, data_in_size, data_out, data_out_size);
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

    command_register("lsdev", "prints hal devices tree", lsdev_cmd);

}

