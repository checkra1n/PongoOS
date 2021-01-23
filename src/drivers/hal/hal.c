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

void hal_probe_hal_services(struct hal_device* device, bool isEarlyProbe) ;

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
        
        hal_probe_hal_services(device, true);
        
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
        
        hal_probe_hal_services(ndevice, false);
        
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

        if (index < device->nr_device_maps && device->device_maps[index].size) {
            struct device_regs * regs = &device->device_maps[index];
            ((void**)data_out)[0] = (void*)regs->base;
            ((void**)data_out)[1] = (void*)regs->size;
            return 0;
        }
        
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
    
        struct device_regs * regs = val;
        
        uint64_t regbase = regs[index].base;
        uint64_t size = regs[index].size;

        void* pmap = ((void**)data_out)[0] = (void*)hal_map_physical_mmio(regbase, size);
        ((void**)data_out)[1] = (void*)regs[index].size;

        uint32_t old_maps_size = device->nr_device_maps;
        uint32_t new_maps_size = old_maps_size;
        if (!new_maps_size) new_maps_size = 8;

        while (index >= new_maps_size) {
            new_maps_size *= 2;
        }

        if (old_maps_size != new_maps_size) {
            struct device_regs * new_map_regs = calloc(sizeof(struct device_regs), new_maps_size);
            if (old_maps_size) {
                memcpy(new_map_regs, device->device_maps, sizeof(struct device_regs) * old_maps_size);
            }
            device->device_maps = new_map_regs;
            device->nr_device_maps = new_maps_size;
        }
        
        device->device_maps[index].base = (uint64_t)pmap;
        device->device_maps[index].size = size;

        
        return 0;
    } else if (method == HAL_DEVICE_CLOCK_GATE_ON || method == HAL_DEVICE_CLOCK_GATE_OFF) {
        int32_t count = hal_get_clock_gate_size(device);
        if (count > 0) {
            for (int i=0; i < count; i++) {
                int32_t clock_gate_id = hal_get_clock_gate_id(device, i);
                if (clock_gate_id > 0) {
                    uint64_t clock = device_clock_by_id(clock_gate_id);
                    if (clock) {
                        clock_gate(clock, method == HAL_DEVICE_CLOCK_GATE_ON);
                    }
                }
            }
            return 0;
        }
        return -1;
    }
    
    return -1;
}

struct range_translation_entry {
    uint64_t reg_base;
    uint64_t phys_base;
    uint64_t size;
} range_translation [64];

uint32_t range_translation_entries = 0;

uint64_t translate_register_address(uint64_t address) {
    for (int i=0; i < range_translation_entries; i++) {
        if (address >= range_translation[i].reg_base && address < range_translation[i].reg_base + range_translation[i].size) {
            return address - range_translation[i].reg_base + range_translation[i].phys_base;
        }
    }
    panic("couldn't find address %llx in arm-io map", address);
    return -1;
}

int hal_apply_tunables(struct hal_device* device, const char* tunable_dt_entry_name) {
    if (!tunable_dt_entry_name) {
        tunable_dt_entry_name = "tunables";
    }
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return -1;
    
    struct tunable_array {
        uint32_t reg_index;
        uint32_t reg_offset;
        uint32_t reg_bits_to_clear;
        uint32_t reg_bits_to_set;
    };
    
    struct tunable_array* val = dt_prop(node, tunable_dt_entry_name, &len);
    if (!val) {
        return -1;
    }
    if (len & 0xf) {
        panic("hal_apply_tunables: my understanding of tunables is 4x uint32_t, but len is not a multiple of 0x10...");
    }
    
    uint32_t tunable_cnt = len / 0x10;
    for (uint32_t i=0; i < tunable_cnt; i++) {
        size_t sz = 0;
        uint64_t regbase = (uint64_t) hal_map_registers(device, val[i].reg_index, &sz);
        if (!regbase) {
            panic("hal_apply_tunables: invalid reg_index (%d)", val[i].reg_index);
        }
        if ((val[i].reg_offset + 4) > sz) {
            panic("hal_apply_tunables: OOB access (%d > %d)", val[i].reg_offset, sz);
        }
        uint32_t value = *(volatile uint32_t*)(regbase + val[i].reg_offset);

        value &= ~val[i].reg_bits_to_clear;
        value |= val[i].reg_bits_to_set;

        *(volatile uint32_t*)(regbase + val[i].reg_offset) = value;
    }
    return 0;
}

uint64_t hal_map_physical_mmio(uint64_t regbase, uint64_t size) {
    regbase = translate_register_address(regbase);
    uint64_t offset = regbase & 0x3fff;
    regbase &= ~0x3fff;

    size += offset;

    size +=  0x3FFF;
    size &= ~0x3FFF;
    uint64_t va = linear_kvm_alloc(size);
    
    map_range_map((uint64_t*)kernel_vm_space.ttbr0, va, regbase, size, 3, 0, 1, 0, PROT_READ|PROT_WRITE, !!(va & 0x7000000000000000));

    for (uint32_t i=0; i < size; i+=0x1000) {
        vm_flush_by_addr_all_asid(va + i);
    }

    return va + offset;
}

int32_t hal_get_clock_gate_id(struct hal_device* device, uint32_t index) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return -1;

    int32_t* val = dt_prop(node, "clock-gates", &len);
    if (!val || index * 4 >= len) {
        return -1;
    }
    return val[index];
}
int32_t hal_get_clock_gate_size(struct hal_device* device) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return -1;
    dt_prop(node, "clock-gates", &len);
    return len / 4;
}
extern struct hal_device* gInterruptDevice;
int32_t hal_get_irqno(struct hal_device* device, uint32_t index) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return -1;

#if 0
    int32_t* pval = dt_prop(node, "interrupt-parent", &len);
    int32_t irqparent = *pval;
    
    if (hal_get_phandle_device(irqparent) != gInterruptDevice) {
        panic("hal_get_irqno: only supported for AIC interrupt children");
    }
#endif
    
    int32_t* val = dt_prop(node, "interrupts", &len);
    if (!val || index * 4 >= len) {
        return -1;
    }
    return val[index];
}
bool hal_unmask_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irq", IRQ_UNMASK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_mask_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irq", IRQ_MASK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_ack_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irq", IRQ_ACK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_register_interrupt(struct hal_device* device, struct task* task, uint32_t irqno, void* context) {
    struct irq_register_args args = {
        .irq = irqno,
        .task = task,
        .context = context
    };
    if (hal_invoke_service_op(device, "irq", IRQ_REGISTER, &args, sizeof(args), NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_controller_unmask_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irqctrl", IRQ_UNMASK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_controller_mask_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irqctrl", IRQ_MASK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_controller_ack_interrupt(struct hal_device* device, uint32_t reg) {
    if (hal_invoke_service_op(device, "irqctrl", IRQ_ACK, &reg, 4, NULL, 0)) {
        return false;
    }
    return true;
}
bool hal_controller_register_interrupt(struct hal_device* device, struct task* task, uint32_t irqno, void* context) {
    struct irq_register_args args = {
        .irq = irqno,
        .task = task,
        .context = context
    };
    if (hal_invoke_service_op(device, "irqctrl", IRQ_REGISTER, &args, sizeof(args), NULL, 0)) {
        return false;
    }
    return true;
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
    .service_op = hal_service_op,
    .flags = SERVICE_FLAGS_EARLY_PROBE
};

int hal_invoke_service_op(struct hal_device* device, const char* svc_name, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    struct hal_device_service* svc = device->services;
    
    bool metaservice_lookup = false;
    if (((method & METASERVICE_TAG_MASK) == HAL_METASERVICE_TAG)) {
        metaservice_lookup = true;
    }
    
    while (svc) {
        if (strcmp(svc_name, svc->name) == 0 || metaservice_lookup) {
            if (svc->service->service_op) {
                int rv = svc->service->service_op(svc, device, method, data_in, data_in_size, data_out, data_out_size);
                if (!metaservice_lookup) {
                    return rv;
                }
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
void hal_associate_service(struct hal_device* device, struct hal_service* svc, void* ctx) {
    struct hal_device_service* hds = malloc(sizeof(struct hal_device_service));
    hds->name = svc->name;
    hds->service = svc;
    hds->context = ctx;
    hds->next = device->services;
    device->services = hds;
}
void hal_probe_hal_services(struct hal_device* device, bool isEarlyProbe) {
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
        if (!(svc->flags & SERVICE_FLAGS_EARLY_PROBE)) {
            if (isEarlyProbe) {
                svc = svc->next;
                continue;
            }
        } else {
            if (device->flags & DEVICE_HAS_BEEN_PROBED_EARLY) {
                svc = svc->next;
                continue;
            }
        }
        if (svc->probe) {
            void* ctx = NULL;
            if (svc->probe(svc, device, &ctx)) {
                hal_associate_service(device, svc, ctx);
            }
        }
        svc = svc->next;
    }
    
    if (isEarlyProbe) {
        device->flags |= DEVICE_HAS_BEEN_PROBED_EARLY;
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


void hal_late_probe_hal_services_cb(struct hal_device* dev, int depth) {
    if (gDeviceTreeDevice == dev) return;
    
    hal_probe_hal_services(dev, false);
}
void hal_late_probe_hal_services() {
    recurse_device(gDeviceTreeDevice, 0, hal_late_probe_hal_services_cb);
}
void hal_issue_recursive_start_cb(struct hal_device* dev, int depth) {
    hal_invoke_service_op(dev, "hal", HAL_METASERVICE_START, NULL, 0, NULL, NULL);
}
void hal_issue_recursive_start() {
    recurse_device(gDeviceTreeDevice, 0, hal_issue_recursive_start_cb);
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

static bool irq_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        int32_t* pval = dt_prop(node, "interrupt-parent", &len);
        if (pval) {
            int32_t irqparent = *pval;
            *context = (void*)(uintptr_t)irqparent;
            return true;
        }
    }
    return false;
}

static int irq_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    struct hal_device* irq_ctrl_parent = hal_get_phandle_device((uint32_t) svc->context);
    if (irq_ctrl_parent) {
        if (method == IRQ_MASK && data_in_size == 4) {
            uint32_t irq_index = *(uint32_t*)data_in;
            int32_t irq_number = hal_get_irqno(device, irq_index);
            if (irq_number < 0) {
                return -1;
            }
            
            return hal_controller_mask_interrupt(irq_ctrl_parent, irq_number) == 0 ? true : false; // redirect request to interrupt controller
        } else if (method == IRQ_UNMASK && data_in_size == 4) {
            uint32_t irq_index = *(uint32_t*)data_in;
            int32_t irq_number = hal_get_irqno(device, irq_index);
            if (irq_number < 0) {
                return -1;
            }
            return hal_controller_unmask_interrupt(irq_ctrl_parent, irq_number) == 0 ? true : false; // redirect request to interrupt controller
        } else if (method == IRQ_ACK) {
            uint32_t irq_index = *(uint32_t*)data_in;
            int32_t irq_number = hal_get_irqno(device, irq_index);
            if (irq_number < 0) {
                return -1;
            }
            return hal_controller_ack_interrupt(irq_ctrl_parent, irq_number) == 0 ? true : false; // redirect request to interrupt controller
        } else if (method == IRQ_REGISTER && data_in_size == sizeof(struct irq_register_args)) {
            struct irq_register_args* args = data_in;
            
            int32_t irq_number = hal_get_irqno(device, args->irq);
            if (irq_number < 0) {
                return -1;
            }
            return hal_controller_register_interrupt(irq_ctrl_parent, args->task, irq_number, args->context) == 0 ? true : false; // redirect request to interrupt controller
        }
    }
    return -1;
}

static struct hal_service irq_svc = {
    .name = "irq",
    .probe = irq_probe,
    .service_op = irq_service_op
};


void hal_init() {
    gPlatform = NULL;
    gRootDevice = &_gRootDevice;
    
    dt_node_t* dev = dt_find(gDeviceTree, "arm-io");
    if (!dev) panic("invalid devicetree: no arm-io!");
    uint32_t len = 0;
    
    uint64_t* val = dt_prop(dev, "ranges", &len);
    if (!val) panic("invalid devicetree: no prop!");
    
    len /= 0x18;
    
    for (int i=0; i < len; i++) { // basically a memcpy but for clarity...
        range_translation[i].reg_base = val[i*3];
        range_translation[i].phys_base = val[i*3 + 1];
        range_translation[i].size = val[i*3 + 2];
        range_translation_entries++;
        if (range_translation_entries > 64) panic("too many entries in arm-io");
    }
    
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
    hal_register_hal_service(&irq_svc);

    hal_probe_hal_services(gRootDevice, true);
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
    
    hal_late_probe_hal_services();
    
    command_register("lsdev", "prints hal devices tree", lsdev_cmd);
}

bool hal_device_is_compatible(struct hal_device* device, const char* name) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (!node) return false;
    
    char* compat = dt_prop(node, "compatible", &len);
    if (!compat) {
        return false;
    }
    
    char* compatend = compat + len;
    while (compat < compatend) {
        if (strcmp(compat, name) == 0) {
            return true;
        }
        compat += strlen(compat) + 1;
    }
    return false;
}
