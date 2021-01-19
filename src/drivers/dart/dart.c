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
#import "dart.h"

struct t8020_dart {
    uint64_t dart_type;
    uint64_t dart_regbase;
};

struct task* dart_irq_task;

void dart_irq_handler() {
    while (1) {
        // struct t8020_dart* dart = task_current_interrupt_context();
        panic("DART IRQ received!");
        task_exit_irq();
    }
}

static bool register_dart_mapper(struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    dt_node_t* pnode = device->parent->node;

    if (strcmp(dt_prop(pnode, "compatible", &len), "dart,t8020") == 0) {
        uint32_t* regid = dt_prop(node, "reg", &len);
        if (len != 4) regid = NULL;
        
        void* val = dt_prop(node, "name", &len);

        uint32_t reg_index = device->phandle - device->parent->phandle;
        reg_index--;
        
        if (regid) {
            reg_index = *regid;
        }

        void* regs = hal_map_registers(device->parent, reg_index, NULL);
        
        if (!regs) {
            iprintf("Couldn't map MMIO for 8020 dart-mapper: %s\n", val);
            return false;
        }
        
        struct t8020_dart* dart = calloc(sizeof(struct t8020_dart), 1);
        dart->dart_type = 0x8020;
        dart->dart_regbase = (uint64_t) regs;
        
        int dart_irq = hal_get_irqno(device->parent, 0);
        if (dart_irq > 0) {
            if (!interrupt_context(dart_irq)) {
                if (!dart_irq_task) {
                    dart_irq_task = task_create_extended("dart", dart_irq_handler, TASK_IRQ_HANDLER, 0);
                }
                task_bind_to_irq(dart_irq_task, dart_irq);
                interrupt_associate_context(dart_irq, dart);
            }
        }
        
        iprintf("Found 8020 dart-mapper: %s @ %llx\n", val, dart->dart_regbase);

        *context = dart;
        return true;
    }
    
    return false;
}

static bool dart_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "dart-mapper") == 0) {
            return register_dart_mapper(device, context);
        }
    }
    return false;
}

static int dart_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    struct t8020_dart* dart = ((struct t8020_dart*)svc->context);
    
    if (method == DART_ENTER_BYPASS_MODE) {
        if (dart->dart_type == 0x8020) {
            *(volatile uint32_t*)(dart->dart_regbase + 0x100) = 0x80000 | 0x10;
            return dart_service_op(svc, device, DART_FLUSH_CACHE, NULL, 0, NULL, 0);
        }
    } else if (method == DART_FLUSH_CACHE) {
        if (dart->dart_type == 0x8020) {
            *(volatile uint32_t*)(dart->dart_regbase + 0x34) = 0;
            *(volatile uint32_t*)(dart->dart_regbase + 0x20) = 0;
            while(*(volatile uint32_t*)(dart->dart_regbase + 0x20) & 4) {}
            
            return 0;
        }
    }
    return -1;
}

static struct hal_service dart_svc = {
    .name = "dart",
    .probe = dart_probe,
    .service_op = dart_service_op
};

static void dart_init(struct driver* driver) {
    hal_register_hal_service(&dart_svc);
}

REGISTER_DRIVER(dart, dart_init, NULL, 0);
