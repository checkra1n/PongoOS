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
#include <pongo.h>

struct atc {
    uint64_t regBase;
};

struct drd {
    uint64_t regBase;
    struct task* irq_task;
    struct hal_device* atc_device;
    struct hal_device* mapper;
    struct hal_device* device;
};


static void drd_irq_handle() {
    puts("drd irq");
}

static void drd_irq_task() {
    while (1) {
        disable_interrupts();
        drd_irq_handle();
        enable_interrupts();
        task_exit_irq();
    }

}
static int drd_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    return -1;
}
static int atc_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    return -1;
}
static bool register_drd(struct hal_device* device, void** context) {
    // DesignWare DWC3 Dual Role Device
    struct drd* drd = calloc(sizeof(struct drd), 1);
    drd->mapper = hal_get_mapper(device, 0);

    hal_invoke_service_op(drd->mapper, "dart", DART_CLOCK_GATE_ON, NULL, 0, NULL, NULL);

    clock_gate(0x23b700420, 1);
    clock_gate(0x23d280088, 1);
    clock_gate(0x23d280098, 1);
    
    hal_invoke_service_op(drd->mapper, "dart", DART_ENTER_BYPASS_MODE, NULL, 0, NULL, NULL);
    drd->regBase = (uint64_t)hal_map_registers(device, 0, NULL);
    drd->device = device;
    drd->irq_task = task_create_extended("uart", drd_irq_task, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);

    task_bind_to_irq(drd->irq_task, hal_get_irqno(device, 0));

    uint32_t len = 0;
    uint32_t* val = dt_prop(device->node, "atc-phy-parent", &len);

    if (val && len >= 4) {
        drd->atc_device = hal_get_phandle_device(*val);
    } else {
        panic("unknown atc-phy-parent!");
    }
    
    *context = drd;
    return true;
}

static bool register_atc(struct hal_device* device, void** context) {
    // Apple Type C PHY
    
    return false;
}

static bool atc_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "atc-phy") == 0) {
            return register_atc(device, context);
        }
    }
    return false;
}

static bool drd_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "usb-drd") == 0) {
            return register_drd(device, context);
        }
    }
    return false;
}
static struct hal_service drd_svc = {
    .name = "drd",
    .probe = drd_probe,
    .service_op = drd_service_op
};
static struct hal_service atc_svc = {
    .name = "atc",
    .probe = atc_probe,
    .service_op = atc_service_op
};

static void drd_init(struct driver* driver) {
    hal_register_hal_service(&drd_svc);
    hal_register_hal_service(&atc_svc);
}

REGISTER_DRIVER(drd, drd_init, NULL, 0);
