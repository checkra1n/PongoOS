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

struct drd {
    uint64_t regBase;
    uint64_t atcRegBase;
    
    struct task* irq_task;
    struct hal_device* atc_device;
    struct hal_device* mapper;
    struct hal_device* device;
};

__unused static uint32_t drd_reg_read(struct drd* drd, uint32_t offset) {
    return *(volatile uint32_t *)(drd->regBase + offset);
}
__unused static uint32_t atc_reg_read(struct drd* drd, uint32_t offset) {
    return *(volatile uint32_t *)(drd->atcRegBase + offset);
}

__unused static void drd_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->regBase + offset) = value;
}
__unused static void atc_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->atcRegBase + offset) = value;
}

__unused static void drd_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->regBase + offset) &= value;
}
__unused static void atc_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->atcRegBase + offset) &= value;
}

__unused static void drd_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->regBase + offset) |= value;
}
__unused static void atc_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(drd->atcRegBase + offset) |= value;
}

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

static void atc_enable_device(struct drd* drd, bool enable) {
    uint32_t reg = 0;
    if (enable) {
        reg = atc_reg_read(drd, 0) & 0xFFFFFFF8;
    } else {
        spin(5 * 1000);
        reg = (atc_reg_read(drd, 0) & 0xFFFFFFF8) | 4;
    }
    atc_reg_write(drd, 0, reg);
}
static void atc_bringup(struct drd* drd) {
    atc_reg_or(drd, 0x8, 0x3);
    atc_reg_or(drd, 0x8, 0xc);
    spin(10 * 1000);
    atc_reg_and(drd, 0x4, 0xfffffff7);
    spin(10);
    atc_reg_and(drd, 0x4, 0xfffffffC);
    atc_reg_or(drd, 0x4, 0x4);
    atc_reg_or(drd, 0x1c, 0x9fffffff);
    spin(30);

    atc_enable_device(drd, true);
}

static int drd_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    return -1;
}
static bool register_drd(struct hal_device* device, void** context) {
    // DesignWare DWC3 Dual Role Device
    struct drd* drd = calloc(sizeof(struct drd), 1);
    drd->mapper = hal_get_mapper(device, 0);
    drd->device = device;

    uint32_t len = 0;
    uint32_t* val = dt_prop(device->node, "atc-phy-parent", &len);

    if (val && len >= 4) {
        drd->atc_device = hal_get_phandle_device(*val);
    } else {
        panic("unknown atc-phy-parent!");
    }

    hal_invoke_service_op(drd->mapper->parent, "hal", HAL_DEVICE_CLOCK_GATE_ON, NULL, 0, NULL, NULL);
    hal_invoke_service_op(drd->atc_device, "hal", HAL_DEVICE_CLOCK_GATE_ON, NULL, 0, NULL, NULL);
    hal_invoke_service_op(drd->device, "hal", HAL_DEVICE_CLOCK_GATE_ON, NULL, 0, NULL, NULL);

    hal_invoke_service_op(drd->mapper, "dart", DART_ENTER_BYPASS_MODE, NULL, 0, NULL, NULL);
    drd->regBase = (uint64_t)hal_map_registers(drd->device, 0, NULL);
    drd->atcRegBase = (uint64_t)hal_map_registers(drd->atc_device, 0, NULL);
    drd->irq_task = task_create_extended(drd->device->name, drd_irq_task, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);

    atc_bringup(drd);
    
    task_bind_to_irq(drd->irq_task, hal_get_irqno(device, 0));
    
    *context = drd;
    return true;
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

static void drd_init(struct driver* driver) {
    hal_register_hal_service(&drd_svc);
}

REGISTER_DRIVER(drd, drd_init, NULL, 0);
