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

// cleanroom from  https://edc.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/comet-lake-u/intel-400-series-chipset-on-package-platform-controller-hub-register-database/global-core-control-gctl-offset-c110/

#include <pongo.h>
#define REG_LOG

struct drd {
    uint64_t regBase;
    uint64_t configRegBase;
    uint64_t pipeHandlerRegBase;
    uint64_t coreEvtRegBase;
    uint64_t ausbCtlRegBase;
    uint64_t ausbBulkFabricRegBase;
    uint64_t atcLinkRegBase;
    uint64_t atcRegBase;
    
    struct task* irq_task;
    struct hal_device* atc_device;
    struct hal_device* mapper;
    struct hal_device* device;
};

__unused static uint32_t drd_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->regBase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}
__unused static uint32_t atc_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->atcRegBase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "atc_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}
__unused static uint32_t pipehandler_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->pipeHandlerRegBase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "pipehandler_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}

__unused static void drd_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->regBase + offset) = value;
}
__unused static void atc_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "atc_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->atcRegBase + offset) = value;
}
__unused static void pipehandler_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "pipehandler_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->pipeHandlerRegBase + offset) = value;
}

__unused static void drd_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_and(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->regBase + offset) &= value;
}
__unused static void atc_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "atc_reg_and(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->atcRegBase + offset) &= value;
}
__unused static void pipehandler_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "pipehandler_reg_and(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->pipeHandlerRegBase + offset) &= value;
}

__unused static void drd_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_or(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->regBase + offset) |= value;
}
__unused static void atc_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "atc_reg_or(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->atcRegBase + offset) |= value;
}
__unused static void pipehandler_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "pipehandler_reg_or(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->pipeHandlerRegBase + offset) |= value;
}

#include "synopsys_drd_regs.h"

static void USB_DEBUG_PRINT_REGISTERS(struct drd* drd) {
    disable_interrupts();
#define USB_DEBUG_REG_VALUE(reg) fiprintf(stderr, ""#reg " = 0x%x\n", drd_reg_read(drd, reg));
    USB_DEBUG_REG_VALUE(G_GSNPSID);
    USB_DEBUG_REG_VALUE(G_GCTL);
    USB_DEBUG_REG_VALUE(G_GSTS);
    enable_interrupts();
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
static void drd_bringup(struct drd* drd) {
    uint32_t reg;
    
    pipehandler_reg_and(drd, P_PHY_MUX_SELECT, ~PIPE_CLK_EN);

    pipehandler_reg_and(drd, P_PHY_MUX_SELECT, ~PIPE_MODE);

    reg = pipehandler_reg_read(drd, P_PHY_MUX_SELECT);
    reg &= ~PIPE_CLK_EN;
    reg |= 0x8;
    pipehandler_reg_write(drd, P_PHY_MUX_SELECT, reg);

    reg = pipehandler_reg_read(drd, P_PHY_MUX_SELECT);
    reg &= ~PIPE_MODE;
    reg |= 0x2;
    pipehandler_reg_write(drd, P_PHY_MUX_SELECT, reg);

    reg = pipehandler_reg_read(drd, P_PHY_MUX_SELECT);
    reg &= ~PIPE_CLK_EN;
    reg |= 0x20;
    pipehandler_reg_write(drd, P_PHY_MUX_SELECT, reg);

    pipehandler_reg_and(drd, P_LOCK_PIPE_IF_REQ, ~1);
    
    while (pipehandler_reg_read(drd, P_LOCK_PIPE_IF_ACK) & 1) {
        ;;
    }
    
    drd_reg_and(drd, G_GUSB2PHYCFG, ~SUSPENDUSB20);
    drd_reg_and(drd, G_GUSB3PIPECTL, ~SUSPENDENABLE);
    
    pipehandler_reg_and(drd, P_AON_GENERAL_REGS, ~ATC_USB31_DRD_FORCE_CLAMP_EN);
    
    pipehandler_reg_or(drd, P_AON_GENERAL_REGS, ATC_USB31_DRD_SW_VCC_RESET);

    drd_reg_or(drd, G_GCTL, GCTL_DSBLCLKGTNG);
    drd_reg_or(drd, G_GCTL, GCTL_CORESOFTRESET);
    drd_reg_and(drd, G_GCTL, ~GCTL_CORESOFTRESET);
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
    
    if (strcmp(dt_prop(device->node, "compatible", &len), "usb-drd,t8103") == 0) {
        drd->regBase = (uint64_t)hal_map_registers(drd->device, 2, NULL);
        drd->configRegBase = (uint64_t)hal_map_registers(drd->device, 1, NULL);
        drd->pipeHandlerRegBase = (uint64_t)hal_map_registers(drd->device, 3, NULL);
        drd->coreEvtRegBase = (uint64_t)hal_map_registers(drd->device, 4, NULL);
        drd->ausbCtlRegBase = (uint64_t)hal_map_registers(drd->device, 6, NULL);
        drd->ausbBulkFabricRegBase = (uint64_t)hal_map_registers(drd->device, 7, NULL);
        drd->atcLinkRegBase = (uint64_t)hal_map_registers(drd->device, 8, NULL);
    } else {
        panic("unsupported usb-drd");
    }
    
    drd->atcRegBase = (uint64_t)hal_map_registers(drd->atc_device, 0, NULL);
    drd->irq_task = task_create_extended(drd->device->name, drd_irq_task, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);

    atc_bringup(drd);
    
    task_bind_to_irq(drd->irq_task, hal_get_irqno(device, 0));
    
    drd_bringup(drd);

    USB_DEBUG_PRINT_REGISTERS(drd);
    
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
