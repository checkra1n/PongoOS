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
    uint64_t configRegBase;
    uint64_t pipeHandlerRegBase;
    uint64_t coreEvtRegBase;
    uint64_t ausbCtlRegBase;
    uint64_t ausbBulkFabricRegBase;
    uint64_t atcLinkRegBase;
    uint64_t atcRegBase;
    uint64_t atcRegBasePipe;

    uint64_t physBaseDMA;
    void* virtBaseDMA;
    
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
__unused static uint32_t atc3_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->atcRegBasePipe + offset);
#ifdef REG_LOG
    fiprintf(stderr, "atc3_reg_read(%x) = %x\n", offset, rv);
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
__unused static uint32_t ausb_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->ausbCtlRegBase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "ausb_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}
__unused static uint32_t configreg_reg_read(struct drd* drd, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(drd->configRegBase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "configreg_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}

__unused static void drd_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->regBase + offset) = value;
}
__unused static void drd_reg_write64(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "drd_reg_write64(%x) = %x\n", offset, value);
#endif
    *(volatile uint64_t *)(drd->regBase + offset) = value;
}
__unused static void atc_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "atc_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->atcRegBase + offset) = value;
}
__unused static void atc3_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "atc3_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->atcRegBasePipe + offset) = value;
}
__unused static void pipehandler_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "pipehandler_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->pipeHandlerRegBase + offset) = value;
}
__unused static void ausb_reg_write(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "ausb_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->ausbCtlRegBase + offset) = value;
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
__unused static void ausb_reg_and(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "ausb_reg_and(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->ausbCtlRegBase + offset) &= value;
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
__unused static void ausb_reg_or(struct drd* drd, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "ausb_reg_or(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(drd->ausbCtlRegBase + offset) |= value;
}

#include "synopsys_drd_regs.h"

static void USB_DEBUG_PRINT_REGISTERS(struct drd* drd) {
    disable_interrupts();
#define USB_DEBUG_REG_VALUE(reg) fiprintf(stderr, ""#reg " = 0x%x\n", drd_reg_read(drd, reg));
#define PHY_DEBUG_REG_VALUE(reg) fiprintf(stderr, ""#reg " = 0x%x\n", drd_reg_read(drd, reg));
    
    PHY_DEBUG_REG_VALUE(AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL);
    PHY_DEBUG_REG_VALUE(AUSBC_CFG_USB2PHY_BLK_USB2PHY_MISC_TUNE);
    
    USB_DEBUG_REG_VALUE(G_DCFG);
    USB_DEBUG_REG_VALUE(G_DCTL);
    USB_DEBUG_REG_VALUE(G_DSTS);
    USB_DEBUG_REG_VALUE(G_GSNPSID);
    USB_DEBUG_REG_VALUE(G_GCTL);
    USB_DEBUG_REG_VALUE(G_GSTS);
    USB_DEBUG_REG_VALUE(G_GPMSTS);
    USB_DEBUG_REG_VALUE(G_GUSB2PHYCFG);
    USB_DEBUG_REG_VALUE(G_GDBGFIFOSPACE);
    USB_DEBUG_REG_VALUE(G_GEVNTADRLO(0));
    USB_DEBUG_REG_VALUE(G_GEVNTADRHI(0));
    USB_DEBUG_REG_VALUE(G_GEVNTCOUNT(0));
    USB_DEBUG_REG_VALUE(G_GEVNTSIZ(0));
    USB_DEBUG_REG_VALUE(G_GPMSTS);
    USB_DEBUG_REG_VALUE(G_BUSERRADDR_LO);
    USB_DEBUG_REG_VALUE(G_BUSERRADDR_HI);
    USB_DEBUG_REG_VALUE(G_GSBUSCFG0);
    
    enable_interrupts();
}


__unused static int8_t drd_device_generic_command(struct drd* drd, uint32_t cmd, uint32_t arg) {
    drd_reg_write(drd, G_DGCMDPAR, arg);
    drd_reg_write(drd, G_DGCMD, (cmd & DGCMD_CMDMASK) | DGCMD_CMDACT);
    while (1) {
        uint32_t rd = drd_reg_read(drd, G_DGCMD);
        if (! (rd & DGCMD_CMDACT)) {
            return (rd & DGCMD_CMDSTSMASK) >> DGCMD_CMDSTSSHIFT;
        }
    }
}
__unused static int8_t drd_endpoint_command(struct drd* drd, uint32_t ep, uint32_t cmd, uint32_t arg0, uint32_t arg1, uint32_t arg2) {
    drd_reg_write(drd, G_DEPCMDPAR0(ep), arg0);
    drd_reg_write(drd, G_DEPCMDPAR1(ep), arg1);
    drd_reg_write(drd, G_DEPCMDPAR2(ep), arg2);
    drd_reg_write(drd, G_DEPCMD(ep), (cmd & DGCMD_CMDMASK));
    
    drd_reg_or(drd, G_DEPCMD(ep), DEPCMD_CMDACT);
    
    while (!(cmd & DEPCMD_CMDIOC)) {
        uint32_t rd = drd_reg_read(drd, G_DEPCMD(ep));
        if (! (rd & DEPCMD_CMDACT)) {
            return (rd & DGCMD_CMDSTSMASK) >> DGCMD_CMDSTSSHIFT;
        }
    }
    
    return 0;
}


#define ENDPOINT_EP0_OUT 0
#define ENDPOINT_EP0_IN 1
#define ENDPOINT_EP1_OUT 2
#define ENDPOINT_EP1_IN 3

void drd_endpoint_start_configuration(struct drd* drd, uint32_t ep, uint32_t rsrc) {
    if (drd_endpoint_command(drd, ep, DEPSTARTCFG | DEPCMD_RESOURCE_INDEX(rsrc) , 0, 0, 0)) {
        panic("drd_endpoint_set_configuration: drd_endpoint_command failed!");
    }
}
void drd_endpoint_set_configuration(struct drd* drd, uint32_t ep, uint32_t ep_type, uint32_t packetsz) {
    if (drd_endpoint_command(drd, ep, DEPCFG, DEPCFG_ACTION_INITIALIZE | DEPCFG_MAX_PACKET_SIZE(packetsz) | DEPCFG_EP_TYPE(ep_type), DEPCFG_FIFO_BASED | DEPCFG_EP_NUMBER(ep) | DEPCFG_XFER_NOT_READY_EN | DEPCFG_XFER_COMPLETE_EN | DEPCFG_INTR_NUM(0), 0)) {
        panic("drd_endpoint_set_configuration: drd_endpoint_command failed!");
    }
}

static void drd_irq_handle() {
    fiprintf(stderr, "drd irq\n");
    struct drd* drd = task_current_interrupt_context();

    while (1) {
        uint32_t elements = drd_reg_read(drd, G_GEVNTCOUNT(0));
        if (!elements) {
            break;
        }

        cache_invalidate(drd->virtBaseDMA, ((elements * 4) + 0x3f) & ~0x3f);
        
        volatile uint32_t* eventbuffer = drd->virtBaseDMA;
        
        for (uint32_t i = 0; i < elements; i++) {
            uint32_t event = eventbuffer[0xfff - i];
            fiprintf(stderr, "drd event: %x\n", event);
        }
        
        drd_reg_write(drd, G_GEVNTCOUNT(0), elements);
    }
}

static void drd_irq_task() {
    while (1) {
        disable_interrupts();
        drd_irq_handle();
        enable_interrupts();
        task_exit_irq();
    }

}
bool is_in_host_mode = true; // default value

__unused static void atc_enable_device(struct drd* drd, bool enable) {
    uint32_t reg = 0;
    if (enable) {
        reg = (atc_reg_read(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL) & ~USB_MODE_MASK) | 2;
    } else {
        spin(5 * 1000);
        reg = (atc_reg_read(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL) & ~USB_MODE_MASK) | 0;
    }
    atc_reg_write(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL, reg);
    
    hal_apply_tunables(drd->atc_device, "tunable-device");
    is_in_host_mode = false;
}

__unused static void atc_enable_host(struct drd* drd, bool enable) {
    uint32_t reg = 0;
    if (enable) {
        atc_reg_or(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_SIG, VBUS_DETECT_FORCE_VAL | VBUS_DETECT_FORCE_EN | VBUS_VALID_EXT_FORCE_VAL | VBUS_VALID_EXT_FORCE_EN);
        spin(10 * 1000);
        atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, ~USB2PHY_SIDDQ);
        spin(10 * 1000);
        atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, 0xFFFFFFFC);
        atc_reg_or(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_SIG, USB2PHY_APB_RESETN);
        atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_MISC_TUNE, 0x9FFFFFFFLL);

        reg = (atc_reg_read(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL) & ~USB_MODE_MASK) | 2;
        atc_reg_write(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL, reg);

    } else {
        spin(5 * 1000);
        reg = (atc_reg_read(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL) & ~USB_MODE_MASK) | 4;
        atc_reg_write(drd, AUSBC_CFG_USB2PHY_BLK_USB_CTL, reg);

        atc_reg_or(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, 0xb);
        atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, 0xFFFFFFFB);
        spin(10);
        atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_MISC_TUNE, 0x60000000LL);

    }
    is_in_host_mode = true;

    hal_apply_tunables(drd->atc_device, "tunable-host");

}
__unused static void atc_bringup(struct drd* drd) {
    atc_reg_or(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_SIG, VBUS_DETECT_FORCE_VAL | VBUS_DETECT_FORCE_EN | VBUS_VALID_EXT_FORCE_VAL | VBUS_VALID_EXT_FORCE_EN);
    spin(10 * 1000);
    atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, ~USB2PHY_SIDDQ);
    spin(10);
    atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, ~(USB2PHY_RESET|USB2PHY_PORT_RESET));
    atc_reg_or(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL, USB2PHY_APB_RESETN);
    atc_reg_and(drd, AUSBC_CFG_USB2PHY_BLK_USB2PHY_MISC_TUNE, ~(USB2PHY_REFCLK_GATEOFF | USB2PHY_APBCLK_GATEOFF));
    spin(30);
}

__unused static void enable_endpoint(struct drd* drd, uint8_t index) {
    drd_endpoint_start_configuration(drd, index, 0);
    drd_endpoint_set_configuration(drd, index, USB_ENDPOINT_CONTROL, EP0_MAX_PACKET_SIZE);
    drd_reg_or(drd, G_DALEPENA, 1 << index);
}

__unused static void drd_bringup(struct drd* drd) {
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
    
    ausb_reg_and(drd, AUSBC_FORCE_CLK_ON, ~0x1f);

    pipehandler_reg_or(drd, BLK_PIPE_HANDLER_NON_SELECTED_OVERRIDE, DUMMY_PHY_READY);

    pipehandler_reg_and(drd, P_AON_GENERAL_REGS, ~ATC_USB31_DRD_FORCE_CLAMP_EN);
    pipehandler_reg_or(drd, P_AON_GENERAL_REGS, ATC_USB31_DRD_SW_VCC_RESET);
    
    drd_reg_and(drd, G_GUSB2PHYCFG, ~SUSPENDUSB20);
    drd_reg_and(drd, G_GUSB3PIPECTL, ~SUSPENDENABLE);
    
    while (!(configreg_reg_read(drd, USB31DRD_PIPE) & PHY_READY)) {
        ;;
    }

    drd_reg_write(drd, G_DCTL, DCTL_SOFTRESET);
    while (drd_reg_read(drd, G_DCTL) & DCTL_SOFTRESET) {
        ;;
    }
    
    if (is_in_host_mode) {
        hal_apply_tunables(drd->device, "tunables");
        atc_enable_host(drd, true);
    } else {
        drd_reg_write(drd, G_GCTL, GCTL_DSBLCLKGTNG | GCTL_PRTCAPDIR(true) | GCTL_PWRDNSCALE(2));
        drd_reg_write(drd, G_DCFG, DCFG_HIGH_SPEED | (8 << 17));

        drd_reg_write(drd, G_GSBUSCFG0, (1 << 6));
        
        drd->virtBaseDMA = alloc_contig(0x4000);
        drd->physBaseDMA = vatophys_static((void*)drd->virtBaseDMA);
        
        uint64_t dartBaseDMA = 0;
        size_t dartBaseDMASize = 8;
        
        if (hal_invoke_service_op(drd->mapper, "dart", DART_BYPASS_CONVERT_PTR, &drd->physBaseDMA, 8, &dartBaseDMA, &dartBaseDMASize))
            panic("failed to translate address to DART address");
        
        uint32_t eventc = (drd_reg_read(drd, G_GHWPARAMS(1)) >> 15) & 0x3f;

        for (uint32_t i=0; i < eventc; i++) {
            drd_reg_write(drd, G_GEVNTSIZ(i), 0);
        }
        
        drd_reg_write64(drd, G_GEVNTADRLO(0), dartBaseDMA);
        drd_reg_write(drd, G_GEVNTADRHI(0), (dartBaseDMA >> 32ULL) & 0xffffffff);
        drd_reg_write(drd, G_GEVNTSIZ(0), 0x4000);
        drd_reg_write(drd, G_GEVNTCOUNT(0), 0);

        dartBaseDMA += 0x4000;
        
        drd_device_generic_command(drd, 4, dartBaseDMA & 0xffffffff);
        drd_device_generic_command(drd, 5, (dartBaseDMA >> 32ULL) & 0xffffffff);

        
        enable_endpoint(drd, ENDPOINT_EP0_OUT);

        drd_reg_or(drd, G_DEVTEN, DEVTEN_USBRSTEVTEN|DEVTEN_DISSCONNEVTEN|DEVTEN_CONNECTDONEEVTEN|DEVTEN_ULSTCNGEN|DEVTEN_WKUPEVTEN|DEVTEN_ERRTICERREVTEN|DEVTEN_VENDEVTSTRCVDEN);

        hal_apply_tunables(drd->device, "tunables");

        drd_reg_write(drd, G_DCTL, DCTL_RUN_STOP);
    }
}


static bool register_drd(struct hal_device* device, void* context) {
    // DesignWare DWC3 Dual Role Device
    
    struct drd* drd = context;

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

    if (hal_invoke_service_op(drd->mapper, "dart", DART_ENTER_BYPASS_MODE, NULL, 0, NULL, NULL))
        panic("drd: could not enter bypass mode");
    
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
    drd->atcRegBasePipe = (uint64_t)hal_map_registers(drd->atc_device, 1, NULL);

    drd->irq_task = task_create_extended(&drd->device->name[4], drd_irq_task, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);

    atc_bringup(drd);
    if (is_in_host_mode) {
        atc_enable_host(drd, true);
    } else {
        atc_enable_device(drd, true);
    }

    drd_bringup(drd);

    USB_DEBUG_PRINT_REGISTERS(drd);
    
    return true;
}
static int drd_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        struct drd* drd = svc->context;

        register_drd(device, drd);
        
        task_bind_to_irq(drd->irq_task, hal_get_irqno(drd->device,0));
        interrupt_associate_context(hal_get_irqno(drd->device,0), drd);

        return 0;
    }
    return -1;
}

static bool drd_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "usb-drd") == 0) {

            *context = calloc(sizeof(struct drd), 1);

            return true;
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
