/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2020 checkra1n team, Copyright (c) 2016 The Fuchsia Authors
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

// usb regs from  https://edc.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/comet-lake-u/intel-400-series-chipset-on-package-platform-controller-hub-register-database/global-core-control-gctl-offset-c110/, , depcmd stuff from https://github.com/manux81/zircon.ext4/blob/8c1cb41b970722711477a5f4c709b9bc91f71bc6/system/dev/usb/dwc3/dwc3-regs.h (fuchsia project, Copyright 2016 The Fuchsia Authors).

#ifndef SYNOPSYS_DRD_REGS__H_
#define SYNOPSYS_DRD_REGS__H_

#define AUSBC_CFG_USB2PHY_BLK_USB_CTL 0
#define USB_MODE_MASK 0x7

#define AUSBC_CFG_USB2PHY_BLK_USB2PHY_CTL 4

#define USB2PHY_RESET 1
#define USB2PHY_PORT_RESET 2
#define USB2PHY_APB_RESETN 4
#define USB2PHY_SIDDQ 8

#define BLK_PIPE_HANDLER_NON_SELECTED_OVERRIDE 0x20
#define DUMMY_PHY_READY 0x8000

#define AUSBC_CFG_USB2PHY_BLK_USB2PHY_SIG 8
#define VBUS_DETECT_FORCE_VAL 1
#define VBUS_DETECT_FORCE_EN 2
#define VBUS_VALID_EXT_FORCE_VAL 4
#define VBUS_VALID_EXT_FORCE_EN 8

#define AUSBC_CFG_USB2PHY_BLK_USB2PHY_MISC_TUNE 0x1c
#define USB2PHY_REFCLK_GATEOFF 0x40000000
#define USB2PHY_APBCLK_GATEOFF 0x20000000

#define C0_UTMI_CLK_ACTIVE_EVT_CNT 0x20

// AUSBC_CTRLREG_BLK

#define AUSBC_FORCE_CLK_ON 0xf0

// AUSBC_PIPE_HANDLER

#define P_PHY_MUX_SELECT 0xC // register

#define PIPE_MODE 3 // bits within P_PHY_MUX_SELECT
#define PIPE_CLK_EN 0x38 // bits within P_PHY_MUX_SELECT

#define P_LOCK_PIPE_IF_REQ 0x10
#define P_LOCK_PIPE_IF_ACK 0x14
#define P_AON_GENERAL_REGS 0x1c
#define ATC_USB31_DRD_FORCE_CLAMP_EN 0x10 // bits within P_AON_GENERAL_REGS
#define ATC_USB31_DRD_SW_VCC_RESET 0x1 // bits within P_AON_GENERAL_REGS
#define USB31DRD_PIPE 0x20
#define PHY_READY 0x40000000

// Device Configuration Register
#define G_DCFG 0x700

#define DCFG_DEVSPD 0b111
#define DCFG_DEVSPD_SHIFT 0
#define DCFG_FULL_SPEED 0b001
#define DCFG_HIGH_SPEED 0b000
#define DCFG_SUPER_SPEED 0b100
#define DCFG_DEVADDR 0x3F8
#define DCFG_DEVADDR_SHIFT 3
#define DCFG_INTRNUM 0x1FC00
#define DCFG_INTRNUM_SHIFT 10
#define DCFG_NUMP 0x3E0000
#define DCFG_NUMP_SHIFT 17
#define DCFG_LPMCAP 0x400000

// Device Control Register
#define G_DCTL 0x704
#define DCTL_SOFTRESET (1 << 30)
#define DCTL_RUN_STOP (1 << 31)
#define DCTL_CORESOFTRESET (1 << 11)

// Device Event Enable Register
#define G_DEVTEN 0x708
#define DEVTEN_VENDEVTSTRCVDEN (1 << 12)
#define DEVTEN_ERRTICERREVTEN (1 << 9)
#define DEVTEN_WKUPEVTEN (1 << 4)
#define DEVTEN_ULSTCNGEN (1 << 3)
#define DEVTEN_CONNECTDONEEVTEN (1 << 2)
#define DEVTEN_USBRSTEVTEN (1 << 1)
#define DEVTEN_DISSCONNEVTEN (1 << 0)

// Device Status Register
#define G_DSTS 0x70c
#define DSTS_DEVCTRLHLT (1 << 22)

// Device Generic Command (DGCMD) – Offset c714
#define G_DGCMDPAR 0x710
#define G_DGCMD 0x714
#define DGCMD_CMDACT (1 << 10)
#define DGCMD_CMDMASK 0xf
#define DGCMD_CMDSTSMASK 0xF000
#define DGCMD_CMDSTSSHIFT 12

#define CMDTYP_SET_PERIODIC_REMINDERS 0x02
#define CMDTYP_SCRATCHPAD_LO 0x04
#define CMDTYP_SCRATCHPAD_HI 0x05
#define CMDTYP_TRANSMIT_DEVICE 0x07
#define CMDTYP_FIFO_FLUSH 0x09
#define CMDTYP_FIFO_FLUSH_ALL 0x0A
#define CMDTYP_EP_NRDY 0x0C
#define CMDTYP_EP_LOOPBACK_TEST 0x10

// Device Active USB Endpoint Enable (DALEPENA) – Offset c720
#define G_DALEPENA 0x720

#define G_GCTL 0x110
#define GCTL_DSBLCLKGTNG 1
#define GCTL_PRTCAPDIR(isDevice) ((isDevice ? 0b10 : 0b00) << 12)
#define GCTL_PWRDNSCALE(n) (((n) & 0x1fff) << 19)

#define G_GPMSTS 0x114

#define G_GSTS 0x118
#define G_GSNPSID 0x120
#define G_GUSB2PHYCFG 0x200
#define PHYSOFTRST (1 << 31)

#define SUSPENDUSB20 0x40 // bits within G_GUSB2PHYCFG
#define G_GUSB3PIPECTL 0x2C0
#define SUSPENDENABLE 0x20000

#define G_GEVNTADRLO(n) (0x400 + 0x10 * (n))
#define G_GEVNTADRHI(n) (0x404 + 0x10 * (n))
#define G_GEVNTSIZ(n) (0x408 + 0x10 * (n))
#define G_GEVNTCOUNT(n) (0x40c + 0x10 * (n))
#define GEVNTSIZ_EVNTINTRPTMASK (1 << 31)
#define G_GHWPARAMS(n) (0x140 + n * 4)

#define G_DEPCMDPAR2(n) (0x800 + 0x10 * (n))
#define G_DEPCMDPAR1(n) (0x804 + 0x10 * (n))
#define G_DEPCMDPAR0(n) (0x808 + 0x10 * (n))
#define G_DEPCMD(n) (0x80c + 0x10 * (n))

// Command Types for DEPCMD
#define DEPCFG                          1       // Set Endpoint Configuration
#define DEPXFERCFG                      2       // Set Endpoint Transfer Resource Configuration
#define DEPGETSTATE                     3       // Get EndpointState
#define DEPSSTALL                       4       // Set Stall
#define DEPCSTALL                       5       // Clear Stall
#define DEPSTRTXFER                     6       // Start Transfer
#define DEPUPDXFER                      7       // Update Transfer
#define DEPENDXFER                      8       // End Transfer
#define DEPSTARTCFG                     9       // Start New Configuration

#define DEPCMD_RESOURCE_INDEX(n)        (((n) & 0x7f) << 16)

// DEPCFG Params 0
#define DEPCFG_ACTION_INITIALIZE        (0 << 30)
#define DEPCFG_ACTION_RESTORE           (1 << 30)
#define DEPCFG_ACTION_MODIFY            (2 << 30)
#define DEPCFG_BURST_SIZE(n)            ((((n) - 1) & 0xf) << 22)
#define DEPCFG_FIFO_NUM(n)              (((n) & 0x1f) << 17)
#define DEPCFG_INTERNAL_RETRY           (1 << 15)
#define DEPCFG_MAX_PACKET_SIZE(n)       (((n) & 0x7ff) << 3)
#define DEPCFG_EP_TYPE(n)               (((n) & 0x3) << 1)

// DEPCFG Params 1
#define DEPCFG_FIFO_BASED               (1 << 31)
#define DEPCFG_EP_NUMBER(n)             (((n) & 0x1f) << 25)
#define DEPCFG_STREAM_CAPABLE           (1 << 24)
#define DEPCFG_INTERVAL(n)              (((n) & 0xff) << 16)
#define DEPCFG_EBC                      (1 << 15)   // External Buffer Control
#define DEPCFG_EBC_NO_WRITE_BACK        (1 << 14)   // Don't write back HWO bit to the TRB descriptor
#define DEPCFG_STREAM_EVT_EN            (1 << 13)
#define DEPCFG_XFER_NOT_READY_EN        (1 << 10)
#define DEPCFG_XFER_IN_PROGRESS_EN      (1 << 9)
#define DEPCFG_XFER_COMPLETE_EN         (1 << 8)
#define DEPCFG_INTR_NUM(n)              (((n) & 0x1f) << 0)

#define DEPCMD_CMDIOC                   (1 << 8)    // Command Interrupt on Complete
#define DEPCMD_CMDACT                   (1 << 10)   // Command Active

#define USB_ENDPOINT_CONTROL               0x00
#define USB_ENDPOINT_ISOCHRONOUS           0x01
#define USB_ENDPOINT_BULK                  0x02
#define USB_ENDPOINT_INTERRUPT             0x03

#define BUSERRADDR_LO 0x130
#define BUSERRADDR_HI 0x134


#endif
