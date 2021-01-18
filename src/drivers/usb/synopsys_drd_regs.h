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

// cleanroom from  https://edc.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/comet-lake-u/intel-400-series-chipset-on-package-platform-controller-hub-register-database/global-core-control-gctl-offset-c110/, ausb regs re'd from AppleUSBXDCIARM

#ifndef SYNOPSYS_DRD_REGS__H_
#define SYNOPSYS_DRD_REGS__H_

// AUSBC_PIPE_HANDLER

#define P_PHY_MUX_SELECT 0xC // register

#define PIPE_MODE 3 // bits within P_PHY_MUX_SELECT
#define PIPE_CLK_EN 0x38 // bits within P_PHY_MUX_SELECT

#define P_LOCK_PIPE_IF_REQ 0x10
#define P_LOCK_PIPE_IF_ACK 0x14
#define P_AON_GENERAL_REGS 0x1c
#define ATC_USB31_DRD_FORCE_CLAMP_EN 0x10 // bits within P_AON_GENERAL_REGS
#define ATC_USB31_DRD_SW_VCC_RESET 0x1 // bits within P_AON_GENERAL_REGS


#define G_GCTL 0x110
#define GCTL_DSBLCLKGTNG (1 << 0)
#define GCTL_CORESOFTRESET (1 << 11)

#define G_GSTS 0x118
#define G_GSNPSID 0x120
#define G_GUSB2PHYCFG 0x200
#define SUSPENDUSB20 0x40 // bits within G_GUSB2PHYCFG
#define G_GUSB3PIPECTL 0x2C0
#define SUSPENDENABLE 0x20000


#endif
