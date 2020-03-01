//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef SYNOPSYS_OTG_REGS__H_
#define SYNOPSYS_OTG_REGS__H_

#ifndef SYNOPSYS_OTG_REGISTER
#define SYNOPSYS_OTG_REGISTER(_x)	(_x)
#endif

#define rGOTGCTL	(SYNOPSYS_OTG_REGISTER(0x000))
#define rGOTGINT	(SYNOPSYS_OTG_REGISTER(0x004))
#define rGAHBCFG	(SYNOPSYS_OTG_REGISTER(0x008))
#define rGUSBCFG	(SYNOPSYS_OTG_REGISTER(0x00c))
#define rGRSTCTL	(SYNOPSYS_OTG_REGISTER(0x010))
#define rGINTSTS	(SYNOPSYS_OTG_REGISTER(0x014))
#define rGINTMSK	(SYNOPSYS_OTG_REGISTER(0x018))
#define rGRXSTSR	(SYNOPSYS_OTG_REGISTER(0x01c))
#define rGRXSTSP	(SYNOPSYS_OTG_REGISTER(0x020))
#define rGRXFSIZ	(SYNOPSYS_OTG_REGISTER(0x024))
#define rGNPTXFSIZ	(SYNOPSYS_OTG_REGISTER(0x028))
#define rGNPTXSTS	(SYNOPSYS_OTG_REGISTER(0x02c))
#define rGI2CCTL	(SYNOPSYS_OTG_REGISTER(0x030))
#define rGPVNDCTL	(SYNOPSYS_OTG_REGISTER(0x034))
#define rGGPIO		(SYNOPSYS_OTG_REGISTER(0x038))
#define rGUID		(SYNOPSYS_OTG_REGISTER(0x03c))
#define rGSNPSID	(SYNOPSYS_OTG_REGISTER(0x040))
#define rGHWCFG1	(SYNOPSYS_OTG_REGISTER(0x044))
#define rGHWCFG2	(SYNOPSYS_OTG_REGISTER(0x048))
#define rGHWCFG3	(SYNOPSYS_OTG_REGISTER(0x04c))
#define rGHWCFG4	(SYNOPSYS_OTG_REGISTER(0x050))
#define rGLPMCFG	(SYNOPSYS_OTG_REGISTER(0x054))
#define rGPWRDN		(SYNOPSYS_OTG_REGISTER(0x058))
#define rGDFIFOCFG	(SYNOPSYS_OTG_REGISTER(0x05c))
#define rADPCTL		(SYNOPSYS_OTG_REGISTER(0x060))

#define rHPTXFSIZ	(SYNOPSYS_OTG_REGISTER(0x100))
#define rDTXFSIZ(n)	(SYNOPSYS_OTG_REGISTER(0x104 + 0x4 * (n - 1)))

#define rHPTXSIZ	(SYNOPSYS_OTG_REGISTER(0x400))

#define rHPRT0		(SYNOPSYS_OTG_REGISTER(0x440))

#define rDCFG		(SYNOPSYS_OTG_REGISTER(0x800))
#define rDCTL		(SYNOPSYS_OTG_REGISTER(0x804))
#define rDSTS		(SYNOPSYS_OTG_REGISTER(0x808))
#define rDIEPMSK	(SYNOPSYS_OTG_REGISTER(0x810))
#define rDOEPMSK	(SYNOPSYS_OTG_REGISTER(0x814))
#define rDAINT		(SYNOPSYS_OTG_REGISTER(0x818))
#define rDAINTMSK	(SYNOPSYS_OTG_REGISTER(0x81c))

#define rDIEPCTL(ep)	(SYNOPSYS_OTG_REGISTER(0x900 + 0x20 * ep))
#define rDIEPINT(ep)	(SYNOPSYS_OTG_REGISTER(0x908 + 0x20 * ep))
#define rDIEPTSIZ(ep)	(SYNOPSYS_OTG_REGISTER(0x910 + 0x20 * ep))
#define rDIEPDMA(ep)	(SYNOPSYS_OTG_REGISTER(0x914 + 0x20 * ep))
#define rDTXFSTS(ep)	(SYNOPSYS_OTG_REGISTER(0x918 + 0x20 * ep))
#define rDIEPDMAB(ep)	(SYNOPSYS_OTG_REGISTER(0x91c + 0x20 * ep))

#define rDOEPCTL(ep)	(SYNOPSYS_OTG_REGISTER(0xb00 + 0x20 * ep))
#define rDOEPINT(ep)	(SYNOPSYS_OTG_REGISTER(0xb08 + 0x20 * ep))
#define rDOEPTSIZ(ep)	(SYNOPSYS_OTG_REGISTER(0xb10 + 0x20 * ep))
#define rDOEPDMA(ep)	(SYNOPSYS_OTG_REGISTER(0xb14 + 0x20 * ep))
#define rDOEPDMAB(ep)	(SYNOPSYS_OTG_REGISTER(0xb1c + 0x20 * ep))

#endif
