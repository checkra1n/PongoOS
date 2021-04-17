//
// Project: KTRW Synopsys OTG USB controller driver
// Authors:  Brandon Azad <bazad@google.com>
// and qwertyuiop, Siguza, et al from the checkra1n team
//
// Copyright 2019 Google LLC
// Copyright 2019-2021 checkra1n team
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

#include <pongo.h>
uint64_t gSynopsysBase;
uint64_t gSynopsysOTGBase;
uint64_t gSynopsysComplexBase;
uint32_t gSynopsysCoreVersion;
struct _reg { uint32_t off; };
#define SYNOPSYS_OTG_REGISTER(_x)	((struct _reg) { _x })
#include "synopsys_otg_regs.h"

static uint32_t reg_read(struct _reg reg) {
	return *(volatile uint32_t *)(gSynopsysBase + reg.off);
}

static void reg_write(struct _reg reg, uint32_t val) {
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 2
	if (reg.off != rGINTSTS.off) {
		USB_DEBUG(USB_DEBUG_REG, "wr%03x %x", reg.off, val);
	}
#endif
	*(volatile uint32_t *)(gSynopsysBase + reg.off) = val;
}

static void reg_and(struct _reg reg, uint32_t val) {
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 2
	USB_DEBUG(USB_DEBUG_REG, "an%03x %x", reg.off, val);
#endif
	*(volatile uint32_t *)(gSynopsysBase + reg.off) &= val;
}

static void reg_or(struct _reg reg, uint32_t val) {
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 2
	USB_DEBUG(USB_DEBUG_REG, "or%03x %x", reg.off, val);
#endif
    *(volatile uint32_t *)(gSynopsysBase + reg.off) |= val;
}


static void USB_DEBUG_PRINT_REGISTERS();

static void USB_DEBUG_PRINT_REGISTERS() {
    disable_interrupts();
#define USB_DEBUG_REG_VALUE(reg) USB_DEBUG(USB_DEBUG_STANDARD, #reg " = 0x%x\n", reg_read(reg));
	USB_DEBUG_REG_VALUE(rGOTGCTL);
	USB_DEBUG_REG_VALUE(rGOTGINT);
	USB_DEBUG_REG_VALUE(rGAHBCFG);
	USB_DEBUG_REG_VALUE(rGUSBCFG);
	USB_DEBUG_REG_VALUE(rGRSTCTL);
	USB_DEBUG_REG_VALUE(rGINTSTS);
	USB_DEBUG_REG_VALUE(rGINTMSK);
	USB_DEBUG_REG_VALUE(rGRXSTSR);
	USB_DEBUG_REG_VALUE(rGRXSTSP);
	USB_DEBUG_REG_VALUE(rGRXFSIZ);
	USB_DEBUG_REG_VALUE(rGNPTXFSIZ);
	USB_DEBUG_REG_VALUE(rGNPTXSTS);
	USB_DEBUG_REG_VALUE(rGI2CCTL);
	USB_DEBUG_REG_VALUE(rGPVNDCTL);
	USB_DEBUG_REG_VALUE(rGGPIO);
	USB_DEBUG_REG_VALUE(rGUID);
	USB_DEBUG_REG_VALUE(rGSNPSID);
	USB_DEBUG_REG_VALUE(rGHWCFG1);
	USB_DEBUG_REG_VALUE(rGHWCFG2);
	USB_DEBUG_REG_VALUE(rGHWCFG3);
	USB_DEBUG_REG_VALUE(rGHWCFG4);
	USB_DEBUG_REG_VALUE(rGLPMCFG);
	USB_DEBUG_REG_VALUE(rGPWRDN);
	USB_DEBUG_REG_VALUE(rGDFIFOCFG);
	USB_DEBUG_REG_VALUE(rADPCTL);

	USB_DEBUG_REG_VALUE(rHPTXFSIZ);
	USB_DEBUG_REG_VALUE(rDTXFSIZ(0));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(1));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(2));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(3));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(4));

	USB_DEBUG_REG_VALUE(rDCFG);
	USB_DEBUG_REG_VALUE(rDCTL);
	USB_DEBUG_REG_VALUE(rDSTS);
	USB_DEBUG_REG_VALUE(rDIEPMSK);
	USB_DEBUG_REG_VALUE(rDOEPMSK);
	USB_DEBUG_REG_VALUE(rDAINT);
	USB_DEBUG_REG_VALUE(rDAINTMSK);

	USB_DEBUG_REG_VALUE(rDIEPCTL(0));
	USB_DEBUG_REG_VALUE(rDIEPINT(0));
	USB_DEBUG_REG_VALUE(rDIEPTSIZ(0));
	USB_DEBUG_REG_VALUE(rDIEPDMA(0));
	USB_DEBUG_REG_VALUE(rDTXFSTS(0));

	USB_DEBUG_REG_VALUE(rDOEPCTL(0));
	USB_DEBUG_REG_VALUE(rDOEPINT(0));
	USB_DEBUG_REG_VALUE(rDOEPTSIZ(0));
	USB_DEBUG_REG_VALUE(rDOEPDMA(0));

	USB_DEBUG_REG_VALUE(rDIEPCTL(1));
	USB_DEBUG_REG_VALUE(rDIEPINT(1));
	USB_DEBUG_REG_VALUE(rDIEPTSIZ(1));
	USB_DEBUG_REG_VALUE(rDIEPDMA(1));
	USB_DEBUG_REG_VALUE(rDTXFSTS(1));
    enable_interrupts();
}
struct task usb_task = {.name = "usb"};


static const char *string_descriptors[] = {
	[iManufacturer] = "checkra1n team",
	[iProduct]      = "pongoOS USB Device",
	[iSerialNumber] = ("pongoOS / checkra1n "PONGO_VERSION),
};

static const uint32_t string_descriptor_count = sizeof(string_descriptors) / sizeof(string_descriptors[0]);

struct device_descriptor device_descriptor = {
	.bLength            = sizeof(struct device_descriptor),
	.bDescriptorType    = 1,
	.bcdUSB             = 0x200,
	.bDeviceClass       = 0,
	.bDeviceSubClass    = 0,
	.bDeviceProtocol    = 0,
	.bMaxPacketSize0    = EP0_MAX_PACKET_SIZE,
	.idVendor           = 0x5ac,
	.idProduct          = 0x4141,
	.bcdDevice          = 0,
	.iManufacturer      = iManufacturer,
	.iProduct           = iProduct,
	.iSerialNumber      = iSerialNumber,
	.bNumConfigurations = 1,
};

struct full_configuration_descriptor {
	struct configuration_descriptor configuration;
	struct interface_descriptor     interface;
	struct endpoint_descriptor      endpoint_81;
	struct endpoint_descriptor      endpoint_02;
} __attribute__((packed));

struct full_configuration_descriptor configuration_descriptor = {
	.configuration = {
		.bLength             = sizeof(configuration_descriptor.configuration),
		.bDescriptorType     = 2,
		.wTotalLength        = sizeof(configuration_descriptor),
		.bNumInterfaces      = 1,
		.bConfigurationValue = 1,
		.iConfiguration      = iProduct,
		.bmAttributes        = 0x80,
		.bMaxPower           = 250,
	},
	.interface = {
		.bLength            = sizeof(configuration_descriptor.interface),
		.bDescriptorType    = 4,
		.bInterfaceNumber   = 0,
		.bAlternateSetting  = 0,
	        .bNumEndpoints      = 2,
		.bInterfaceClass    = 0xfe,
		.bInterfaceSubClass = 0x13,
		.bInterfaceProtocol = 0x37,
		.iInterface         = 0,
	},
	.endpoint_81 = {
		.bLength          = sizeof(configuration_descriptor.endpoint_81),
		.bDescriptorType  = 5,
		.bEndpointAddress = 0x81,	// IN
		.bmAttributes     = 3,		// Interrupt
		.wMaxPacketSize   = INTR_EP_MAX_PACKET_SIZE,
		.bInterval        = 1,		// Poll every 125us
	},
	.endpoint_02 = {
	        .bLength          = sizeof(configuration_descriptor.endpoint_02),
	        .bDescriptorType  = 5,
	        .bEndpointAddress = 0x02,    // OUT
	        .bmAttributes     = 2,        // Bulk
	        .wMaxPacketSize   = BULK_EP_MAX_PACKET_SIZE,
	        .bInterval        = 0,
	},
};

// ---- The KTRW USB API --------------------------------------------------------------------------

// These functions are provided by the layer below us.
void ep0_begin_data_in_stage(const void *data, uint32_t size, void (*callback)(void));
void ep0_begin_data_out_stage(bool (*callback)(const void *data, uint32_t size));

// The KTRW USB protocol supports 2 control transfer types:
//
//     - IN 0x41: Send data from KTRW to GDB.
//
//       wValue starts at 0 and is incremented each time the data is received successfully. That
//       way, if another request comes in for the same wValue index, we can detect that the
//       previous data was not received and resend it. (This feature isn't currently used.)
//
//       wIndex is 0x1337.
//
//     - OUT 0x41: Receive data from GDB to KTRW.
//
//       wValue starts at 0 and is incremented each time new data is sent. (This feature isn't
//       currently used.)
//
//       wIndex is 0x1337.
//

static uint8_t ktrw_send_data[0x1000];
static uint16_t ktrw_send_count;
static uint16_t ktrw_send_in_flight;

static uint8_t ktrw_recv_data[0x1000];
static uint16_t ktrw_recv_count;

static void
ktrw_send_done() {
	USB_DEBUG(USB_DEBUG_APP, "ktrw_send done");
	if (ktrw_send_in_flight > ktrw_send_count) {
		USB_DEBUG(USB_DEBUG_FATAL, "in_flight %u > %u send_count",
				ktrw_send_in_flight, ktrw_send_count);
		BUG(0x6966203e207363);	// 'if > sc'
	}
	uint16_t send_left = ktrw_send_count - ktrw_send_in_flight;
	memcpy(ktrw_send_data, ktrw_send_data + ktrw_send_in_flight, send_left);
	ktrw_send_count = send_left;
	ktrw_send_in_flight = send_left;
	if (send_left > 0) {
		USB_DEBUG(USB_DEBUG_APP, "ktrw_send'(%.*s)", (int) ktrw_send_in_flight,
				(char *) ktrw_send_data);
		usb_in_transfer(0x81, ktrw_send_data, send_left, ktrw_send_done);
	}
}

static bool
ktrw_recv_done(const void *data, uint32_t size) {
	uint16_t copy_size = sizeof(ktrw_recv_data) - ktrw_recv_count;
	if (copy_size < size) {
		return false;
	}
	if (copy_size > size) {
		copy_size = size;
	}
	USB_DEBUG(USB_DEBUG_APP, "ktrw_recv(%.*s)", (int) size, (char *) data);
	memcpy(ktrw_recv_data + ktrw_recv_count, data, copy_size);
	ktrw_recv_count += copy_size;
	return true;
}

static bool
ktrw_recv(uint16_t wLength) {
	uint16_t capacity = sizeof(ktrw_recv_data) - ktrw_recv_count;
	if (wLength > capacity) {
		return false;
	}
	ep0_begin_data_out_stage(ktrw_recv_done);
	return true;
}

extern bool ep0_device_request(struct setup_packet *setup);

static bool
ep0_vendor_request(struct setup_packet *setup) {
	if ((setup->bmRequestType & 0x80) == 0) {
		if (setup->bRequest == 0x41 && setup->wIndex == 0x1337) {
			return ktrw_recv(setup->wLength);
		}
	}
	return false;
}

size_t
usb_read(void *data, size_t size) {
	size_t read_size = ktrw_recv_count;
	if (read_size > size) {
		read_size = size;
	}
	memcpy(data, ktrw_recv_data, read_size);
	size_t recv_left = ktrw_recv_count - read_size;
	memcpy(ktrw_recv_data, ktrw_recv_data + read_size, recv_left);
	ktrw_recv_count = recv_left;
	return read_size;
}

size_t
usb_write(const void *data, size_t size) {
	size_t write_size = sizeof(ktrw_send_data) - ktrw_send_count;
	if (write_size > size) {
		write_size = size;
	}
	memcpy(ktrw_send_data + ktrw_send_count, data, write_size);
	ktrw_send_count += write_size;
	return write_size;
}

void
usb_write_commit() {
	if (ktrw_send_count > 0 && ktrw_send_in_flight == 0) {
		ktrw_send_in_flight = ktrw_send_count;
		USB_DEBUG(USB_DEBUG_APP, "ktrw_send(%.*s)", (int) ktrw_send_in_flight,
				(char *) ktrw_send_data);
		usb_in_transfer(0x81, ktrw_send_data, ktrw_send_count, ktrw_send_done);
	}
}

// ---- The high-level USB API --------------------------------------------------------------------

// USB functions needed by this level.
static void usb_set_address(uint8_t address);

#define MAX_USB_DESCRIPTOR_LENGTH	63

static bool
get_string_descriptor(uint8_t index) {
	if (index >= string_descriptor_count) {
		return false;
	}
	struct {
		struct string_descriptor descriptor;		// 2 bytes
		uint16_t utf16[MAX_USB_DESCRIPTOR_LENGTH];	// 126 bytes
	} sd;
	uint16_t length;
	if (index == 0) {
		length = 1;
		sd.utf16[0] = 0x0409;
	} else {
		const char *string = string_descriptors[index];
		length = strlen(string);
		if (length > MAX_USB_DESCRIPTOR_LENGTH) {
			length = MAX_USB_DESCRIPTOR_LENGTH;
		}
		for (uint8_t i = 0; i < length; i++) {
			sd.utf16[i] = string[i];
		}
	}
	uint16_t size = sizeof(sd.descriptor) + length * sizeof(sd.utf16[0]);
	sd.descriptor.bLength = size;
	sd.descriptor.bDescriptorType = 3;	// String descriptor
	ep0_begin_data_in_stage(&sd, size, NULL);
	return true;
}

static bool
ep0_get_descriptor_request(struct setup_packet *setup) {
	uint8_t type  = (uint8_t) (setup->wValue >> 8);
	uint8_t index = (uint8_t) (setup->wValue & 0xff);
	switch (type) {
		case 1:		// Device descriptor
			ep0_begin_data_in_stage(&device_descriptor,
					sizeof(device_descriptor), NULL);
			return true;
		case 2:		// Configuration descriptor
			ep0_begin_data_in_stage(&configuration_descriptor,
					sizeof(configuration_descriptor), NULL);
			return true;
		case 3:		// String descriptor
			return get_string_descriptor(index);
		default:
			goto invalid;
	}
invalid:
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled get descriptor type %d", type);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_in_request(struct setup_packet *setup) {
	switch (setup->bRequest) {
		case 6:		// GET_DESCRIPTOR
			return ep0_get_descriptor_request(setup);
		case 8:		// GET_CONFIGURATION
			ep0_begin_data_in_stage(&configuration_descriptor.configuration
					.bConfigurationValue, 1, NULL);
			return true;
		case 10:	// GET_INTERFACE
			ep0_begin_data_in_stage(&configuration_descriptor.interface
					.bAlternateSetting, 1, NULL);
			return true;
	}
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled standard IN request %d", setup->bRequest);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_out_request(struct setup_packet *setup) {
	switch (setup->bRequest) {
		case 5:		// SET_ADDRESS
			usb_set_address(setup->wValue & 0x7f);
			return true;
		case 9:		// SET_CONFIGURATION
			// Ignore :)
			return true;
		case 11:	// SET_INTERFACE
			// Ignore :)
			return true;
	}
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled standard OUT request %d", setup->bRequest);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_request(struct setup_packet *setup) {
	if ((setup->bmRequestType & 0x80) == 0x80) {
		return ep0_standard_in_request(setup);
	} else {
		return ep0_standard_out_request(setup);
	}
}

static bool
ep0_setup_stage(struct setup_packet *setup) {
	USB_DEBUG(USB_DEBUG_STAGE, "[%u] SETUP {%02x,%02x,%04x,%04x,%04x}",
			USB_DEBUG_ITERATION, setup->bmRequestType, setup->bRequest,
			setup->wValue, setup->wIndex, setup->wLength);
	uint8_t type = setup->bmRequestType & 0x60;
	enable_interrupts();
	bool rv = false;
	switch (type) {
		case 0:		// Standard
			rv = ep0_standard_request(setup);
			break;
    		case 0x20:	// Device
            rv = ep0_device_request(setup);
			break;
		case 0x40:	// Vendor
			rv = ep0_vendor_request(setup);
			break;
		default:
			USB_DEBUG(USB_DEBUG_STAGE, "Unhandled request type 0x%x", type);
			break;
	}
	disable_interrupts();
	return rv;
}

// ---- USB endpoint state ------------------------------------------------------------------------

// The size of the default DMA buffer. There is a 0x4000-byte DMA page divided between 4 endpoints.
#define DMA_BUFFER_SIZE    (0x4000 / 4)

// A sentinel value for tarnsfer_size to indicate that we actually want to send an empty packet
// (ZLP).
#define TRANSFER_ZLP    ((uint32_t)(-1))

// For EP 0 OUT transactions, indicates that we expect the next packet to be an OUT DATA
// transaction. Otherwise, the default is that we always expect a SETUP packet.
#define RECV_DATA		0x1

// State for managing data transfer over an endpoint.
struct endpoint_state {
    // -- Endpoint info --
    //
    // Information about the endpoint itself.
    //
    // Initialized during endpoint activation.

    // The endpoint type. 0 = Control, 1 = Isochronous, 2 = Bulk, 3 = Interrupt.
    uint8_t type;
    // The endpoint number.
    uint8_t n:7;
    // The endpoint direction. 0 = OUT, 1 = IN.
    uint8_t dir_in:1;
    // The maximum packet size on this endpoint.
    uint16_t max_packet_size;

    // -- Default DMA buffer --
    //
    // The following fields define the default buffer to use in DMA transfers. See "DMA buffer
    // management" below.
    //
    // Initialized during usb_init().

    // The virtual address of the default DMA buffer.
    uint8_t *default_xfer_dma_data;
    // The size of the default DMA buffer.
    uint32_t default_xfer_dma_size;
    // The physical address of the default DMA buffer.
    uint32_t default_xfer_dma_phys;

    // -- DMA buffer management --
    //
    // The following fields are used to manage DMA transfers. Physical pages suitable for DMA
    // may be a scarce resource; in order to accomodate transfers larger than the amount of
    // available DMA buffer space, the DMA buffer address and size are stored separately from
    // the transfer buffer.
    //
    // Usually, these will be equal to the default DMA buffer.
    //
    // As a special-case optimization, a USB transfer may be given a custom DMA buffer to use
    // in place of the default buffer. When this happens, DMA will be performed directly
    // from/to the specified buffer, eliminating the need to periodically copy data out of the
    // DMA buffer as it fills.

    // The virtual address of the DMA buffer of data to transfer.
    uint8_t *xfer_dma_data;
    // The size of the DMA buffer.
    uint32_t xfer_dma_size;
    // The physical address of the DMA buffer.
    uint32_t xfer_dma_phys;

    // -- Transfer state --
    //
    // The endpoint state keeps track of only one USB transfer at a time; requests cannot be
    // queued on the endpoint as with the SecureROM's USB stack. The transfer_data buffer is
    // managed in units of size xfer_dma_size (or units of 1 packet for OUT Control endpoints).

    // The buffer to/from which data is transferred. This is usually a pointer to a buffer
    // larger than the size of the DMA buffer.
    uint8_t *transfer_data;
    // The amount of data to transfer to/from the host. If transfer_size == TRANSFER_ZLP, then
    // we expect to send/receive an empty packet.
    uint32_t transfer_size;
    // The amount of data transferred so far. This can be greater than transfer_size only for
    // OUT endpoints and only if the host unexpectedly sent us more data than it claimed it
    // would.
    uint32_t transferred;
    // For IN endpoints, the amount of data in flight to the host.
    //
    // For OUT Control endpoints, RECV_DATA to indicate that we expect to receive a data
    // packet, and 0 to indicate that we expect to receive a setup packet.
    //
    // For OUT non-Control endpoints, RECV_DATA to indicate that we are in an OUT transfer, and
    // 0 to indicate that there is no currently scheduled OUT transfer.
    uint32_t in_flight;
};

// The endpoints.
static struct endpoint_state ep0_in;
static struct endpoint_state ep0_out;
static struct endpoint_state ep1_in;
static struct endpoint_state ep2_out;

// ---- Low-level transfer API for IN endpoints ---------------------------------------------------

// Compute the parameters for an IN transfer.
static void
ep_in_send_compute_xfer(struct endpoint_state *ep,
    uint32_t *dma_offset_out, uint32_t *hw_xfer_size_out, uint32_t *packet_count_out) {
    // New data is copied from the transfer_data buffer into the DMA buffer only once the DMA
    // buffer has been fully sent. Thus, we will transfer data from the DMA buffer starting at
    // offset transferred % xfer_dma_size.
    //
    // Maths: We know xfer_dma_size and transferred are both 0 mod max_packet_size, so
    // dma_offset and dma_left are 0 mod max_packet_size. dma_offset < xfer_dma_size, so
    // dma_left > 0. Thus dma_left >= max_packet_size.
    uint32_t dma_offset = ep->transferred % ep->xfer_dma_size;
    uint32_t dma_left = ep->xfer_dma_size - dma_offset;
    // Compute the amount of transfer left.
    uint32_t xfer_size = ep->transfer_size - ep->transferred;
    uint32_t packet_count = 1;
    if (ep->transfer_size == TRANSFER_ZLP) {
        // If we are sending an empty packet, xfer_size is 0.
        xfer_size = 0;
	} else {
		if (ep->type == 0) {
			// If we are sending data on EP 0 IN, then cap the transfer size at 1
			// packet.
            if (xfer_size > ep->max_packet_size) {
                xfer_size = ep->max_packet_size;
			}
		} else {
            // Cap the transfer size to the size of the DMA buffer.
            if (xfer_size > dma_left) {
                xfer_size = dma_left;
            }
            // Cap the transfer size by the width of DIEPTSIZ.xfersize. We round down
            // one full packet to ensure that we don't send a partial packet and signal
            // the end of the transfer.
            if (xfer_size > 0x7ffff) {
                xfer_size = 0x7ffff + 1 - ep->max_packet_size;
            }
            // TODO: Consider GHWCFG3!
			// If we are sending at least one full packet of data on EP !0 IN, then
			// compute the number of packets we need to send. If the data we're sending
			// completely fills all packets with no remainder, then we'll also need to
			// tack on an empty packet to signal the end of the transfer. I thought
			// this could be programmed here, but it appears to not work correctly, so
            // I've moved sending the ZLP to ep_in_send_done().
            if (xfer_size > ep->max_packet_size) {
                packet_count = (xfer_size + ep->max_packet_size - 1)
					/ ep->max_packet_size;
			}
		}
	}
    if (xfer_size > dma_left || dma_left < ep->max_packet_size) {
        USB_DEBUG(USB_DEBUG_FATAL, "xfer_size %u, dma_left %u, mps %u",
                  xfer_size, dma_left, (unsigned) ep->max_packet_size);
        BUG(0x7866696e206264);    // 'xfin bd'
    }
    *dma_offset_out = dma_offset;
    *hw_xfer_size_out = xfer_size;
    *packet_count_out = packet_count;
}

// Execute or continue an IN transaction (EP 0) or IN transfer (EP !0) on the endpoint. This
// function should not be called directly.
//
// The fields transfer_size, transferred, and transfer_data should be initialized before calling
// this function. in_flight is set on return.
static void ep_in_send(struct endpoint_state *ep) {
    if (ep->dir_in != 1 || ep->in_flight != 0) {
        BUG(0x73656e642031);    // 'send 1'
    }
    if (ep->transferred >= ep->transfer_size && ep->transfer_size != TRANSFER_ZLP) {
        USB_DEBUG(USB_DEBUG_XFER, "transfer_size %u, transferred %u",
                ep->transfer_size, ep->transferred);
        BUG(0x73656e642032);    // 'send 2'
    }
    // Compute the offset into the DMA buffer, the size of the transfer, and the number of
    // packets.
    uint32_t dma_offset, hw_xfer_size, packet_count;
    ep_in_send_compute_xfer(ep, &dma_offset, &hw_xfer_size, &packet_count);
        USB_DEBUG(USB_DEBUG_XFER, "EP%u IN xfer %u|%u|%u", ep->n,
                dma_offset, hw_xfer_size, packet_count);
    // New data is copied from the transfer_data buffer into the DMA buffer only once the DMA
    // buffer has been fully sent and is ready to be filled again.
    if (dma_offset == 0 && hw_xfer_size > 0) {
        uint32_t cache_length;
        if (ep->xfer_dma_data == ep->transfer_data) {
            // In direct DMA mode, the DMA buffer already contains all the data.
            cache_length = ep->transfer_size;
            if (cache_length == TRANSFER_ZLP) {
                BUG(0x6e6f207a6c70);    // 'no zlp'
            }
        } else {
            // In buffered DMA mode, data is copied from the transfer_data buffer into
            // the DMA buffer.
            memcpy(ep->xfer_dma_data, ep->transfer_data + ep->transferred,
                    hw_xfer_size);
            cache_length = hw_xfer_size;
        }
        // Make sure the writes hit the DMA buffer before starting DMA.
        cache_clean_and_invalidate(ep->xfer_dma_data, cache_length);
    }

	// Set the registers.
    reg_write(rDIEPDMA(ep->n), ep->xfer_dma_phys + dma_offset);
    reg_write(rDIEPTSIZ(ep->n), (packet_count << 19) | hw_xfer_size);
	reg_or(rDIEPCTL(ep->n), 0x84000000);
	// We now have data in flight.
    ep->in_flight = hw_xfer_size;
}

// Call this once the hardware signals that a transfer on an IN endpoint initiated with
// ep_in_send_data() is complete (DIEPINT(n).xfercompl). This function will update state and return
// true if all the requested data has been sent.
static bool
ep_in_send_done(struct endpoint_state *ep) {
    if (ep->dir_in != 1) {
        BUG(0x73656e642033);    // 'send 3'
    }
    USB_DEBUG(USB_DEBUG_XFER, "DIEPTSIZ(%u) = %x", ep->n, reg_read(rDIEPTSIZ(ep->n)));
    // Update the amount of data that has been transferred and the amount in flight.
	ep->transferred += ep->in_flight;
	ep->in_flight = 0;
    // If we were sending a ZLP, replace transfer_size.
    if (ep->transfer_size == TRANSFER_ZLP) {
        ep->transfer_size = 0;
    }
    // Check if we're done sending all the data.
	if (ep->transferred == ep->transfer_size) {
        // Handle sending a ZLP after transferring a whole number of full packets.
        // Initially this was done by configuring DIEPTSIZ to include the ZLP in the
        // initial call to ep_in_send() (thus avoiding another call out to the USB stack),
        // but the hardware does not seem to handle this case.
        bool need_zlp = (ep->transfer_size > 0 && ep->transfer_size % ep->max_packet_size == 0);
        if (!need_zlp) {
            USB_DEBUG(USB_DEBUG_XFER, "EP%u IN xfer done", ep->n);
            return true;
		}
        // Prepare to send a ZLP.
        ep->transferred = 0;
        ep->transfer_size = TRANSFER_ZLP;
    }
    // There's more data to send.
    ep_in_send(ep);
    return false;
}

// Send data on an IN endpoint. Call ep_in_send_done() every time DIEPINT(ep->n).xfercompl is
// asserted to check whether the data has been sent and to continue sending data if the transfer is
// only partially complete.
static void
ep_in_send_data(struct endpoint_state *ep, const void *data, uint32_t size) {
    if (ep->dir_in != 1 || ep->transfer_size != ep->transferred || ep->in_flight != 0) {
        BUG(0x73656e642034);    // 'send 4'
    }
    // Reset the DMA buffer to default.
    ep->xfer_dma_data = ep->default_xfer_dma_data;
    ep->xfer_dma_size = ep->default_xfer_dma_size;
    ep->xfer_dma_phys = ep->default_xfer_dma_phys;
    // We store a pointer to the source buffer, so it must remain alive. The source buffer may
    // be the xfer_dma_data buffer, in which case we're doing direct DMA.
    ep->transfer_data = (uint8_t *) data;
    ep->transfer_size = (size == 0 ? TRANSFER_ZLP : size);
	ep->transferred = 0;
	ep_in_send(ep);
}

// ---- Low-level transfer API for OUT endpoints --------------------------------------------------

// The code for EP 0 OUT is structured a bit differently from that for IN endpoints above. The
// reason for this is that while we have control of exactly what we send, we don't have control of
// exactly what we receive, so there are more edge cases we need to handle. This requires us to
// process one packet at a time in the interrupt handler, rather than firing off a request and
// being notified once it's all done. (The structure of the DOEP* registers for EP 0 also emphasize
// this: they prevent us from receiving more than 1 packet at a time.)
//
// The SecureROM does this by receiving 1 packet at a time, always into the same buffer at the same
// address, and then copying the data to the appropriate destination. That could work here, but it
// would require a different high-level API for handling control transfers, one that would send the
// supplied data to the upper layers one chunk at a time, rather than all at once when the transfer
// is complete. The flexibility of being able to send data piecemeal isn't actually a significant
// advantage for us, because if the transaction is aborted, then all that data should be discarded;
// this means that all the received data must be buffered anyway. (Perhaps in other circumstances,
// where the receiver can somehow compress the data as it is received in chunks, the other design
// might be better.)
//
// Instead, I'll receive and buffer partially completed DATA OUT stages in the DMA buffer.

// Compute the parameters for an OUT transfer.
static void
ep_out_recv_compute_xfer(struct endpoint_state *ep,
        uint32_t *dma_offset_out, uint32_t *hw_xfer_size_out, uint32_t *packet_count_out) {
    uint32_t dma_offset = 0;
    if (ep->xfer_dma_data == ep->transfer_data) {
        // In direct DMA mode, data is DMA'd directly to its destination in the DMA buffer
        // (which is also the transfer_data buffer).
        dma_offset = ep->transferred;
    } else {
        // In buffered DMA mode, data in the DMA buffer is moved into the transfer_data
        // buffer as it is received in ep_out_recv_data_done(), so we always DMA into the
        // start of the DMA buffer.
        dma_offset = 0;
    }
    if (dma_offset > ep->xfer_dma_size) {
        BUG(0x646d616f6666);    // 'dmaoff'
    }
    uint32_t dma_left = ep->xfer_dma_size - dma_offset;
    uint32_t xfer_size = ep->transfer_size - ep->transferred;
    uint32_t packet_count = 1;
    if (ep->type == 0 || ep->transfer_size == TRANSFER_ZLP) {
        // If we are receiving on EP 0 OUT or if we are receiving a ZLP, then set the
        // transfer size to a full packet.
        xfer_size = ep->max_packet_size;
    } else {
        // We are receiving at least some data on EP !0 OUT. Cap the transfer size to the
        // remaining space available in the DMA buffer.
        if (xfer_size > dma_left) {
            xfer_size = dma_left;
        }
	// Cap the transfer size by the width of DIEPTSIZ.xfersize. We round down
	// one full packet to ensure that we don't send a partial packet and signal
	// the end of the transfer.
        if (xfer_size > 0x7ffff) {
            xfer_size = 0x7ffff + 1 - ep->max_packet_size;
        }
        // TODO: Consider GHWCFG3!
        // Compute the number of packets needed and round the transfer size up to a packet
        // boundary.
        packet_count = (xfer_size + ep->max_packet_size - 1) / ep->max_packet_size;
        xfer_size = packet_count * ep->max_packet_size;
    }
    if (xfer_size > dma_left) {
        USB_DEBUG(USB_DEBUG_FATAL, "xfer_size %u > dma_left %u", xfer_size, dma_left);
        BUG(0x646d616f206264);    // 'dmao bd'
    }
    *dma_offset_out = dma_offset;
    *hw_xfer_size_out = xfer_size;
    *packet_count_out = packet_count;
}

// For EP 0 OUT:
//
// Execute the SETUP or OUT DATA transaction pending on EP 0 OUT. A SETUP packet will always be
// received into the start of the buffer, so there is no need to reset buffer state after receiving
// a maximally-sized DATA OUT stage.
//
// This function should be called every time we want to actually receive any data on EP 0 OUT,
// including after a USB reset, after an interrupt on EP 0 OUT, and after completing the DATA IN
// stage of a control transfer (so that we can actually receive the STATUS OUT stage).
//
// For EP !0 OUT:
//
// Execute the OUT transfer pending on the endpoint. This function should not be called directly.
//
// The fields transfer_size, transferred, transfer_data, and in_flight should be initialized before
// calling this function.
//
// There are two DMA modes: buffered DMA and direct DMA.
//
// For buffered DMA, the DMA'd data is copied into the transfer_data buffer during
// ep_out_recv_data_done().
static void
ep_out_recv(struct endpoint_state *ep) {
    if (ep->dir_in != 0) {
        BUG(0x73656e642031);    // 'recv 1'
    }
    if (ep->n == 0 && (ep0_out.xfer_dma_data != ep0_out.default_xfer_dma_data
            || ep0_out.xfer_dma_size != ep0_out.default_xfer_dma_size
            || ep0_out.xfer_dma_phys != ep0_out.default_xfer_dma_phys)) {
        BUG(0x72637630206466);    // 'rcv0 df'
    }
    if (ep->in_flight != RECV_DATA) {
        // RECV_DATA must be set on non-Control endpoints.
        if (ep->type != 0) {
            BUG(0x726563762032);    // 'recv 2'
        }
        // This is EP 0 OUT. When expecting a SETUP packet, set transfer_size and
        // transferred to 0. transfer_size is not needed, and transferred is 0 because
        // nothing precedes a SETUP packet.
        ep->transfer_size = 0;
        ep->transferred = 0;
    }
    // Compute the size of the transfer and the number of packets. The transfer size is rounded
    // up to a whole number of packets. Thus, the DMA buffer size must be a multiple of the
    // packet size. (Note that the DMA buffer size may not be a power of two in direct DMA
    // mode.)
    uint32_t dma_offset, hw_xfer_size, packet_count;
    ep_out_recv_compute_xfer(ep, &dma_offset, &hw_xfer_size, &packet_count);
    USB_DEBUG(USB_DEBUG_XFER, "EP%u OUT xfer %u|%u|%u", ep->n,
            dma_offset, hw_xfer_size, packet_count);
    // Also invalidate the cache for the DMA buffer before the DMA begins to avoid cached
    // writes overwriting DMA'd data.
    uint32_t cache_length = hw_xfer_size;
    if (hw_xfer_size > 0) {
        // In buffered DMA mode, invalidate the part of the cache we'll be receiving into.
        if (ep->xfer_dma_data == ep->transfer_data) {
            // In direct DMA mode, invalidate the cache for the whole buffer once at
            // the start.
            cache_length = ep->transfer_size;
            if (cache_length == TRANSFER_ZLP) {
                cache_length = ep->max_packet_size;
            }
        }
    }
    if (!cache_length) cache_length = ep->max_packet_size;
    cache_invalidate(ep->xfer_dma_data + dma_offset, cache_length);
    // Set the registers.
    reg_write(rDOEPDMA(ep->n), ep->xfer_dma_phys + dma_offset);
    reg_write(rDOEPTSIZ(ep->n), (packet_count << 19) | hw_xfer_size);
    // Only cnak if we're receiving data.
    reg_or(rDOEPCTL(ep->n), (ep->in_flight == RECV_DATA ? 0x84000000 : 0x80000000));
}

// When a SETUP packet is received on EP 0 OUT, call this routine to receive a pointer to it. The
// SETUP packet is still in the DMA buffer and should be copied out before being used.
//
// It is fine to call this function after calling ep_out_recv_data() to initiate a DATA OUT stage.
// Any data from an in-progress but incomplete DATA OUT stage is discarded. The endpoint is primed
// to receive a SETUP packet.
//
// This routine is not valid for other endpoints.

static struct setup_packet *
ep_out_recv_setup_done(struct endpoint_state *ep) {
    if (ep->dir_in != 0 || ep->type != 0 || ep->in_flight == RECV_DATA) {
        BUG(0x726563762033);    // 'recv 3'
    }
    // We need to offset by ep->transferred in case the SETUP packet arrived after some data
    // was received by ep_out_recv_data_done().
    struct setup_packet *setup = (void *)(ep->xfer_dma_data + ep->transferred);
    // Invalidate the cache to discard prefetches.
    cache_invalidate(setup, sizeof(*setup));

    // By default, expect another SETUP packet at the beginning of the buffer.
    ep->transfer_size = 0;
    ep->transferred = 0;
    ep->in_flight = 0;
    // Don't call ep_out_recv() for Control endpoints.
    return setup;
}

// Common code for ep_out_recv_data() and ep_out_recv_data_dma().
static void
ep_out_recv_data_common(struct endpoint_state *ep, void *data, uint32_t size) {
    // Set the transfer buffer. If data == xfer_dma_data, then we're doing direct DMA.
    ep->transfer_data = data;
    ep->transfer_size = (size == 0 ? TRANSFER_ZLP : size);
    ep->transferred = 0;
    ep->in_flight = RECV_DATA;
    // Only perform the recv on EP !0 OUT. On EP 0 OUT, the call to ep_out_recv() has been
    // moved to the end of the interrupt handler to ensure it is always called exactly once.
    if (ep->n != 0) {
        ep_out_recv(ep);
    } else {
        USB_DEBUG(USB_DEBUG_XFER, "EP%u OUT skip recv", ep->n);
    }
}

// For EP 0 OUT:
//
// Prime EP 0 OUT to receive OUT DATA transactions as part of a DATA OUT stage of a control
// transfer, rather than the default behavior of receiving a SETUP packet. This function can only
// be called once per control transfer.
//
// ep_out_recv() still needs to be called to actually begin the transfer. Each time an OUT DATA
// transaction is successfully received on the endpoint, call ep_out_recv_data_done() to update
// state and test whether all data has been received.
//
// For EP !0 OUT:
//
// Receive data on an non-Control OUT endpoint. Call ep_out_recv_data_done() every time
// DOEPINT(ep->n).xfercompl is asserted to check whether the data has been received and to continue
// receiving data if the transfer is only partially complete.
static void
ep_out_recv_data(struct endpoint_state *ep, void *data, uint32_t size) {
    if (ep->dir_in != 0 || ep->in_flight != 0 || data == NULL) {
        BUG(0x73656e642034);    // 'recv 4'
	}

    // Reset the DMA buffer to default.
    ep->xfer_dma_data = ep->default_xfer_dma_data;
    ep->xfer_dma_size = ep->default_xfer_dma_size;
    ep->xfer_dma_phys = ep->default_xfer_dma_phys;
    // Set the transfer buffer.
    ep_out_recv_data_common(ep, data, size);
}

static void
ep_out_recv_data_dma(struct endpoint_state *ep, void *data, uint32_t dma, uint32_t size) {
    if (ep->dir_in != 0 || ep->in_flight != 0 || data == NULL
            || size == 0 || (size % ep->max_packet_size) != 0) {
        BUG(0x73656e642035);    // 'recv 5'
    }
    ep->xfer_dma_data = data;
    ep->xfer_dma_size = size;
    ep->xfer_dma_phys = dma;
    // Set the transfer buffer.
    ep_out_recv_data_common(ep, data, size);
}

// For EP 0 OUT:
//
// Call this during an OUT DATA transaction for a control transfer once the hardware signals that a
// packet has been successfully received. This will update state and return whether the transfer is
// complete.
//
// This function does not call ep_out_recv() to retrieve more data; that should be done at the end
// of the EP 0 OUT interrupt handler.
//
// For EP !0 OUT:
//
// Call this once the hardware signals that a transfer on an OUT endpoint initiated with
// ep_out_recv_data() is complete (DOEPINT(n).xfercompl). This function will update state and
// return true if the host has finished sending us data. (ep_out_recv() is called automatically to
// resume transferring.)
static bool
ep_out_recv_data_done(struct endpoint_state *ep) {
    // We expect to reach here only after ep_out_recv_data() has been called to specify that we
    // expect data.
    if (ep->dir_in != 0 || ep->in_flight != RECV_DATA) {
        BUG(0x726563762036);    // 'recv 6'
    }
    // Read the number of bytes left to transfer. This is different on EP 0 and EP !0.
    uint32_t doeptsiz = reg_read(rDOEPTSIZ(ep->n));
    uint32_t hw_xfer_left = doeptsiz & (ep->n == 0 ? 0x7f : 0x7ffff);
    // Compute the original values of hw_xfer_size and packet_count given to the hardware. We
    // need these in order to check whether the transfer is actually complete.
    uint32_t dma_offset, hw_xfer_size, packet_count;
    ep_out_recv_compute_xfer(ep, &dma_offset, &hw_xfer_size, &packet_count);
    // Move the DMA'd data into the transfer_data buffer and update the amount transferred.
    uint32_t data_received = hw_xfer_size - hw_xfer_left;
    if (data_received > 0) {
        if (ep->xfer_dma_data != ep->transfer_data) {
            // In buffered mode, we always receive into the start of the DMA buffer.
            if (dma_offset != 0) {
                BUG(0x72637662756630);    // 'rcvbuf0'
            }
            // We're doing buffered DMA, so we need to copy the data we just received
            // out of the DMA buffer into the transfer_data buffer. Invalidate the
            // cache to discard prefetches.
            cache_invalidate(ep->xfer_dma_data, data_received);
            memcpy(ep->transfer_data + ep->transferred, ep->xfer_dma_data,
                data_received);
        }
        ep->transferred += data_received;
    }
    // If we expected a ZLP, update transfer_size to its correct value. This must be done after
    // ep_out_recv_compute_xfer(), which expects TRANSFER_ZLP to be intact. It's safe to
    // convert transfer_size at this point because we know this is the end of the transfer, so
    // we won't hit ep_out_recv_compute_xfer() again.
    if (ep->transfer_size == TRANSFER_ZLP) {
        ep->transfer_size = 0;
    }
    // Both for the DATA OUT stage of control transfers and for OUT non-control transfers, we
    // want to only return true here (signaling that the transfer is done) once we've received
    // the expected amount of data or once we've received a partial packet (including a ZLP).
    // In particular, if the controller stopped after receiving some data even though this
    // transfer is incomplete (e.g. because we've reached the maximum packet count per transfer
    // supported by the hardware), we should silently resume receiving data here rather than
    // report the end of the transfer to our caller.
    bool partial_packet = false;
    if (ep->type == 0) {
        // It's easy to test for a partial packet on EP 0 OUT because we transfer one
        // packet at a time, which means that a partial packet or ZLP was transferred iff
        // hw_xfer_left != 0.
        partial_packet = hw_xfer_left != 0;
    } else {
        // For other endpoints, we may have received a whole number of packets and then
        // been stopped by the hardware. The only case where hw_xfer_left != 0 does NOT
        // mean a partial packet is if we just received a (positive) whole number of
        // packets but no ZLP.
        partial_packet = hw_xfer_left != 0;
        // If we had some space left over and received a whole number of packets, check for
        // the ZLP. (We know we didn't receive a partial packet before now, so we only need
        // to check the just-received data.)
        bool whole_number_of_packets = (data_received > 0 && data_received % ep->max_packet_size == 0);
        if (partial_packet && whole_number_of_packets) {
            // We can test for whether we received a ZLP by counting how many packets
            // we expect to receive for the amount of data we actually received
            // compared to the number of packets we actually received. We should either
            // see packets_received == expected_packetcs (no ZLP) or packets_received ==
            // expected_packets + 1 (ZLP).
            uint32_t expected_packets = data_received / ep->max_packet_size;
            uint32_t packets_left = (doeptsiz >> 19) & 0x3ff;
            uint32_t packets_received = packet_count - packets_left;
            if (packets_received == expected_packets + 1) {
                USB_DEBUG(USB_DEBUG_XFER, "EP%u OUT ZLP", ep->n);
            } else {
                if (packets_received != expected_packets) {
                    USB_DEBUG(USB_DEBUG_FATAL, "EP%u OUT: Unexpected number "
                          "of packets received: %u != %u", ep->n, packets_received, expected_packets);
                            USB_DEBUG_ABORT();
                }
                USB_DEBUG(USB_DEBUG_XFER, "EP%u OUT no ZLP", ep->n);
                partial_packet = false;
            }
        }
    }
    // If we've received all the expected data or have a partial packet, we're done.
    if (ep->transferred >= ep->transfer_size || partial_packet) {
        ep->in_flight = 0;
        // We just finished the whole transfer. If we're in direct DMA mode, invalidate the
        // cache to discard prefetches (since we didn't do it as each piece was received).
        if (ep->xfer_dma_data == ep->transfer_data) {
            cache_invalidate(ep->xfer_dma_data, ep->transferred);
        }
        return true;
    }
    // Continue receiving data, but only on EP !0 OUT.
    if (ep->n != 0) {
        ep_out_recv(ep);
    }
    return false;
}

// ---- Controlling USB functionality -------------------------------------------------------------

// The maximum number of iterations we'll loop for when waiting for a USB register write to take
// effect.

__attribute__((used)) static void
ep_in_activate(struct endpoint_state *ep, uint8_t n, uint8_t type, uint16_t max_packet_size,
		uint8_t txfifo) {
	USB_DEBUG(USB_DEBUG_FUNC, "EP%u IN activate", n);
	ep->n = n;
    ep->dir_in = 1;
	ep->type = type;
	ep->max_packet_size = max_packet_size;
    // Use the default DMA buffer.
    ep->xfer_dma_data = ep->default_xfer_dma_data;
    ep->xfer_dma_size = ep->default_xfer_dma_size;
    ep->xfer_dma_phys = ep->default_xfer_dma_phys;
    // For Bulk and Interrupt endpoints, initialize DOEPCTL and FIFO state.
    if (type == 2 || type == 3) {
        reg_write(rDIEPCTL(ep->n), 0);
        // setd0pid | snak | txfnum | eptype | usbactep | mps
        reg_write(rDIEPCTL(ep->n), (1 << 28) | (1 << 27) | (txfifo << 22) | (type << 18)
                | (1 << 15) | max_packet_size);
    }
    // Start receiving interrupts.
    reg_or(rDAINTMSK, (1 << n));
}
__attribute__((used))static void
ep_out_activate(struct endpoint_state *ep, uint8_t n, uint8_t type, uint16_t max_packet_size) {
    USB_DEBUG(USB_DEBUG_FUNC, "EP%u OUT activate", n);
    ep->n = n;
    ep->dir_in = 0;
    ep->type = type;
    ep->max_packet_size = max_packet_size;
    // Use the default DMA buffer.
    ep->xfer_dma_data = ep->default_xfer_dma_data;
    ep->xfer_dma_size = ep->default_xfer_dma_size;
    ep->xfer_dma_phys = ep->default_xfer_dma_phys;
    // For Bulk and Interrupt endpoints, initialize DOEPCTL.
    if (type == 2 || type == 3) {
        reg_write(rDOEPCTL(ep->n), 0);
        // setd0pid | snak | eptype | usbactep | mps
        reg_write(rDOEPCTL(ep->n), (1 << 28) | (1 << 27) | (type << 18)
                | (1 << 15) | max_packet_size);
    }
    // Start receiving interrupts.
    reg_or(rDAINTMSK, (1 << (n + 16)));
}

__attribute__((used))static void
ep_in_abort(struct endpoint_state *ep) {
	USB_DEBUG(USB_DEBUG_FUNC, "EP%u IN abort", ep->n);
	ep->transfer_size = 0;
	ep->transferred = 0;
	ep->in_flight = 0;
	if (reg_read(rDIEPCTL(ep->n)) & 0x80000000) {
		reg_or(rDIEPCTL(ep->n), 0x40000000);
		while (1) {
			if (reg_read(rDIEPINT(ep->n)) & 0x2) {
				break;
			}
		}
	}
	reg_write(rDIEPINT(ep->n), reg_read(rDIEPINT(ep->n)));
}

__attribute__((used))static void
ep_out_abort(struct endpoint_state *ep) {
    USB_DEBUG(USB_DEBUG_FUNC, "EP%u OUT abort", ep->n);
    ep->transfer_size = 0;
    ep->transferred = 0;
    ep->in_flight = 0;
    if (reg_read(rDOEPCTL(ep->n)) & 0x80000000) {
        reg_write(rGINTSTS, 0x80);    // goutnakeff
        reg_or(rDCTL, 0x200);        // sgoutnak
        while (1) {
            if (reg_read(rGINTSTS) & 0x80) {
                break;
            }
        }
        reg_write(rGINTSTS, 0x80);
        reg_or(rDOEPCTL(ep->n), 0x48000000);
        while (1) {
        if (reg_read(rDOEPINT(ep->n)) & 0x2) {
                break;
            }
        }
        reg_or(rDCTL, 0x400);
    }
    reg_write(rDOEPINT(ep->n), reg_read(rDOEPINT(ep->n)));
}

__attribute__((used)) static void
ep_stall(struct endpoint_state *ep) {
    USB_DEBUG(USB_DEBUG_FUNC, "EP%u %s stall", ep->n, (ep->dir_in ? "IN" : "OUT"));
    if (ep->dir_in) {
        reg_or(rDIEPCTL(ep->n), 0x200000);
    } else {
        reg_or(rDOEPCTL(ep->n), 0x200000);
    }
}

__attribute__((used)) static void
usb_set_address(uint8_t address) {
	USB_DEBUG(USB_DEBUG_FUNC, "Set address %u", address);
	uint32_t dcfg = reg_read(rDCFG);
	dcfg = (dcfg & ~0x7f0) | (((uint32_t) address << 4) & 0x7f0);
	reg_write(rDCFG, dcfg);
}
__attribute__((used)) static void
usb_reset() {
    USB_DEBUG(USB_DEBUG_FUNC, "Reset");
    ep_in_abort(&ep0_in);
    ep_in_abort(&ep1_in);
    ep_in_abort(&ep2_out);
    usb_set_address(0);
    reg_write(rDOEPMSK, 0);
    reg_write(rDIEPMSK, 0);
    reg_write(rDAINTMSK, 0);
    reg_write(rDIEPINT(0), 0x1f);
    reg_write(rDOEPINT(0), 0xf);
    reg_write(rGRXFSIZ,    0x0000021b);
    reg_write(rGNPTXFSIZ,  0x0010021b);    //   64 bytes
    reg_write(rDTXFSIZ(1), 0x0040022b);    //  256 bytes
    reg_write(rDTXFSIZ(2), 0x0100026b);    // 1024 bytes
    reg_write(rDTXFSIZ(3), 0x0100036b);    // 1024 bytes
    reg_write(rDTXFSIZ(4), 0x0100046b);    // 1024 bytes
    reg_write(rDOEPCTL(0), 0);
    reg_write(rDIEPCTL(0), 0);
    reg_or(rGINTMSK, 0xc0000);
    reg_write(rDOEPMSK, 0xd);
    reg_write(rDIEPMSK, 0xd);
    reg_write(rDAINTMSK, 0);
    ep_out_activate(&ep0_out, 0, 0, EP0_MAX_PACKET_SIZE);
    ep_in_activate(&ep0_in, 0, 0, EP0_MAX_PACKET_SIZE, 0);
    uint8_t ep_type = configuration_descriptor.endpoint_81.bmAttributes;
    uint16_t ep_mps = configuration_descriptor.endpoint_81.wMaxPacketSize;
    ep_in_activate(&ep1_in, 1, ep_type, ep_mps, 2);
    ep_type = configuration_descriptor.endpoint_02.bmAttributes;
    ep_mps = configuration_descriptor.endpoint_02.wMaxPacketSize;
    ep_out_activate(&ep2_out, 2, ep_type, ep_mps);
    ep_out_recv(&ep0_out);
}

// ---- USB transfer API --------------------------------------------------------------------------

// This holds state for a pair of IN/OUT Control endpoints to manage a control transfer.
struct control_transfer_state {
    struct setup_packet setup_packet;
    bool setup_packet_pending;
    bool (*data_out_stage_callback)(const void *data, uint32_t size);
    void (*status_out_stage_callback)(void);
};

// This holds state for a non-Control IN or OUT endpoint to manage transfers.
struct transfer_state {
    union {
        // A callback to invoke once the IN transfer is done.
        void (*in_transfer_done)(void);
        // A callback to invoke once the OUT transfer is done (either because we received
        // enough or because the host ended it earlier than expected).
        void (*out_transfer_done)(void *data, uint32_t size, uint32_t transferred);
    };
};

// State for IN/OUT EP 0 control transfers.
static struct control_transfer_state ep0;

// State for other endpoints.
struct transfer_state ep1;
struct transfer_state ep2;

// You may try to send more data than was requested, but the request will be truncated to the size
// requested by the host.
void
ep0_begin_data_in_stage(const void *data, uint32_t size, void (*callback)(void)) {
    if (size > ep0.setup_packet.wLength) {
        size = ep0.setup_packet.wLength;
    }
    USB_DEBUG(USB_DEBUG_STAGE, "DATA IN %u", size);
    ep0.status_out_stage_callback = callback;
    // Send the DATA IN stage from the default DMA buffer. This allows the caller to supply a
    // temporary buffer.
    if (size > ep0_in.default_xfer_dma_size) {
        BUG(0x64696e32626967);    // 'din2big'
    }
    memcpy(ep0_in.default_xfer_dma_data, data, size);
    ep_in_send_data(&ep0_in, ep0_in.default_xfer_dma_data, size);
}

void
ep0_begin_data_out_stage(bool (*callback)(const void *, uint32_t)) {
    USB_DEBUG(USB_DEBUG_STAGE, "DATA OUT %u", ep0.setup_packet.wLength);
    ep0.data_out_stage_callback = callback;
    // Receive the DATA OUT stage into the default DMA buffer. This is a simplification but
    // limits the maximum size of the DATA OUT stage.
    if (ep0.setup_packet.wLength > ep0_out.default_xfer_dma_size) {
        BUG(0x646f7532626967);    // 'dou2big'
    }
    ep_out_recv_data(&ep0_out, ep0_out.default_xfer_dma_data, ep0.setup_packet.wLength);
    // We explicitly do not want to call ep_out_recv(&ep0_out) here; we will do that once this
    // whole stack unwinds and we're back in ep0_out_interrupt().
}

// Look up the endpoint address.
static void
lookup_endpoint(uint8_t ep_addr, int dir_in,
        struct endpoint_state **ep, struct transfer_state **state) {
    if (dir_in) {
        if (ep_addr == 0x81) {
            *ep = &ep1_in;
            *state = &ep1;
        }
    } else {
        if (ep_addr == 0x02) {
            *ep = &ep2_out;
            *state = &ep2;
        }
    }
}

// Queue data for sending on the specified bulk or interrupt endpoint. The data won't be sent until
// the host initiates an IN transfer. Once the transfer is complete, the specified callback will be
// invoked. The data buffer must remain alive until the callback is invoked.
void
usb_in_transfer(uint8_t ep_addr, const void *data, uint32_t size, void (*callback)(void)) {
    struct endpoint_state *ep = NULL;
    struct transfer_state *state = NULL;
    lookup_endpoint(ep_addr, 1, &ep, &state);
    if (ep == NULL) {
        BUG(0x6e6f206570);    // 'no ep'
    }
    if (state->in_transfer_done != NULL) {
        BUG(0x636220736574);    // 'cb set'
    }
    state->in_transfer_done = callback;
    ep_in_send_data(ep, data, size);
}

void
usb_out_transfer(uint8_t ep_addr, void *data, uint32_t size,
        void (*callback)(void *, uint32_t, uint32_t)) {
    USB_DEBUG(USB_DEBUG_APP, "%s(%u)", __func__, size);
    struct endpoint_state *ep = NULL;
    struct transfer_state *state = NULL;
    lookup_endpoint(ep_addr, 0, &ep, &state);
    if (ep == NULL) {
        BUG(0x6e6f206570);    // 'no ep'
    }
    if (state->out_transfer_done != NULL) {
        BUG(0x636220736574);    // 'cb set'
    }
    state->out_transfer_done = callback;
    ep_out_recv_data(ep, data, size);
}

void
usb_out_transfer_dma(uint8_t ep_addr, void *data, uint32_t dma, uint32_t size,
        void (*callback)(void *, uint32_t, uint32_t)) {
    USB_DEBUG(USB_DEBUG_APP, "%s(%u)", __func__, size);
    struct endpoint_state *ep = NULL;
    struct transfer_state *state = NULL;
    lookup_endpoint(ep_addr, 0, &ep, &state);
    if (ep == NULL) {
        BUG(0x6e6f206570);    // 'no ep'
    }
    if (state->out_transfer_done != NULL) {
        BUG(0x636220736574);    // 'cb set'
    }
    state->out_transfer_done = callback;
    ep_out_recv_data_dma(ep, data, dma, size);
}

// ---- USB interrupt handling --------------------------------------------------------------------

// This is the API we export to the layer above:
//
// At the start:
//
//     - We will call ep0_setup_stage() when the SETUP stage is done and we have a setup packet.
//       This function should return true if the request was recognized and the control transfer
//       should continue, and false to stall EP 0 OUT.
//
// For IN control transfers:
//
//     - ep0_setup_stage() should call ep0_begin_data_in_stage() to begin the DATA IN stage. The
//       third parameter to ep0_begin_data_in_stage() is a callback function
//       status_out_stage_callbock to invoke if the entire transfer completes successfully.
//
//     - When the DATA IN stage is complete, we will call ep_out_recv_data(&ep0_out, 0) to begin
//       the STATUS OUT stage.
//
//     - If the STATUS OUT stage does not complete successfully (because a non-zero-length packet
//       was received), then we will stall EP 0 OUT without calling status_out_stage_callback().
//
//       (The reason for this behavior is that we're relying on DCTL.nzstsouthshk to send the STALL
//       handshake in response to a non-zero-length STATUS OUT stage. When this bit is set, we
//       won't receive the offending STATUS OUT.)
//
//       If an IN control transfer specified a status_out_stage_callback and that callback was not
//       invoked, then that means the data was not successfully received by the host.
//
//     - If the STATUS OUT stage completes successfully (we receive a zero-length packet), then we
//       will call status_out_stage_callback().
//
// For OUT control transfers:
//
//     - If there is a DATA OUT stage, ep0_setup_stage() should call ep0_begin_data_out_stage() to
//       begin the DATA OUT stage. The only parameter to ep0_begin_data_out_stage() is a callback
//       function data_out_stage_callback that will be invoked when the data is successfully
//       received.
//
//     - If we receive a setup packet before the transfer is complete, ep0_setup_stage() is called
//       again without calling data_out_stage_callback().
//
//     - If we receive the wrong amount of data, EP 0 OUT is stalled without calling
//       data_out_stage_callback().
//
//     - Otherwise, if the DATA OUT stage is received successfully, we will call
//       data_out_stage_callback() with the received data. This function should return true if we
//       should send a successful zero-length STATUS IN stage, or false if we should stall EP 0 IN.
//
// Structuring control transfers in this way makes things less efficient, since the host may send
// the last packet and an ack at the same time, and we now force it to take a retry. But I think
// it's much simpler to use this API.


static void
ep0_in_interrupt() {
	uint32_t diepint = reg_read(rDIEPINT(0));
	reg_write(rDIEPINT(0), diepint);
	USB_DEBUG(USB_DEBUG_INTR, "DIEPINT(0) %x", diepint);
	if (diepint & 0x1) {
		bool done = ep_in_send_done(&ep0_in);
		if (done) {
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This is an IN control transfer and we're done sending the data,
				// so we want to begin the STATUS OUT stage.
				//
				// Note that there's an edge case here: Let's say the host has
				// requested 0x123 bytes, and we have only 0x80. We send 2 full
				// packets then think we're done. The host however doesn't know
				// that yet, it still thinks we're going to send more, so it issues
				// another DATA IN. Because of this, we need to send an incomplete
				// packet to let it know that that's all there is.
				uint16_t requested = ep0.setup_packet.wLength;
				uint16_t sent = ep0_in.transferred;
				bool partial = sent == 0 || (sent % EP0_MAX_PACKET_SIZE) != 0;
				if (requested > sent && !partial) {
					// We have no more data, but the host doesn't yet know that
					// this transfer is complete since we haven't sent a
					// partial packet. Send an empty packet now to let it know.
					USB_DEBUG(USB_DEBUG_STAGE, "Send partial packet");
					ep_in_send_data(&ep0_in, NULL, 0);
				} else {
					// Either we've sent all the requested data, or we've
					// already sent a partial packet (possibly the zero-length
					// one from the if case), so the host knows the transfer is
					// done. Begin the STATUS OUT stage by requesting an empty
					// packet.
					USB_DEBUG(USB_DEBUG_STAGE, "STATUS OUT");
                    // Explicitly call ep_out_recv(&ep0_out) because we're not
                    // in the ep0_out_interrupt() stack.
					//
					// Even though it's possible we have both IN and OUT
					// interrupts to handle for EP 0, I believe that it should
                    // be fine to call ep_out_recv_data() and ep_out_recv() on
                    // ep0_out here. Up until this point we have had EP 0 OUT
                    // send a NAK for all OUT DATA packets. Thus, the only
                    // interesting interrupt on EP 0 OUT could be a setup
                    // packet. If that's the case, then receiving that setup
                    // packet will clear the request to receive data.
                    ep_out_recv_data(&ep0_out,
                            ep0_out.default_xfer_dma_data, 0);
                    ep_out_recv(&ep0_out);
				}
			} else {
				// This is an OUT control transfer, which means that we must have
                // completed the STATUS IN stage. Nothing to do, since the hardware
                // will signal us in ep0_out_interrupt().
			}
		}
	}
	if (diepint & 0x8) {
		USB_DEBUG(USB_DEBUG_INTR, "TIMEOUT");
		USB_DEBUG_ABORT();
	}
	if (diepint & 0x4) {
		BUG(0x61686220696e);	// 'ahb in'
	}
}

static void
ep0_out_interrupt() {
	uint32_t doepint = reg_read(rDOEPINT(0));
	reg_write(rDOEPINT(0), doepint);
    bool is_setup = !!(doepint & 0x8008);
	bool is_data  = !is_setup && !!(doepint & 0x1);
	if (is_setup) {
		// We've received a setup packet.

        spin(2); // this is required because this interrupt is asserted *before* the DMA transfer is complete on some devices.. ugh
        struct setup_packet *setup = ep_out_recv_setup_done(&ep0_out);
        ep0.setup_packet = *setup;

		ep0.setup_packet_pending = true;
		ep0.data_out_stage_callback = NULL;
		ep0.status_out_stage_callback = NULL;
	}
	if ((doepint & 0x8) && ep0.setup_packet_pending) {
		// The SETUP stage is done, so process the queued setup packet.
		ep0.setup_packet_pending = false;

        bool success = false;
		// Only begin processing the setup packet if we will have enough room for the whole
		// transfer. We could break down the layering to allow even bigger contiguous
		// transfers, but this works fine for me.
		if (ep0.setup_packet.wLength <= DMA_BUFFER_SIZE) {

			success = ep0_setup_stage(&ep0.setup_packet);
		}
		if (success) {
			// The SETUP stage was successful.
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This is an IN control transfer. There will be a DATA IN stage,
				// so we don't expect to receive the STATUS OUT stage yet. The DATA
				// IN was initialized by ep0_setup_stage().
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 1
				// Check to make sure that ep0_begin_data_in_stage() was called.
				if (ep0_in.transfer_size == ep0_in.transferred) {
					USB_DEBUG(USB_DEBUG_FATAL,
							"ep0_begin_data_in_stage() not called!");
					USB_DEBUG_ABORT();
				}
#endif
			} else {
				// This is an OUT control transfer. We may or may not have a data
				// stage.
				if (ep0.setup_packet.wLength > 0) {
					// We do have a DATA OUT stage. The size should have been
					// set it ep0_setup_stage() by a call to
					// ep0_begin_data_out_stage() (which internally calls
                    // ep_out_recv_data(&ep0_out)).
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 1
					if (ep0_out.in_flight != RECV_DATA) {
						USB_DEBUG(USB_DEBUG_FATAL, "ep0_begin_data_out_"
								"stage() not called!");
					}
#endif
				} else {
					// We do not have a DATA OUT stage, so we move directly to
					// the STATUS IN stage.
					USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN");
					ep_in_send_data(&ep0_in, NULL, 0);
				}
			}
		} else {
			// The SETUP stage failed, so stall the next endpoint that will be queried.
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This was supposed to be an IN control transfer, so stall EP 0
				// IN.
                ep_stall(&ep0_in);
			} else {
				// This was supposed to be an OUT control transfer.
				if (ep0.setup_packet.wLength > 0) {
					// If there was supposed to be a DATA OUT stage, stall EP 0
					// OUT.
                    ep_stall(&ep0_out);
				} else {
					// If we were supposed to go directly to STATUS IN, stall
					// EP 0 IN.
					ep_stall(&ep0_in);
				}
			}
		}
	} else if(is_data) {
		if ((doepint & 0x20) == 0x20) {
			// After an OUT control transfer with data completes, we get a zero-length OUT DATA
			// with DOEPINT 0x21 (stsphsercvd | xfercompl). This is expected, don't stall.
			USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN done");
		} else {
			// This packet is part of the DATA OUT stage or STATUS OUT stage.
			bool done = ep_out_recv_data_done(&ep0_out);
			if (done) {
				// ep0_out_recv_data_done() has reset the receive state, so the next call
				// to ep0_out_recv() expects a setup packet. But before we start receiving
				// more data, process the data we did receive.
				if (ep0.setup_packet.bmRequestType & 0x80) {
					// This is an IN control transfer, so this packet is part of the
					// STATUS OUT stage.
					if (ep0_out.transferred != 0
							|| ep0_out.transfer_size != 0) {
						// STATUS OUT failed.
	                    ep_stall(&ep0_out);
					} else {
						// STATUS OUT completed successfully.
						USB_DEBUG(USB_DEBUG_STAGE, "STATUS OUT done");
						if (ep0.status_out_stage_callback != NULL) {
							ep0.status_out_stage_callback();
							ep0.status_out_stage_callback = NULL;
						}
					}
				} else {
					// This is an OUT control transfer, so this packet is part of the
					// DATA OUT stage.
					if (ep0_out.transferred != ep0_out.transfer_size) {
						// The wrong amount of data was transferred.
						ep_stall(&ep0_out);
					} else {
						// We got all the data. Give it to the layer above us to
						// process the DATA OUT stage.
						if (ep0.data_out_stage_callback == NULL) {
							BUG(0x6e6f20646f206362);	// 'no do cb'
						}
						bool success = ep0.data_out_stage_callback(
								ep0_out.transfer_data,
								ep0_out.transfer_size);
						ep0.data_out_stage_callback = NULL;
						if (success) {
							// The DATA OUT stage was successful. Move to the
							// STATUS IN stage.
							USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN");
							ep_in_send_data(&ep0_in, NULL, 0);
						} else {
							// The DATA OUT stage failed.
							ep_stall(&ep0_in);
						}
					}
				}
			} else {
				// The DATA OUT transaction is not done. The call to ep0_out_recv() below
				// will continue receiving OUT DATA.
			}
		}
	}
	if (doepint & 0x4) {
		BUG(0x616862206f7574);	// 'ahb out'
	}
    // We call ep_out_recv() after everything has been processed to ensure that in all cases
    // we'll re-enable the endpoint. ep_out_recv() will only allow receiving OUT DATA if
    // ep_out_recv_data() was called.
    ep_out_recv(&ep0_out);
}

static void
ep1_in_interrupt() {
	uint32_t diepint = reg_read(rDIEPINT(1));
	reg_write(rDIEPINT(1), diepint);
	USB_DEBUG(USB_DEBUG_INTR, "DIEPINT(1) %x", diepint);
	if (diepint & 0x1) {
		bool done = ep_in_send_done(&ep1_in);
		if (done) {
			// The transfer is done! Notify the upper layer.
			USB_DEBUG(USB_DEBUG_APP, "EP%u IN done", ep1_in.n);
			if (ep1.in_transfer_done == NULL) {
				BUG(0x6e6f203169206362);	// 'no 1i cb'
			}
			// We need to clear ep1.in_transfer_done before invoking the callback,
			// since in_transfer_done() might itself register another transfer.
			void (*in_transfer_done)(void) = ep1.in_transfer_done;
			ep1.in_transfer_done = NULL;
			in_transfer_done();
		}
	}
	if (diepint & 0x8) {
		USB_DEBUG(USB_DEBUG_STAGE | USB_DEBUG_INTR, "TIMEOUT");
		USB_DEBUG_ABORT();
	}
	if (diepint & 0x4) {
		BUG(0x61686220696e2031);	// 'ahb in 1'
	}
}


static void
ep2_out_interrupt() {
    uint32_t doepint = reg_read(rDOEPINT(2));
    reg_write(rDOEPINT(2), doepint);
    USB_DEBUG(USB_DEBUG_INTR, "DOEPINT(2) %x", doepint);
    if (doepint & 0x1) {
        bool done = ep_out_recv_data_done(&ep2_out);
        if (done) {
            // The transfer is done! Notify the upper layer.
            USB_DEBUG(USB_DEBUG_APP, "EP%u OUT done", ep2_out.n);
            if (ep2.out_transfer_done == NULL) {
                BUG(0x6e6f203169206362);    // 'no 1i cb'
            }
            // We need to clear ep2.transfer_done before invoking the callback,
            // since transfer_done() might itself register another transfer.
            void (*out_transfer_done)(void *, uint32_t, uint32_t) = ep2.out_transfer_done;
            ep2.out_transfer_done = NULL;
            out_transfer_done(ep2_out.transfer_data, ep2_out.transfer_size,
                    ep2_out.transferred);
        }
    }
    if (doepint & 0x8) {
        USB_DEBUG(USB_DEBUG_STAGE | USB_DEBUG_INTR, "TIMEOUT");
        USB_DEBUG_PRINT_REGISTERS();
        USB_DEBUG_ABORT();
    }
    if (doepint & 0x4) {
        BUG(0x61686220696e2031);    // 'ahb in 1'
    }
}

static void
usb_ep_interrupt() {
	uint32_t daint = reg_read(rDAINT);
	if (daint != 0) {
		USB_DEBUG(USB_DEBUG_INTR, "[%u] DAINT %x", USB_DEBUG_ITERATION, daint);
	}
    if (daint & (1 << (0))) {
        ep0_in_interrupt();
    }
    if (daint & (1 << (1))) {
        ep1_in_interrupt();
    }
    if (daint & (1 << (16 + 0))) {
        ep0_out_interrupt();
    }
    if (daint & (1 << (16 + 2))) {
        ep2_out_interrupt();
    }
}
char usb_irq_mode;
char usb_usbtask_handoff_mode;
uint16_t usb_irq;
struct task* usbtask_niq;

void usb_handler() {
    uint32_t gintsts = 0;
    while (1) {
        gintsts |= reg_read(rGINTSTS);
        if (gintsts & 0x1000) {
    		usb_reset();
	        reg_write(rGINTSTS, 0x1000);
    	}
        if (gintsts & 0xC0000) {
    		usb_ep_interrupt();
	        reg_write(rGINTSTS, 0xc0000);
    	}
        if (!(gintsts&0xc1000)) {
            break;
        } else {
            gintsts &= ~0xc1000;
        }
    }
}

void usb_main_nonirq() {
    while (1) {
        usb_handler();
        disable_interrupts();
        if (usb_irq) unmask_interrupt(usb_irq);
        task_unlink(task_current());
        task_yield_asserted();
    }
}


void usb_main() {
    while (1) {
        if (usb_usbtask_handoff_mode && usb_irq_mode) {
            if (usbtask_niq->flags & TASK_LINKED) panic("USB: spurious IRQ");
            task_link(usbtask_niq);
            task_current()->flags |= TASK_MASK_NEXT_IRQ;
        } else {
            disable_interrupts();
            usb_handler();
            enable_interrupts();
        }
	if (usb_irq_mode)
        task_exit_irq();
        else task_yield();
    }
}

static uint64_t reg1=0, reg2=0, reg3=0;

void usb_bringup() {
    clock_gate(reg1, 0);
    clock_gate(reg2, 0);
    clock_gate(reg3, 0);
    spin(1000);
    clock_gate(reg1, 1);
    clock_gate(reg2, 1);
    clock_gate(reg3, 1);
    // t8011 is really just cursed...
    if (socnum == 0x8011) {
        *(volatile uint32_t*)(gSynopsysComplexBase + 0x00) = 1;
        *(volatile uint32_t*)(gSynopsysComplexBase + 0x24) = 0x3000088;
    } else {
        *(volatile uint32_t*)(gSynopsysComplexBase + 0x1c) = 0x108;
        *(volatile uint32_t*)(gSynopsysComplexBase + 0x5c) = 0x108;
    }
    *(volatile uint32_t *)(gSynopsysOTGBase + 0x8) = dt_get_u32_prop("otgphyctrl", "cfg0-device");
    *(volatile uint32_t *)(gSynopsysOTGBase + 0xc) = dt_get_u32_prop("otgphyctrl", "cfg1-device");
    *(volatile uint32_t*)(gSynopsysOTGBase) |= 1;
    spin(20);
    *(volatile uint32_t*)(gSynopsysOTGBase) &= 0xFFFFFFF3;
    spin(20);
    *(volatile uint32_t*)(gSynopsysOTGBase) &= 0xFFFFFFFE;
    spin(20);
    *(volatile uint32_t*)(gSynopsysOTGBase + 0x4) &= ~2;
    spin(1500);
}

void usb_init() {
    gSynopsysOTGBase = 0;
    uint32_t sz = 0;
    uint64_t *reg = dt_get_prop("otgphyctrl", "reg", &sz);
    if(reg)
    {
        sz /= 0x10;
        for(uint32_t i = 0; i < sz; ++i)
        {
            if(reg[2*i + 1] == 0x20)
            {
                gSynopsysOTGBase = reg[2*i];
                break;
            }
        }
    }
    if(!gSynopsysOTGBase)
    {
        panic("Failed to find gSynopsysOTGBase");
    }
    gSynopsysOTGBase += gIOBase;
    gSynopsysComplexBase = gIOBase + dt_get_u32_prop("usb-complex", "reg");
    // Can't trust "usb-device" dtre entry, because that can be USB3 and we want USB2
    gSynopsysBase = (gSynopsysOTGBase & ~0xfffULL) + 0x00100000;
    uint32_t otg_irq;

    struct usb_regs regs;
    size_t plsz = sizeof(struct usb_regs);
    if (!hal_get_platform_value("usb_regs", &regs, &plsz)) {
        panic("synopsys_otg: need usb_regs platform value!");
    }

    reg1 = gIOBase + regs.reg1;
    reg2 = gIOBase + regs.reg2;
    reg3 = gIOBase + regs.reg3;
    otg_irq = regs.otg_irq;

    uint64_t dma_page_v = (uint64_t) alloc_contig(4 * DMA_BUFFER_SIZE);
    uint64_t dma_page_p = vatophys_static((void*)dma_page_v);
    bzero((void*)dma_page_v,4 * DMA_BUFFER_SIZE);
    cache_clean_and_invalidate((void*)dma_page_v, 4 * DMA_BUFFER_SIZE);

    disable_interrupts();
    usb_irq_mode = 1;
    usb_usbtask_handoff_mode = 0;
    usb_bringup();

    gSynopsysCoreVersion = reg_read(rGSNPSID) & 0xffff;
    USB_DEBUG(USB_DEBUG_STANDARD, "gSynopsysCoreVersion: 0x%x", gSynopsysCoreVersion);

    reg_or(rDCTL, 0x2);
    reg_write(rGAHBCFG, 0x2e | usb_irq_mode);
    reg_write(rGUSBCFG, 0x1408);
    reg_write(rDCFG, 0x4);
    reg_write(rGINTMSK, 0);
    reg_write(rDOEPMSK, 0);
    reg_write(rDIEPMSK, 0);
    reg_write(rDAINTMSK, 0);
    reg_write(rDIEPINT(0), 0x1f);
    reg_write(rDOEPINT(0), 0xf);
    reg_write(rGINTMSK, 0x1000);
    reg_and(rDCTL, ~0x2);

    ep_out_activate(&ep0_out, 0, 0, EP0_MAX_PACKET_SIZE);
    ep_in_activate(&ep0_in, 0, 0, EP0_MAX_PACKET_SIZE, 0);

    ep0_out.default_xfer_dma_data = (void *)   (dma_page_v + 0 * DMA_BUFFER_SIZE);
    ep0_out.default_xfer_dma_phys = (uint32_t) (dma_page_p + 0 * DMA_BUFFER_SIZE);
    ep0_out.default_xfer_dma_size = DMA_BUFFER_SIZE;
    ep0_in .default_xfer_dma_data = (void *)   (dma_page_v + 1 * DMA_BUFFER_SIZE);
    ep0_in .default_xfer_dma_phys = (uint32_t) (dma_page_p + 1 * DMA_BUFFER_SIZE);
    ep0_in .default_xfer_dma_size = DMA_BUFFER_SIZE;
    ep1_in .default_xfer_dma_data = (void *)   (dma_page_v + 2 * DMA_BUFFER_SIZE);
    ep1_in .default_xfer_dma_phys = (uint32_t) (dma_page_p + 2 * DMA_BUFFER_SIZE);
    ep1_in .default_xfer_dma_size = DMA_BUFFER_SIZE;
    ep2_out.default_xfer_dma_data = (void *)   (dma_page_v + 3 * DMA_BUFFER_SIZE);
    ep2_out.default_xfer_dma_phys = (uint32_t) (dma_page_p + 3 * DMA_BUFFER_SIZE);
    ep2_out.default_xfer_dma_size = DMA_BUFFER_SIZE;

    *(volatile uint32_t*)(gSynopsysOTGBase + 0x4) |= 2;

    if (usb_usbtask_handoff_mode) {
        usbtask_niq = alloc_contig(sizeof(struct task));
        strcpy(usbtask_niq->name, "usbtask");
        task_register_unlinked(usbtask_niq, usb_main_nonirq);
    }
    usb_irq = 0;
    if (usb_irq_mode) {
        usb_irq = otg_irq;
        task_register_preempt_irq(&usb_task, usb_main, usb_irq);
    }
    else task_register(&usb_task, usb_main);
    enable_interrupts();
    command_register("synopsys", "prints a synopsysotg register dump", USB_DEBUG_PRINT_REGISTERS);
}
void usb_teardown() {
    if (!gSynopsysOTGBase) return;
    reg_write(rGAHBCFG, 0x2e);
    reg_or(rDCTL, 0x2);
}
