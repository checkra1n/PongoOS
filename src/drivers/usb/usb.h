/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2021 checkra1n team
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
#include <stdbool.h>
#define USB_DEBUG_ITERATION 0
#define USB_DEBUG_INCREMENT_ITERATION()			do { } while (0)
#if defined(USB_DEBUG_LEVEL) && USB_DEBUG_LEVEL >= 1
#   include <stdio.h>
#   define USB_DEBUG(_type, fmt, ...)			do { fiprintf(stderr, fmt "\n", ##__VA_ARGS__); } while(0)
#else
#   define USB_DEBUG(_type, ...)				do { } while (0)
#endif
#define USB_DEBUG_ABORT()				do { } while (0)
#define USB_DEBUG_ABORT_ON_ITERATION(_iteration)	do { } while (0)
#define BUG(n) panic("USB BUG: " #n)

struct usb_regs {
    uint64_t reg1;
    uint64_t reg2;
    uint64_t reg3;
    int otg_irq;
};

struct setup_packet {
	uint8_t  bmRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

struct device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
} __attribute__((packed));

struct configuration_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  bMaxPower;
} __attribute__((packed));

struct interface_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bInterfaceNumber;
	uint8_t bAlternateSetting;
	uint8_t bNumEndpoints;
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t iInterface;
} __attribute__((packed));

struct endpoint_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
} __attribute__((packed));

struct string_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bString[0];
} __attribute__((packed));

// ---- USB configuration -------------------------------------------------------------------------

// The maximum packet size for EP 0 is 64 bytes.
#define EP0_MAX_PACKET_SIZE	64

// The maximum packet size for Interrupt endpoints is 1024 bytes.
#define INTR_EP_MAX_PACKET_SIZE    1024

// The maximum packet size for Bulk endpoints is 512 bytes.
#define BULK_EP_MAX_PACKET_SIZE    512

enum {
	/* 0 is reserved */
	iManufacturer = 1,
	iProduct      = 2,
	iSerialNumber = 3,
};

extern void usb_init();
extern void usb_teardown();
extern void ep0_begin_data_in_stage(const void *data, uint32_t size, void (*callback)(void));
extern void ep0_begin_data_out_stage(bool (*callback)(const void *data, uint32_t size));
extern size_t usb_read(void *data, size_t size);
extern size_t usb_write(const void *data, size_t size);
extern void usb_in_transfer(uint8_t ep_addr, const void *data, uint32_t size, void (*callback)(void));
extern void usb_out_transfer(uint8_t ep_addr, void *data, uint32_t size, void (*callback)(void *data, uint32_t size, uint32_t transferred));
extern void usb_out_transfer_dma(uint8_t ep_addr, void *data, uint32_t dma, uint32_t size, void (*callback)(void *data, uint32_t size, uint32_t transferred));
