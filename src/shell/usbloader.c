// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
#define LL_KTRW_INTERNAL 1
#include <pongo.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#define UPLOADSZ (1024 * 1024 * 128)
uint8_t * loader_xfer_recv_data;
uint32_t loader_xfer_recv_count;

extern uint64_t vatophys(uint64_t kvaddr);
char usbloader_is_waiting_xfer;
void usbloader_xfer_done_cb(void* data, uint32_t size, uint32_t transferred) {
    if (!usbloader_is_waiting_xfer) return;
    cache_invalidate(loader_xfer_recv_data, loader_xfer_recv_count);
    loader_xfer_recv_count = transferred;
    usbloader_is_waiting_xfer = 0;
}

char cmd_buf[256];
uint32_t cmd_len;
char should_wait_for_cmd_handler = 0;
extern void queue_rx_char(char inch);
bool usb_write_stdin(const void *data, uint32_t size) {
    enable_interrupts();
    const char* datac = (const char*) data;
    for (int i=0; i<size; i++) {
        if (!datac[i]) break;
        queue_rx_char(datac[i]);
    }
    if (should_wait_for_cmd_handler)
        event_wait(&command_handler_iter);
    disable_interrupts();
    return true;
}
void usbloader_init() {
    loader_xfer_recv_data = alloc_contig(UPLOADSZ);
    loader_xfer_recv_count = 0;
} // fetch_stdoutbuf

char stdoutbuf_copy[STDOUT_BUFLEN];
void usb_read_stdout_cb() {
    
}
bool ep0_device_request(struct setup_packet *setup) {
    if (setup->bmRequestType == 0x21) {
        if (setup->bRequest == 1 && setup->wLength == 0) { // request bulk upload initialization
            if (usbloader_is_waiting_xfer) return false;
            loader_xfer_recv_count = 0;
            usbloader_is_waiting_xfer = 1;
            usb_out_transfer_dma(2, loader_xfer_recv_data, vatophys((uint64_t)loader_xfer_recv_data), UPLOADSZ, usbloader_xfer_done_cb); // should resolve the VA rather than doing this, but oh well.
            return true;
        }
        if (setup->bRequest == 2 && setup->wLength == 0) { // discard loaded data
            if (!usbloader_is_waiting_xfer)
                loader_xfer_recv_count = 0;
            return true;
        }
        if (setup->bRequest == 3 && setup->wLength > 0 && setup->wLength < 256) { // write to stdin
            ep0_begin_data_out_stage(usb_write_stdin);
            return true;
        }
        if (setup->bRequest == 4) { // make it so next write to stdin will stall until command is over
            should_wait_for_cmd_handler = 1;
            return true;
        }
    } else if (setup->bmRequestType == 0xA1) {
        // IN request
        if (setup->bRequest == 1 && setup->wLength == 512) { // request bulk upload initialization
            int xferlen = 0;
            fetch_stdoutbuf(stdoutbuf_copy, &xferlen);
            ep0_begin_data_in_stage(stdoutbuf_copy, xferlen, usb_read_stdout_cb);
            return true;
        }       
    }
    return false;
}
