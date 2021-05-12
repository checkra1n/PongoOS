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
#include <pongo.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#define UPLOADSZ (1024 * 1024)
#define UPLOADSZ_MAX (1024 * 1024 * 128)

uint8_t * loader_xfer_recv_data;
uint32_t loader_xfer_recv_count;
uint32_t loader_xfer_recv_size;
uint32_t loader_next_xfer_size;
uint32_t loader_xfer_size;
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

void resize_loader_xfer_data(uint32_t newsz) {
    if (newsz > UPLOADSZ_MAX) panic("resize_loader_xfer_data");
    disable_interrupts();
    if (newsz > loader_xfer_recv_size) {
        uint8_t* new_xfer_buffer = alloc_contig(newsz);
        memcpy(new_xfer_buffer, loader_xfer_recv_data, loader_xfer_recv_count);
        free_contig(loader_xfer_recv_data, loader_xfer_recv_size);
        loader_xfer_recv_size = newsz;
        loader_xfer_recv_data = new_xfer_buffer;
    }
    enable_interrupts();
}
bool reallocate_loader_xfer_data(const void* data, uint32_t size) {
    if (size != 4) panic("reallocate_loader_xfer_data");
    
    uint32_t newsz = *(uint32_t*)data;
    newsz += 0x1ff;
    newsz &= ~0x1ff;
    if (newsz > UPLOADSZ_MAX) return false;
    loader_xfer_recv_count = 0;
    usbloader_is_waiting_xfer = 1;
    resize_loader_xfer_data(newsz);
    loader_xfer_size = newsz;
    usb_out_transfer_dma(2, loader_xfer_recv_data, vatophys((uint64_t)loader_xfer_recv_data), loader_xfer_size, usbloader_xfer_done_cb); // should resolve the VA rather than doing this, but oh well.

    return true;
}

void usbloader_init() {
    loader_xfer_recv_data = alloc_contig(UPLOADSZ);
    loader_xfer_size = UPLOADSZ;
    loader_xfer_recv_size = UPLOADSZ;
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
            usb_out_transfer_dma(2, loader_xfer_recv_data, vatophys((uint64_t)loader_xfer_recv_data), loader_xfer_size, usbloader_xfer_done_cb); // should resolve the VA rather than doing this, but oh well.
            return true;
        }
        if (setup->bRequest == 2 && setup->wLength == 0) { // discard loaded data
            if (!usbloader_is_waiting_xfer)
                loader_xfer_recv_count = 0;
            return true;
        }
        if (setup->bRequest == 3 && setup->wLength > 0 && setup->wLength <= 512) { // write to stdin
            ep0_begin_data_out_stage(usb_write_stdin);
            return true;
        }
        if (setup->bRequest == 4) {
            if(setup->wValue == 0) // make it so next write to stdin will stall until command is over
            {
                should_wait_for_cmd_handler = 1;
                set_stdout_blocking(false);
                return true;
            }
            if(setup->wValue == 1) // make writes to stdout stall until async check-in
            {
                should_wait_for_cmd_handler = 0;
                set_stdout_blocking(true);
                return true;
            }
            if(setup->wValue == 0xffff) // reset all
            {
                should_wait_for_cmd_handler = 0;
                set_stdout_blocking(false);
                return true;
            }
        }
        if (setup->bRequest == 1 && setup->wLength == 4) { // request upload buffer size change
            if (usbloader_is_waiting_xfer) return false;
            ep0_begin_data_out_stage(reallocate_loader_xfer_data);
            return true;
        }
    } else if (setup->bmRequestType == 0xA1) {
        // IN request
        if (setup->bRequest == 1 && (setup->wLength == 512 || setup->wLength == 0x1000)) { // request bulk upload initialization
            int xferlen = 0;
            char *buf = stdoutbuf_copy;
            fetch_stdoutbuf(buf, &xferlen);
            if(xferlen > setup->wLength)
            {
                buf += xferlen - setup->wLength;
                xferlen = setup->wLength;
            }
            ep0_begin_data_in_stage(buf, xferlen, usb_read_stdout_cb);
            return true;
        }
        if (setup->bRequest == 2 && setup->wLength == 1) { // check for async command completion status
            uint8_t inprog = command_in_progress;
            ep0_begin_data_in_stage(&inprog, 1, usb_read_stdout_cb);
            return true;
        }
    }
    return false;
}
