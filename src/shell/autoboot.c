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
#ifdef AUTOBOOT
#include <pongo.h>
uint64_t* autoboot_block;
void pongo_autoboot()
{
	if (autoboot_block) {
        resize_loader_xfer_data((uint32_t)autoboot_block[1]);
        memcpy(loader_xfer_recv_data, &autoboot_block[2], (uint32_t)autoboot_block[1]);
        loader_xfer_recv_count = (uint32_t)autoboot_block[1];
        autoboot_count = loader_xfer_recv_count;
        phys_force_free(vatophys((uint64_t)autoboot_block), (autoboot_block[1] + 0x20 + 0x3fff) & ~0x3fff);

        queue_rx_string("modload\nautoboot\n");
	}
}

#endif
