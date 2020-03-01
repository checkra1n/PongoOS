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
#ifdef AUTOBOOT
#define LL_KTRW_INTERNAL 1
#include <pongo.h>

void pongo_autoboot()
{
	uint64_t* autoboot_block = (uint64_t*)0x429000000;
	if (autoboot_block[0] == 0x746F6F626F747561) {
                memcpy(loader_xfer_recv_data, &autoboot_block[2], (uint32_t)autoboot_block[1]);
                loader_xfer_recv_count = (uint32_t)autoboot_block[1];
                autoboot_count = loader_xfer_recv_count;
                queue_rx_string("modload\nautoboot\n");
	}
}

#endif
