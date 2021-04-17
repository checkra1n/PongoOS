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

uint32_t dt_get_u32_prop(const char* device, const char* prop) {
    uint32_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint32_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[0], 4);
    return rval;
}
uint64_t dt_get_u64_prop(const char* device, const char* prop) {
    uint64_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint64_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[0], 8);
    return rval;
}
uint64_t dt_get_u64_prop_i(const char* device, const char* prop, uint32_t idx) {
    uint64_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint64_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[idx], 8);
    return rval;
}
void* dt_get_prop(const char* device, const char* prop, uint32_t* size) {
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    void* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    if (size) *size = len;
    return val;
}

