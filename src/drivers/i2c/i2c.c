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
#import <pongo.h>
#import "i2c.h"

static bool i2c_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    panic("i2c_probe: i2c service is a virtual service provider that is not registered to HAL!");
    return false;
}

static int i2c_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        return 0;
    }
    return -1;
}

static struct hal_service i2c_svc = {
    .name = "i2c",
    .probe = i2c_probe,
    .service_op = i2c_service_op
};

bool i2c_provide_service(struct hal_device* device, struct i2c_ops* ops, void* context) {
    struct i2c_ctx* ctx = calloc(sizeof(struct i2c_ctx), 1);
    ctx->ops = ops;
    ctx->context = context;
    hal_associate_service(device, &i2c_svc, ctx);
    return true;
}

