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
#include <pongo.h>

/*
 #interrupt-cells                 0x00000002
 interrupt-controller                                                                ||
 compatible                       gpio,t8101
 interrupt-parent                 0x0000005c
 interrupts                       be 00 00 00 bf 00 00 00  c0 00 00 00 c1 00 00 00   |................|
                                  c2 00 00 00 c3 00 00 00  c4 00 00 00               |............|
 #gpio-int-groups                 0x00000007
 reg                              00 00 10 3c 00 00 00 00  00 00 10 00 00 00 00 00   |...<............|
 #gpio-pins                       0x000000d4
 AAPL,phandle                     0x00000063
 device_type                      interrupt-controller
 #address-cells                   0x00000000
 role                             AP
 name                             gpio
 
 
 */


struct t8101_gpio_ctx {
    struct task* irq_task;
    uint64_t gpio_base;
};

static int gpio_irqctrl_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == IRQ_MASK && data_in_size == 4) {
        __unused uint32_t irq_index = *(uint32_t*)data_in;
    } else if (method == IRQ_UNMASK && data_in_size == 4) {
        __unused uint32_t irq_index = *(uint32_t*)data_in;
    } else if (method == IRQ_ACK) {
        __unused uint32_t irq_index = *(uint32_t*)data_in;
    } else if (method == IRQ_REGISTER && data_in_size == sizeof(struct irq_register_args)) {
        __unused struct irq_register_args* args = data_in;
        return 0;
    }
    return -1;
}

static struct hal_service gpio_irqctrl_svc = {
    .name = "irqctrl",
    .probe = NULL,
    .service_op = gpio_irqctrl_service_op
};

static void gpio_t8101_irq() {
    while (1) {
        fiprintf(stderr, "GPIO IRQ\n");
        task_exit_irq();
    }
}

static bool gpio_register_t8101(struct hal_device* device, void** context) {
    struct t8101_gpio_ctx* gpioctx = calloc(sizeof(struct t8101_gpio_ctx), 1);
    gpioctx->gpio_base = (uint64_t) hal_map_registers(device, 0, NULL);
    gpioctx->irq_task = task_create_extended(device->name, gpio_t8101_irq, TASK_IRQ_HANDLER, 0);
    hal_associate_service(device, &gpio_irqctrl_svc, gpioctx);
    *context = gpioctx;
    return true;
}


static bool gpio_t8101_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    if (hal_device_is_compatible(device, "gpio,t8101")) {
        return gpio_register_t8101(device, context);
    }
    return false;
}

static int gpio_t8101_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        struct t8101_gpio_ctx* gpioctx = svc->context;
        if (!hal_register_interrupt(device, gpioctx->irq_task, 0, gpioctx))
            panic("gpio_t8101_start: hal_register_interrupt failed!");
        
        return 0;
    }
    return -1;
}

static struct hal_service gpio_t8101_svc = {
    .name = "gpio",
    .probe = gpio_t8101_probe,
    .service_op = gpio_t8101_service_op
};


static void gpio_init(struct driver* driver) {
    hal_register_hal_service(&gpio_t8101_svc);
}

REGISTER_DRIVER(gpio, gpio_init, NULL, 0);
