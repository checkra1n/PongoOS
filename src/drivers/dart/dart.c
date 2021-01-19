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
#import "dart.h"

#define DART1_ERROR_STATUS 0x0040
#define DART1_ERROR_FLAG (1 << 30)
#define DART1_ERROR_SID_MASK (15 << 24)
#define DART1_ERROR_APF_REJECT (1 << 11)
#define DART1_ERROR_UNKNOWN (1 << 9)
#define DART1_ERROR_CTRR_WRITE_PROT (1 << 8)
#define DART1_ERROR_REGION_PROT (1 << 7)
#define DART1_ERROR_AXI_SLV_ERR (1 << 6)
#define DART1_ERROR_AXI_SLV_DECODE (1 << 5)
#define DART1_ERROR_READ_PROT (1 << 4)
#define DART1_ERROR_WRITE_PROT (1 << 3)
#define DART1_ERROR_PTE_INVLD (1 << 2)
#define DART1_ERROR_L2E_INVLD (1 << 1)
#define DART1_ERROR_TTBR_INVLD (1 << 0)
#define DART1_ERROR_ADDRESS_LO 0x0050
#define DART1_ERROR_ADDRESS_HI 0x0054

struct t8020_dart {
    uint64_t dart_type;
    uint64_t dart_regbase;
    uint64_t dart_flags;
    uint64_t dart_bypass_base;
};

__unused static uint32_t dart8020_reg_read(struct t8020_dart* dart, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(dart->dart_regbase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "dart8020_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}
__unused static void dart8020_reg_write(struct t8020_dart* dart, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "dart8020_reg_write(%x) = %x\n", offset, value);
#endif
    *(volatile uint32_t *)(dart->dart_regbase + offset) = value;
}


#define DART_FLAGS_MODE_MASK 3
#define DART_FLAGS_MODE_BYPASS 1

struct task* dart_irq_task;

void dart_irq_handler() {
    while (1) {
        __unused struct t8020_dart* dart = task_current_interrupt_context();

        uint32_t dart_error_status = dart8020_reg_read(dart, DART1_ERROR_STATUS);
        uint32_t dart_error_addr_lo = dart8020_reg_read(dart, DART1_ERROR_ADDRESS_LO);
        uint32_t dart_error_addr_hi = dart8020_reg_read(dart, DART1_ERROR_ADDRESS_HI);

        uint64_t dart_error_addr = dart_error_addr_lo;
        dart_error_addr |= ((uint64_t)dart_error_addr_hi) << 32ULL;
        
        for (int i=0; i < 256; i++) {
            fiprintf(stderr, "%02x: %08x ", i*4, dart8020_reg_read(dart, i*4));
            if (3 == (i & 3)) {
                fiprintf(stderr, "\n");
            }
        }
        fiprintf(stderr, "\n");
        panic("DART error! ERRSTS: %x, ERRADDR: %llx", dart_error_status, dart_error_addr);


        task_exit_irq();
    }
}

static bool register_dart_mapper(struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    dt_node_t* pnode = device->parent->node;

    if (strcmp(dt_prop(pnode, "compatible", &len), "dart,t8020") == 0) {
        void* val = dt_prop(node, "name", &len);

        uint32_t* regid = dt_prop(node, "reg", &len);
        if (len != 4) regid = NULL;

        uint32_t reg_index = 0;
        if (regid) {
            reg_index = *regid;
        }
        
        void* regs = hal_map_registers(device->parent, reg_index, NULL);
        
        if (!regs) {
            iprintf("Couldn't map MMIO for 8020 dart-mapper: %s\n", val);
            return false;
        }
        
        struct t8020_dart* dart = calloc(sizeof(struct t8020_dart), 1);
        dart->dart_type = 0x8020;
        dart->dart_regbase = (uint64_t) regs;
        
        int dart_irq = hal_get_irqno(device->parent, 0);
        if (dart_irq > 0) {
            if (!interrupt_context(dart_irq)) {
                if (!dart_irq_task) {
                    dart_irq_task = task_create_extended("dart", dart_irq_handler, TASK_IRQ_HANDLER, 0); // can't be preempt since we map the same task to many different IRQs, which means task_current_interrupt_context is UB
                }
                task_bind_to_irq(dart_irq_task, dart_irq);
                interrupt_associate_context(dart_irq, dart);
            }
        }
        
        iprintf("Found 8020 dart-mapper: %s @ %llx\n", val, dart->dart_regbase);

        *context = dart;
        return true;
    }
    
    return false;
}

static bool dart_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "dart-mapper") == 0) {
            return register_dart_mapper(device, context);
        }
    }
    return false;
}
#define DART_TTBR(n) (0x200 + n*4)
#define DART_MODE(n) (0x100 + n*4)
#define DART_MODE_BYPASS(high_byte) ((high_byte << 16) | 0x100)
static int dart_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    struct t8020_dart* dart = ((struct t8020_dart*)svc->context);
    if (method == DART_ENTER_BYPASS_MODE) {
        if (dart->dart_type == 0x8020) {
            for (int i=0; i < 32; i++) {
                dart8020_reg_write(dart, DART_MODE(i), DART_MODE_BYPASS(0x8));
            }
            for (int i=0; i < 32; i++) {
                dart8020_reg_write(dart, DART_TTBR(i), 0);
            }

            dart->dart_bypass_base = 0x800000000;
            
            dart->dart_flags &= ~DART_FLAGS_MODE_MASK;
            dart->dart_flags |= DART_FLAGS_MODE_BYPASS;            
            
            return dart_service_op(svc, device, DART_FLUSH_CACHE, NULL, 0, NULL, 0);
        }
    } else if (method == DART_FLUSH_CACHE) {
        if (dart->dart_type == 0x8020) {
            dart8020_reg_write(dart, 0x34, 0);
            dart8020_reg_write(dart, 0x20, 0);
            while(dart8020_reg_read(dart, 0x20) & 4) {}
            return 0;
        }
    } else if (method == DART_BYPASS_CONVERT_PTR && data_in_size == 8 && data_out_size && *data_out_size == 8) {
        if ((dart->dart_flags & DART_FLAGS_MODE_MASK) == DART_FLAGS_MODE_BYPASS) {
            uint64_t inptr = *(uint64_t*)data_in;
            
            if (inptr >= dart->dart_bypass_base) {
                *(uint64_t*)data_out = inptr - dart->dart_bypass_base;
                return 0;
            }
        }
    }
    return -1;
}

static struct hal_service dart_svc = {
    .name = "dart",
    .probe = dart_probe,
    .service_op = dart_service_op
};

static void dart_init(struct driver* driver) {
    hal_register_hal_service(&dart_svc);
}

REGISTER_DRIVER(dart, dart_init, NULL, 0);
