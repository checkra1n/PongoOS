#import <pongo.h>
#import "i2c.h"


struct i2c_8940x_ctx {
    uint64_t i2c_regbase;
    struct hal_device* device;
    lock i2c_lock;
    
    uint8_t* data_in;
    uint16_t data_in_size;
    
    struct event irq_event;
    struct task* irq_task;
    
    uint32_t rdreg;
};

__unused static uint32_t i2c_8940x_reg_read(struct i2c_8940x_ctx* i2c, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(i2c->i2c_regbase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_8940x_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}

__unused static void i2c_8940x_reg_write(struct i2c_8940x_ctx* i2c, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_8940x_reg_write(%x) = %x\n", offset, rv);
#endif
    *(volatile uint32_t *)(i2c->i2c_regbase + offset) = value;
}

__unused static void i2c_8940x_reg_or(struct i2c_8940x_ctx* i2c, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_reg_or(%x) = %x\n", offset, rv);
#endif
    *(volatile uint32_t *)(i2c->i2c_regbase + offset) |= value;
}

static void i2c_8940x_init_regs(struct i2c_ctx* ctx) {
    struct i2c_8940x_ctx* i2c = ctx->context;
    
    i2c_8940x_reg_write(i2c, 0x1c, 4);
    i2c_8940x_reg_write(i2c, 0x14, 0xAA00040);
    i2c_8940x_reg_write(i2c, 0x18, 0);
    i2c_8940x_reg_write(i2c, 0x10, 0x80000000);
    
    uint32_t hwrev = i2c_8940x_reg_read(i2c, 0x28);
    if (hwrev >= 6) {
        i2c_8940x_reg_or(i2c, 0x1c, 0x800);
    }
    
    /*
        TBD: filter-tunable and tbuf-tunable impl
     */
}

__unused static void i2c_8940x_lockunlock(struct i2c_8940x_ctx* i2c, bool lockunlock) {
    if (lockunlock) {
        i2c_8940x_reg_write(i2c, 0x44, 1);
    } else {
        i2c_8940x_reg_write(i2c, 0x44, 0);
    }
}

static void i2c_8940x_irq_task() {
    while (1) {
        fiprintf(stderr, "i2c irq\n");
        struct i2c_8940x_ctx* i2c = task_current_interrupt_context();
        i2c_8940x_reg_write(i2c, 0x18, 0);
        i2c->rdreg = i2c_8940x_reg_read(i2c, 0x14);
        i2c_8940x_reg_write(i2c, 0x14, i2c->rdreg);
        event_fire(&i2c->irq_event);
        
        task_exit_irq();
    }

}

static bool i2c_8940x_read(struct i2c_ctx* ctx, uint16_t addr, void* data_in, uint16_t size) {
    struct i2c_8940x_ctx* i2c = ctx->context;

    uint32_t rg = i2c_8940x_reg_read(i2c, 0x2C);
    rg &= 0xFFFF00FF;
    rg |= ((size << 8) & 0xFF00);
    i2c_8940x_reg_write(i2c, 0x2C, rg);
    
    i2c_8940x_reg_write(i2c, 0, ((addr << 1) & 0xFE) | 0x101);
    i2c_8940x_reg_write(i2c, 0, size | 0x600);
    
    uint8_t* data_in_c = data_in;
    uint16_t data_cursor = 0;
    
    while (1) {
        disable_interrupts();
        i2c_8940x_reg_write(i2c, 0x18, 0xB00040);
        i2c->rdreg = 0;
        event_wait_asserted(&i2c->irq_event);
        
        if (i2c->rdreg & 0xA00040) {
            return false;
        }

        uint8_t readb = i2c_8940x_reg_read(i2c, 0x8) >> 8;
        for (uint8_t i = 0; i < readb; i++) {
            if (data_cursor >= size) {
                panic("i2c_8940x_read: ???");
            }
            data_in_c[data_cursor++] = i2c_8940x_reg_read(i2c, 4);
        }
        
        if (data_cursor >= size) {
            break;
        }
    }
    
    return true;
}

static bool i2c_8940x_write(struct i2c_ctx* ctx, uint16_t addr, void* data_out, uint16_t size) {
    struct i2c_8940x_ctx* i2c = ctx->context;
    uint8_t* data_out_c = data_out;
    
    i2c_8940x_reg_write(i2c, 0, ((addr << 1) & 0xFE) | 0x100);
    for (int i=0; i < size; i++) {
        i2c_8940x_reg_write(i2c, 0, data_out_c[i] | (i+1 == size ? 0x200 : 0));
    }
    
    return true;
}

static bool i2c_8960x_command_perform(struct i2c_ctx* ctx, struct i2c_cmd* cmd) {
    struct i2c_8940x_ctx* i2c = ctx->context;
    
    lock_take(&i2c->i2c_lock);
    
    i2c_8940x_init_regs(ctx);
    
    for (uint16_t i = 0; i < cmd->txno; i++) {
        if (cmd->txes[i].readwrite) {
            // write
            if (!i2c_8940x_write(ctx, cmd->txes[i].addr, cmd->txes[i].buf, cmd->txes[i].size)) {
                lock_release(&i2c->i2c_lock);
                return false;
            }
        } else {
            // read
            if (!i2c_8940x_read(ctx, cmd->txes[i].addr, cmd->txes[i].buf, cmd->txes[i].size)) {
                lock_release(&i2c->i2c_lock);
                return false;
            }
        }
    }
    
    lock_release(&i2c->i2c_lock);
    return true;
}


struct i2c_ops i2c_8940x_ops = {
    .i2c_command_perform = i2c_8960x_command_perform
};

static bool register_8940x_i2c(struct hal_device* device, void** context) {
    // S5L8940x I2C controller

    struct i2c_8940x_ctx* i2c = calloc(sizeof(struct i2c_8940x_ctx), 1);

    dt_node_t* node = device->node;

    uint32_t len = 0;
    void* name = dt_prop(node, "name", &len);
    
    i2c->device = device;
    i2c->i2c_regbase = (uint64_t)hal_map_registers(i2c->device, 0, NULL);

    hal_invoke_service_op(i2c->device, "hal", HAL_DEVICE_CLOCK_GATE_ON, NULL, 0, NULL, NULL); // turn on I2C controller

    i2c->irq_task = task_create_extended(name, i2c_8940x_irq_task, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);
    interrupt_associate_context(hal_get_irqno(device,0), i2c);
    task_bind_to_irq(i2c->irq_task, hal_get_irqno(device,0));

    *context = i2c;
    
    return true;
}

static int i2c_8940x_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {

        /*
         test i2c by doing a register read on the usb controller's VID
         */

        struct i2c_cmd* cmd = i2c_cmd_create(2);
        uint8_t regid = 0x00;
        i2c_cmd_set_write_tx(cmd, 0, 0x38, &regid, 1);
        uint32_t readreg = 0;
        i2c_cmd_set_read_tx(cmd, 1, 0x38, &readreg, 4);

        struct i2c_ctx fake = {0};
        fake.context = svc->context;

        bool rv = i2c_8960x_command_perform(&fake, cmd);
        
        i2c_cmd_destroy(cmd);
        
        fiprintf(stderr, "I2C READ: %x (%d)\n", readreg, rv);

        return 0;
    }
    return -1;
}

static bool i2c_8940x_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "i2c") == 0) {
            char* compat = dt_prop(node, "compatible", &len);
            char* compatend = compat + len;
            
            while (compat < compatend) {
                if (strcmp(compat, "i2c,s5l8940x") == 0) {
                    if (register_8940x_i2c(device, context)) {
                        return i2c_provide_service(device, &i2c_8940x_ops, *context);
                    }
                    return false;
                }
                compat += strlen(compat) + 1;
            }
        }
    }
    return false;
}

static struct hal_service i2c_8940x_svc = {
    .name = "i2c8940x",
    .probe = i2c_8940x_probe,
    .service_op = i2c_8940x_service_op
};

static void i2c_8940x_init(struct driver* driver) {
    hal_register_hal_service(&i2c_8940x_svc);
}

REGISTER_DRIVER(i2c_8940x, i2c_8940x_init, NULL, 0);
