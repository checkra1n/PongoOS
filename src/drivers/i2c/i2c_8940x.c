#import <pongo.h>

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

static void i2c_8940x_init_regs(struct i2c_8940x_ctx* i2c) {
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
        // fiprintf(stderr, "i2c irq\n");
        struct i2c_8940x_ctx* i2c = task_current_interrupt_context();
        i2c_8940x_reg_write(i2c, 0x18, 0);
        i2c->rdreg = i2c_8940x_reg_read(i2c, 0x14);
        i2c_8940x_reg_write(i2c, 0x14, i2c->rdreg);
        event_fire(&i2c->irq_event);
        task_exit_irq();
    }

}

static bool i2c_8940x_read(struct i2c_8940x_ctx* i2c, uint16_t addr, void* data_in, uint16_t size) {
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
            uint32_t rdreg = i2c_8940x_reg_read(i2c, 0x14);
            i2c_8940x_reg_write(i2c, 0x14, rdreg);
            i2c_8940x_reg_write(i2c, 0x10, 0x80000000);
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

static bool i2c_8940x_write(struct i2c_8940x_ctx* i2c, uint16_t addr, void* data_out, uint16_t size) {
    uint8_t* data_out_c = data_out;
    
    i2c_8940x_reg_write(i2c, 0, ((addr << 1) & 0xFE) | 0x100);
    
    i2c_8940x_lockunlock(i2c, true);
    for (uint32_t i=0; i < size; i++) {
        if (i && !(i & 0xF)) {
            // fifo depth is not too great
            i2c_8940x_lockunlock(i2c, false);
            
            while (1) {
                disable_interrupts();
                i2c_8940x_reg_write(i2c, 0x18, 0x8800040);
                i2c->rdreg = 0;
                event_wait_asserted(&i2c->irq_event);
                if (i2c->rdreg & 0x800040) {
                    uint32_t rdreg = i2c_8940x_reg_read(i2c, 0x14);
                    i2c_8940x_reg_write(i2c, 0x14, rdreg);
                    i2c_8940x_reg_write(i2c, 0x10, 0x80000000);
                    return false;
                }
                if (i2c->rdreg & 0x08000000) {
                    // tx queue space available
                    break;
                }
            }

            i2c_8940x_lockunlock(i2c, true);
        }
        i2c_8940x_reg_write(i2c, 0, data_out_c[i] | (i+1 == size ? 0x200 : 0));
    }
    i2c_8940x_lockunlock(i2c, false);
    return true;
}

static bool i2c_8960x_command_perform(struct i2c_8940x_ctx* i2c, struct i2c_cmd* cmd) {
    lock_take(&i2c->i2c_lock);
    
    i2c_8940x_init_regs(i2c);
    
    for (uint16_t i = 0; i < cmd->txno; i++) {
        if (cmd->txes[i].readwrite) {
            // write
            if (!i2c_8940x_write(i2c, cmd->txes[i].addr, cmd->txes[i].buf, cmd->txes[i].size)) {
                lock_release(&i2c->i2c_lock);
                return false;
            }
        } else {
            // read
            if (!i2c_8940x_read(i2c, cmd->txes[i].addr, cmd->txes[i].buf, cmd->txes[i].size)) {
                lock_release(&i2c->i2c_lock);
                return false;
            }
        }
    }
    
    lock_release(&i2c->i2c_lock);
    return true;
}


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
        return 0;
    } else if (method == I2C_CMD_PERFORM && data_in && data_in_size == I2C_CMD_PERFORM_SIZE){
        if (i2c_8960x_command_perform(svc->context, data_in)) {
            return 0;
        }
        return -1;
    }
    return -1;
}

static bool i2c_8940x_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    if (hal_device_is_compatible(device, "i2c,s5l8940x")) {
        if (register_8940x_i2c(device, context)) {
            return true;
        }
    }
    return false;

}

static struct hal_service i2c_8940x_svc = {
    .name = "i2c",
    .probe = i2c_8940x_probe,
    .service_op = i2c_8940x_service_op
};

static void i2c_8940x_init(struct driver* driver) {
    hal_register_hal_service(&i2c_8940x_svc);
}

REGISTER_DRIVER(i2c_8940x, i2c_8940x_init, NULL, 0);
