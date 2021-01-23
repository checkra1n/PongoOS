#import <pongo.h>

/*
 --------------------------------------------------------------------------------------------------------------------------------
                 transports-supported             01 00 00 00 02 00 00 00  03 00 00 00 04 00 00 00   |................|
                                                  05 00 00 00                                        |....|
                 port-location                    back-left
                 compatible                       usbc,cd3217
                 acio-parent                      0x00000043
                 iicProvider                      0x00000093
                 AAPL,phandle                     0x00000094
                 dock                             0x000000fd
                 rid                              0x00000000
                 hpm-class-type                   0x0000000a
                 hpm-iic-addr                     0x00000038
                 port-type                        0x00000002
                 usbc-flash-update                0x00000001
                 usbc-fw-personality              HPM,27
                 port-number                      0x00000001
                 name                             hpm0
 --------------------------------------------------------------------------------------------------------------------------------
 
 https://www.ti.com/lit/ug/slvuan1a/slvuan1a.pdf
 
 */

struct cd3217_ctx {
    struct hal_device* bus;
    struct hal_device* device;
    
    lock cd3217_lock;
    lock cd3217_reg_lock;

    uint16_t i2c_addr;
    struct i2c_cmd* i2ccmd;
};

__unused static bool cd3217_reg_read(struct cd3217_ctx* cd, uint8_t regid, void* readout, uint8_t outsz) {
    uint8_t buf[64] = {0};

    lock_take(&cd->cd3217_reg_lock);
    
    i2c_cmd_set_write_tx(cd->i2ccmd, 0, cd->i2c_addr, &regid, 1);
    i2c_cmd_set_read_tx(cd->i2ccmd, 1, cd->i2c_addr, buf, 64);
    bool rv = i2c_cmd_perform(cd->bus, cd->i2ccmd);
    
    if (rv) {
        if (buf[0] > outsz) {
            buf[0] = outsz;
        }
        memcpy(readout, &buf[1], buf[0]);
    }
    
    lock_release(&cd->cd3217_reg_lock);
#ifdef CD3217_REG_LOG
    iprintf("cd3217_reg_read(%s:%x, reg %x, %x bytes): %d (%d)\n", cd->bus->name, cd->i2c_addr, regid, outsz, rv, buf[0]);
#endif
    return rv;
}

__unused static bool cd3217_reg_write(struct cd3217_ctx* cd, uint8_t regid, const void* readout, uint8_t insz) {
    uint8_t buf[64] = {0};

    lock_take(&cd->cd3217_reg_lock);
    
    if (insz > 63) {
        panic("cd3217: OOB write");
    }
    
    buf[0] = insz;
    memcpy(&buf[1], readout, insz);
    
    i2c_cmd_set_write_tx(cd->i2ccmd, 0, cd->i2c_addr, &regid, 1);
    i2c_cmd_set_write_tx(cd->i2ccmd, 1, cd->i2c_addr, buf, insz + 1);
    bool rv = i2c_cmd_perform(cd->bus, cd->i2ccmd);
    
    lock_release(&cd->cd3217_reg_lock);
#ifdef CD3217_REG_LOG
    iprintf("cd3217_reg_write(%s:%x, reg %x, %x bytes): %d\n", cd->bus->name, cd->i2c_addr, regid, insz, rv);
#endif
    return rv;
}


__unused static bool cd3217_enter_system_power_state(struct cd3217_ctx* cd, uint8_t p_state) {
    if (p_state > 5) {
        panic("cd3217: invalid pstate requested\n");
    }
    
    bool rv = cd3217_reg_write(cd, 0x20, &p_state, 1);
    if (!rv) {
        iprintf("cd3217: couldn't enter power state\n");
    }
    
    return rv;
}

__unused static int8_t cd3217_get_system_power_state(struct cd3217_ctx* cd) {
    uint8_t p_state = 0;
    if (! cd3217_reg_read(cd, 0x20, &p_state, 1)) {
        iprintf("cd3217: couldn't get power state\n");
        return -1;
    }
    
    return p_state;
}

__unused static bool cd3217_issue_cmd(struct cd3217_ctx* cd, const char* cmdname, void* data_in, uint8_t data_in_sz, void* data_out, uint8_t data_out_sz) {
    bool status;
    lock_take(&cd->cd3217_lock);

    if (data_in_sz) {
        status = cd3217_reg_write(cd, 9, data_in, data_in_sz);
        if (!status) goto failout;
    }

    status = cd3217_reg_write(cd, 8, cmdname, 4);
    if (!status) goto failout;

    uint32_t rdcmd = -1;
    
    while (1) {
        status = cd3217_reg_read(cd, 8, &rdcmd, 4);
        if (!status || rdcmd == 0x444d4321) goto failout;
        if (!rdcmd) {
            break; // successfully ran
        }
    }

    if (data_out_sz) {
        status = cd3217_reg_read(cd, 9, data_out, data_out_sz);
        if (!status) goto failout;
    }

    lock_release(&cd->cd3217_lock);
    return true;

failout:
    lock_release(&cd->cd3217_lock);
    return false;
}

static bool cd3217_register(struct hal_device* device, void** context) {
    // cd3217 USBC PD controller

    uint32_t len = 0;
    dt_node_t* node = device->node;

    uint32_t* val = dt_prop(node, "iicProvider", &len);
    if (!val || len != 4) panic("cd3217_register: dt looks broken");
    uint32_t i2c_bus_phandle = *val;
    val = dt_prop(node, "hpm-iic-addr", &len);
    if (!val || len != 4) panic("cd3217_register: dt looks broken");
    uint32_t i2c_addr = *val;

    struct hal_device* bus = hal_get_phandle_device(i2c_bus_phandle);
    if (!bus) panic("cd3217_register: invalid iicProvider");
    bus = bus->parent;
    if (!bus) panic("cd3217_register: invalid iicProvider");

    struct cd3217_ctx* cdctx = calloc(sizeof(struct cd3217_ctx), 1);

    cdctx->bus = bus;
    cdctx->device = device;
    cdctx->i2ccmd = i2c_cmd_create(2);
    cdctx->i2c_addr = i2c_addr;
    *context = cdctx;

    return true;
}

static int cd3217_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        struct cd3217_ctx* cd = (struct cd3217_ctx*)(svc->context);
        
        uint32_t vendorID = 0, deviceID = 0;
        bool success = false;
        success = cd3217_reg_read(cd, 0, &vendorID, 4);
        if (!success) panic("cd3217: couldn't fetch VID");
        success = cd3217_reg_read(cd, 1, &deviceID, 4);
        if (!success) panic("cd3217: couldn't fetch DID");
        uint32_t cd3217_uid[4];
        success = cd3217_reg_read(cd, 5, cd3217_uid, 16);
        if (!success) panic("cd3217: couldn't fetch UID");
        char sts[5];
        bzero(sts, 5);
        success = cd3217_reg_read(cd, 3, sts, 4);
        if (!success) panic("cd3217: couldn't fetch mode");

        uint32_t bsts = cd3217_get_system_power_state(cd);

        cd3217_enter_system_power_state(cd, 0);

        if (bsts == 7) {
            uint16_t win = 0;
            success = cd3217_issue_cmd(cd, "SSPS", &win, 2, NULL, 0);
            if (!success) {
                iprintf("SSPS fail!\n");
            } else {
                iprintf("SSPS success\n");
            }
        }
        
        iprintf("cd3217 device found (%s:%x)! uid: %x, pid = %x, vid = %x, mode = %s, pstate = %d\n", cd->bus->name, cd->i2c_addr, cd3217_uid[0], vendorID, deviceID, sts, bsts);

        
        success = cd3217_issue_cmd(cd, "SWDF", NULL, 0, NULL, 0);
        if (!success) {
            iprintf("SWDF fail!\n");
        } else {
            iprintf("SWDF success\n");
        }
        
        success = cd3217_issue_cmd(cd, "SWsr", NULL, 0, NULL, 0);
        if (!success) {
            iprintf("SWsr fail!\n");
        } else {
            iprintf("SWsr success\n");
        }

        return 0;
    }
    return -1;
}

static bool cd3217_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    if (hal_device_is_compatible(device, "usbc,cd3217")) {
        if (cd3217_register(device, context)) {
            return true;
        }
    }
    return false;
}
struct hpm_ctx {
    struct task* irq_task;
};

static void hpm_irq_main() {
    while (1) {
        fiprintf(stderr, "hpm irq\n");
        task_exit_irq();
    }
}
static int hpm_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        struct hpm_ctx* hpm = (struct hpm_ctx*)(svc->context);
        if (!hal_register_interrupt(device, hpm->irq_task, 0, hpm))
            panic("hpm_start: hal_register_interrupt failed!");
        
        return 0;
    }
    return -1;
}
static bool hpm_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    if (hal_device_is_compatible(device, "usbc,manager")) {
        struct hpm_ctx* ctx = calloc(sizeof(struct hpm_ctx), 1);
        ctx->irq_task = task_create_extended("hpm", hpm_irq_main, TASK_IRQ_HANDLER | TASK_PREEMPT, 0);
        *context = ctx;
        return true;
    }
    return false;
}

static struct hal_service cd3217_svc = {
    .name = "cd3217",
    .probe = cd3217_probe,
    .service_op = cd3217_service_op
};
static struct hal_service hpm_svc = {
    .name = "hpm",
    .probe = hpm_probe,
    .service_op = hpm_service_op
};

static void cd3217_init(struct driver* driver) {
    hal_register_hal_service(&hpm_svc);
    hal_register_hal_service(&cd3217_svc);
}

REGISTER_DRIVER(cd3217, cd3217_init, NULL, 0);

