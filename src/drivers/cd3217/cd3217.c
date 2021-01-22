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
 */

struct cd3217_ctx {
    struct hal_device* bus;
    struct hal_device* device;
    
    lock cd3217_lock;
    
    uint16_t i2c_addr;
    struct i2c_cmd* i2ccmd;
};

__unused static bool cd3217_reg_read(struct cd3217_ctx* cd, uint8_t regid, void* readout, uint16_t outsz) {
    lock_take(&cd->cd3217_lock);
    
    i2c_cmd_set_write_tx(cd->i2ccmd, 0, cd->i2c_addr, &regid, 1);
    i2c_cmd_set_read_tx(cd->i2ccmd, 1, cd->i2c_addr, readout, outsz);
    bool rv = i2c_cmd_perform(cd->bus, cd->i2ccmd);
    
    lock_release(&cd->cd3217_lock);
#ifdef CD3217_REG_LOG
    iprintf("cd3217_reg_read(%s:%x, reg %x, %x bytes): %d\n", cd->bus->name, cd->i2c_addr, regid, outsz, rv);
#endif
    return rv;
}

__unused static bool cd3217_reg_write(struct cd3217_ctx* cd, uint8_t regid, void* readout, uint16_t insz) {
    lock_take(&cd->cd3217_lock);
    
    i2c_cmd_set_write_tx(cd->i2ccmd, 0, cd->i2c_addr, &regid, 1);
    i2c_cmd_set_write_tx(cd->i2ccmd, 1, cd->i2c_addr, readout, insz);
    bool rv = i2c_cmd_perform(cd->bus, cd->i2ccmd);
    
    lock_release(&cd->cd3217_lock);
#ifdef CD3217_REG_LOG
    iprintf("cd3217_reg_write(%s:%x, reg %x, %x bytes): %d\n", cd->bus->name, cd->i2c_addr, regid, insz, rv);
#endif
    return rv;
}


static bool cd3217_enter_system_power_state(struct cd3217_ctx* cd, uint8_t p_state) {
    if (p_state > 5) {
        panic("cd3217: invalid pstate requested\n");
    }
    
    bool rv = cd3217_reg_write(cd, 0x20, &p_state, 1);
    if (!rv) {
        iprintf("cd3217: couldn't enter power state\n");
    }
    
    return rv;
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
        uint64_t cd3217_uid[2];
        success = cd3217_reg_read(cd, 5, cd3217_uid, 16);
        if (!success) panic("cd3217: couldn't fetch UID");
                                  
        iprintf("cd3217 device found (%s:%x)! uid: %016llx%016llx, pid = %x, vid = %x\n", cd->bus->name, cd->i2c_addr, cd3217_uid[0], cd3217_uid[1], vendorID, deviceID);
        
        cd3217_enter_system_power_state(cd, 0);
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

static struct hal_service cd3217_svc = {
    .name = "cd3217",
    .probe = cd3217_probe,
    .service_op = cd3217_service_op
};

static void cd3217_init(struct driver* driver) {
    hal_register_hal_service(&cd3217_svc);
}

REGISTER_DRIVER(cd3217, cd3217_init, NULL, 0);

