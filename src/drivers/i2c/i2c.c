
#import <pongo.h>
#import "i2c.h"

struct i2c_cmd* i2c_cmd_create(uint16_t txno) {
    struct i2c_cmd* cmd = calloc(sizeof(struct i2c_cmd) + sizeof(struct i2c_tx) * txno, 1);
    cmd->txno = txno;
    return cmd;
}
void i2c_cmd_destroy(struct i2c_cmd* cmd) {
    free(cmd);
}

void i2c_cmd_set_write_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, const void* base, uint16_t size) {
    cmd->txes[index].buf = (void*)base;
    cmd->txes[index].size = size;
    cmd->txes[index].addr = address;
    cmd->txes[index].readwrite = true;
}

void i2c_cmd_set_read_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, void* base, uint16_t size) {
    cmd->txes[index].buf = base;
    cmd->txes[index].size = size;
    cmd->txes[index].addr = address;
    cmd->txes[index].readwrite = false;
}
bool i2c_cmd_perform(struct hal_device* i2c_dev, struct i2c_cmd* cmd){
    if ( ! hal_invoke_service_op(i2c_dev, "i2c", I2C_CMD_PERFORM, (void*)cmd, I2C_CMD_PERFORM_SIZE, NULL, NULL) ) {
        return true;
    }
    return false;
}
