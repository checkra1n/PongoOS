struct i2c_ctx;

struct i2c_tx {
    void* buf;
    uint16_t size;
    uint16_t addr;
    bool readwrite; // true = write, false = read
};

struct i2c_cmd {
    uint16_t txno;
    struct i2c_tx txes[];
};

#define I2C_CMD_PERFORM 1
#define I2C_CMD_PERFORM_SIZE 0xFFFFFFFF

struct i2c_cmd* i2c_cmd_create(uint16_t txno);
extern void i2c_cmd_destroy(struct i2c_cmd* cmd);
extern void i2c_cmd_set_write_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, void* base, uint16_t size);
extern void i2c_cmd_set_read_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, void* base, uint16_t size);
extern bool i2c_cmd_perform(struct hal_device* i2c_dev, struct i2c_cmd* cmd);
