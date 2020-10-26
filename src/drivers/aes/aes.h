#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_ALL_MASK (AES_MODE_MASK | AES_CIPHER_MASK | AES_BITS_MASK | AES_KEY_MASK)

#define AES_ENCRYPT     0x00000000
#define AES_DECRYPT     0x80000000
#define AES_MODE_MASK   0x80000000

#define AES_CBC         0x00000000
#define AES_ECB         0x40000000
#define AES_CIPHER_MASK 0x40000000

#define AES_128         0x10000000
#define AES_192         0x20000000
#define AES_256         0x30000000
#define AES_BITS_MASK   0x30000000

#define AES_USER_KEY    0x00000000
#define AES_UID         0x00000001
#define AES_GID0        0x00000002
#define AES_GID1        0x00000003
#define AES_KEY_MASK    0x00000003

// Return value of 0 = success.
// Any other return value is an error from <errno.h>.
int aes(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);

#endif
