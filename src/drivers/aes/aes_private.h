#ifndef AES_PRIVATE_H
#define AES_PRIVATE_H

#ifdef PONGO_PRIVATE

#include <stddef.h>
#include <stdint.h>

void aes_init(void);
void aes_a9_init(void);
int aes_a7(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);
int aes_a9(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);

#endif

#endif
