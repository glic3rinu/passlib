/* exports for des.c */

#ifndef PASSLIB_DES_H
#define PASSLIB_DES_H 1

#include <stdint.h>

void des_init_tables(void);
    /* initialize des tables - NOT THREAD SAFE */

int des_cipher_block(const uint8_t *key,
               const uint8_t *input,
               uint8_t *output,
               long salt, long count
               );
    /* encrypt single des block using specified key, salt, and rounds
       - thread safe IFF des_init_tables() already called */

#endif /* PASSLIB_DES_H */
