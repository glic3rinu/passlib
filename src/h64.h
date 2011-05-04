/* exports for h64.c */

#ifndef PASSLIB_H64_H
#define PASSLIB_H64_H 1

#include <stdint.h>

inline uint8_t h64_decode_int6(char ch);
inline char h64_encode_int6(uint8_t value);

void h64_encode_from_long(char *dst, unsigned long src, int bytes);

#endif /* PASSLIB_H64_H */
