/* h64.c - hash64 encoding routines

    this is a collection of C-level routines
    fufilling the same purpose as the passlib.util.h64 python module.
*/

#include <stdint.h>
#include "h64.h"

static const char hash64[] =
     "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/*	  0000000000111111111122222222223333333333444444444455555555556666 */
/*	  0123456789012345678901234567890123456789012345678901234567890123 */
/* plain 6-bit int <-> ascii char */
/*
inline uint8_t h64_decode_int6(char ch)
{
	if (ch > 'z')
		return(0);
	if (ch >= 'a')
		return(ch - 'a' + 38);
	if (ch > 'Z')
		return(0);
	if (ch >= 'A')
		return(ch - 'A' + 12);
	if (ch > '9')
		return(0);
	if (ch >= '.')
		return(ch - '.');
	return(0);
}

char h64_encode_int6(uint8_t value)
{
    return hash64[value & 0x3f];
}
*/
/* encode multi-byte strings <-> long */
void h64_encode_from_long(char *dst, unsigned long src, int bytes)
{
	while (--bytes >= 0) {
		*(dst++) = hash64[src&0x3f];
		src >>= 6;
	}
}
