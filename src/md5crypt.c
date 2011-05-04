/*
 * passlib/src/md5crypt.c - md5-crypt & apr-md5-crypt encryption routines
 *
 * this file is a direct copy of FreeBSD's md5crypt.c,
 * taken from http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2
 * the following changes were made from the original:
 *     - mild refactoring of frontend functions
 *     - changed to use C99 types
 *
 * ============================================================================
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 *
 */

#include <string.h>
#include <stdint.h>
#include <openssl/md5.h>
#include "h64.h"
#include "md5crypt.h"

#define to64 h64_encode_from_long

int md5_crypt(char *outbuf,
              char *passwd,
              char *salt,
              char *magic)
{
    /* NOTE: 'magic' should be '$1$' for md5 crypt,
     * and '$apr1$' for apache md5 crypt
     *
     * NOTE: outbuf must have at least 23 bytes alloc'd
     * it will be filled with the encoded checksum ONLY
     *
     * returns 1 on error, 0 on success
     */
	MD5_CTX	ctx;
    uint8_t tmpbuf[MD5_DIGEST_LENGTH];
    char *p;
	int i;
	unsigned long l;
    int pwdlen = strlen(passwd);
    int saltlen = strlen(salt);

	/* Prepare tmp digest MD5(pw,salt,pw) */
	MD5_Init(&ctx);
	MD5_Update(&ctx, passwd, pwdlen);
	MD5_Update(&ctx, salt, saltlen);
	MD5_Update(&ctx, passwd, pwdlen);
	MD5_Final(tmpbuf, &ctx);

	/* start real digest */
	MD5_Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5_Update(&ctx, passwd, pwdlen);

	/* Then our magic string */
	MD5_Update(&ctx, magic, strlen(magic));

	/* Then the raw salt */
	MD5_Update(&ctx, salt, saltlen);

	/* then tmp digest above, repeated to match pwd size */
	for(i = pwdlen; i > 0; i -= MD5_DIGEST_LENGTH)
		MD5_Update(&ctx, tmpbuf, i>MD5_DIGEST_LENGTH ? MD5_DIGEST_LENGTH : i);

	/* Then something really weird... */
		/* NOTE: original code has a more complex alg
		   which was probably meant to be stronger,
		   but had some typos, so it's effectively this...
		*/
	tmpbuf[0] = '\0';
	for (i = pwdlen; i ; i >>= 1)
		if(i&1)
		    MD5_Update(&ctx, tmpbuf, 1);
		else
		    MD5_Update(&ctx, passwd, 1);

	/* Now make the output string */
	MD5_Final(tmpbuf,&ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		MD5_Init(&ctx);
		if(i & 1)
			MD5_Update(&ctx,passwd,pwdlen);
		else
			MD5_Update(&ctx,tmpbuf, MD5_DIGEST_LENGTH);

		if(i % 3)
			MD5_Update(&ctx,salt,saltlen);

		if(i % 7)
			MD5_Update(&ctx,passwd,pwdlen);

		if(i & 1)
			MD5_Update(&ctx,tmpbuf, MD5_DIGEST_LENGTH);
		else
			MD5_Update(&ctx,passwd,pwdlen);
		MD5_Final(tmpbuf,&ctx);
	}

	p = outbuf;
	l = (tmpbuf[ 0]<<16) | (tmpbuf[ 6]<<8) | tmpbuf[12]; to64(p,l,4); p += 4;
	l = (tmpbuf[ 1]<<16) | (tmpbuf[ 7]<<8) | tmpbuf[13]; to64(p,l,4); p += 4;
	l = (tmpbuf[ 2]<<16) | (tmpbuf[ 8]<<8) | tmpbuf[14]; to64(p,l,4); p += 4;
	l = (tmpbuf[ 3]<<16) | (tmpbuf[ 9]<<8) | tmpbuf[15]; to64(p,l,4); p += 4;
	l = (tmpbuf[ 4]<<16) | (tmpbuf[10]<<8) | tmpbuf[ 5]; to64(p,l,4); p += 4;
	l =                     tmpbuf[11]                 ; to64(p,l,2); p += 2;
	*p = '\0';

	/* Don't leave anything around in vm they could use. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	memset(&ctx, 0, sizeof(ctx));

	return 0;
}
