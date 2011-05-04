/* exports for md5crypt.c */

#ifndef PASSLIB_MD5CRYPT_H
#define PASSLIB_MD5CRYPT_H 1

int md5_crypt(char *outbuf, char *passwd, char *salt, char *magic);

#endif /* PASSLIB_MD5CRYPT_H */
