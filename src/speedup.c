/**************************************************************************
 **************************************************************************
 * passlib "speedup" C python extension - provides C routines of
 * various key derivation primitives
 *
 * this code assumes C99 uint32 and uint64 will both be available.
 **************************************************************************
 **************************************************************************/

/**************************************************************************
 * includes
 **************************************************************************/
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "des.h"

static PyObject *UnknownDigestError;

/**************************************************************************
 * note: the following tries to figure out which PyArgs_ParseTuple & PyUnicode_FromFormat
 *  unit will grab 32 & 64 bit ints, and set macros accordingly
 **************************************************************************/

    /* try to find PyArg_ParseTuple char corresponding to int32_t */
#if SIZEOF_LONG == 4
#   define PA_INT32 "l"
#   define PA_UINT32 "k"
#   define PF_INT32 "ld"
#   define PF_UINT32 "lu"

#elif SIZEOF_INT == 4
#   define PA_INT32 "i"
#   define PA_UINT32 "I"
#   define PF_INT32 "d"
#   define PF_UINT32 "u"

#else
#   error "passlib can't find a 32-bit integer for PyArgs"
#endif /* int32 search */

/* try to find PyArg_ParseTuple char corresponding to int64_t */
#if SIZEOF_LONG == 8
#   define PA_INT64 "l"
#   define PA_UINT64 "k"
#   define PF_INT64 "ld"
#   define PF_UINT64 "lu"

#elif SIZEOF_LONG_LONG == 8
#   define PA_INT64 "L"
#   define PA_UINT64 "K"
#   define PF_INT32 "lld"
#   define PF_UINT32 "llu"

#else
#   error "passlib can't find a 64-bit integer for PyArgs"
#endif /* int64 search */

/**************************************************************************
 * pbkdf2
 *
 * NOTE: rfc2898 places no restrictions on salt size, rounds, or keylen
 * (outside of the fact that keylen <= (2**32-1)*digest_size)
 *
 * for passlib's use, rounds & keylen will not exceed 2**31-1 any time soon,
 * this internal backend uses int32_t for rounds & keylen,
 * simplifying parsing of the values, as well as ensuring the keylen limit is never reached.
 * if the need arises, this could be revisited.
 **************************************************************************/

#define PBKDF2_HMAC_DOCSTRING "pbkdf2_hmac(password, salt, rounds, keylen, digest)"

static char *pbkdf2_hmac_kwds[] = {"password", "salt", "rounds", "keylen", "digest", NULL};

static PyObject *
pbkdf2_hmac_py(PyObject *self, PyObject *args, PyObject *kwds)
{
    const char *digest_name;
    uint8_t *pwdbuf, /* RO ptr to password */
            *saltbuf,/* RO ptr to salt string */
            *keybuf, /* final key - cleared after call */
            *workbuf,/* tmp buffer used for round ops - cleared after call */
            *outbuf; /* cursor to in-progress block of keybuf */
    Py_ssize_t pwdlen, /* length of pwdbuf */
            saltlen; /* length of saltbuf */
    int32_t rounds,  /* number of rounds requested */
            blocks,  /* number of blocks required */
            block,   /* current block */
            round,   /* current round */
            keylen,  /* length of requested key */
            rklen;   /* length of keybuf - keylen rounded up to
                        multiple of digest_size */
    const EVP_MD *digest_ref; /* ref to ssl message digest */
    HMAC_CTX hmac_ctx; /* ssl hmac context */
    int digest_size, /* size of digest chunk */
            i;       /* general purpose iterator */
    PyObject *result = NULL; /* pointer to final result */

    /* parse python args*/
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "s#s#" PA_INT32 PA_INT32 "s",
                                     pbkdf2_hmac_kwds,
                                     &pwdbuf, &pwdlen, &saltbuf, &saltlen,
                                     &rounds, &keylen, &digest_name))
        return NULL;
    if(rounds < 1){
        PyErr_Format(PyExc_ValueError, "rounds must be >= 1: %" PF_INT32, rounds);
        return NULL;
    }
    if(keylen < 0){
        PyErr_Format(PyExc_ValueError, "keylen must be >= 0: %" PF_INT32, keylen);
        return NULL;
    }

    /* locate digest in openssl*/
    digest_ref = EVP_get_digestbyname(digest_name);
    if(!digest_ref){
        PyErr_Format(UnknownDigestError, "unknown digest: %s", digest_name);
        return NULL;
    }

    /* figure out block, keybuf size, etc */
    digest_size = EVP_MD_size(digest_ref);
    blocks = keylen/digest_size;
    if(keylen % digest_size){
        /* make rklen > keylen so we have room in keybuf to store last block */
        blocks += 1;
        rklen = blocks * digest_size;
    }else{
        rklen = keylen;
    }
        /* NOTE: since keylen is int32_t, we can trust blocks < 2**32-1,
          the rfc specified max for blocks */

/*    printf("r=%" PF_INT32 " k=%" PF_INT32 " d=%d b=%" PF_INT32 " rk=%" PF_INT32 "\n", rounds, keylen, digest_size, blocks, rklen); */

    /* alloc working buffer & output buffer */
    workbuf = PyMem_Malloc(digest_size);
    if(!workbuf)
        return PyErr_NoMemory();

    keybuf = PyMem_Malloc(rklen);
    if(!keybuf){
        PyMem_Free(workbuf);
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS;

    /* initialize hmac */
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init_ex(&hmac_ctx, (void *)pwdbuf, pwdlen, digest_ref, NULL);

    /* begin pbkdf2 main loop */
    outbuf = keybuf; /* points to part of keybuf we're building next block in */
    for(block=1; block<=blocks; ++block){
        /* do hmac(password, salt + block) -> workbuf & outbuf */
        HMAC_Init_ex(&hmac_ctx, NULL, 0, NULL, NULL);
        HMAC_Update(&hmac_ctx, saltbuf, saltlen);
        workbuf[0] = (uint8_t)(block>>24);
        workbuf[1] = (uint8_t)(block>>16);
        workbuf[2] = (uint8_t)(block>>8);
        workbuf[3] = (uint8_t)(block);
        HMAC_Update(&hmac_ctx, workbuf, 4);
        HMAC_Final(&hmac_ctx, workbuf, NULL);
        memcpy(outbuf, workbuf, digest_size);

        /* do rounds loop */
        for(round=1; round<rounds; ++round){
            /* do hmac(password, workbuf) -> workbuf */
            HMAC_Init_ex(&hmac_ctx, NULL, 0, NULL, NULL);
            HMAC_Update(&hmac_ctx, workbuf, digest_size);
            HMAC_Final(&hmac_ctx, workbuf, NULL);

            /* xor workbuf into outbuf */
            for(i=0; i<digest_size; ++i)
                outbuf[i] ^= workbuf[i];
        }

        /* advance outbuf to next block in keybuf */
        outbuf += digest_size;
    }

    Py_END_ALLOW_THREADS;

    /* render python return value */
    result = Py_BuildValue("s#", keybuf, keylen);
        /* NOTE: if sets error, we run cleanup anyways */

    /* cleanup buffers, return result */
    HMAC_CTX_cleanup(&hmac_ctx);
    memset(workbuf, 0, digest_size);
    memset(keybuf, 0, rklen);
    PyMem_Free(workbuf);
    PyMem_Free(keybuf);
    return result;
}

/**************************************************************************
 * des
 **************************************************************************/

#define DES_CIPHER_BLOCK_DOCSTRING "des_cipher_block(key, input, salt, rounds)"

static char *des_cipher_block_kwds[] = {"key", "input", "salt", "rounds", NULL};

static PyObject *
des_cipher_block_py(PyObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *result;
    uint8_t outbuf[8];
    uint8_t *keybuf, *inputbuf;
    Py_ssize_t keylen, inputlen;
    long salt, rounds;
    int rc;

    /* parse python args*/
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "s#s#ll",
                                     des_cipher_block_kwds,
                                     &keybuf, &keylen, &inputbuf, &inputlen,
                                     &salt, &rounds))
        return NULL;
    /* NOTE: this ignores all but first 8 bytes of key & input */
    if(keylen < 8){
        PyErr_Format(PyExc_ValueError, "key must be at least 8 bytes: %zd", keylen);
        return NULL;
    }
    if(inputlen < 8){
        PyErr_Format(PyExc_ValueError, "input must be least 8 bytes: %zd", inputlen);
        return NULL;
    }
    if(rounds < 1){
        PyErr_Format(PyExc_ValueError, "rounds must be >= 1: %ld", rounds);
        return NULL;
    }

/*    printf("des_cipher_block_py: key=%lu input=%lu salt=%ld rounds=%ld\n",
           (uint64_t) *keybuf, (uint64_t) *inputbuf, salt, rounds); */

    /* init des tables */
    des_init_tables();

    /* create context, set the key, encode block */
    Py_BEGIN_ALLOW_THREADS;
    rc = des_cipher_block(keybuf, inputbuf, outbuf, salt, rounds);
    Py_END_ALLOW_THREADS;

    /* cleanup & return */
    if(rc){
        /* NOTE: only time this is known to happen is w/ invalid rounds,
           which have already been checked, so something unknown is wrong */
        PyErr_SetString(PyExc_RuntimeError, "unexpected error in des_cipher");
        result = NULL;
    }else{
        result = Py_BuildValue("s#", outbuf, 8);
    }
    memset(outbuf, 0, 8);
    return result;
}

/**************************************************************************
 * module init
 **************************************************************************/

static PyMethodDef SpeedupMethods[] = {
    {"pbkdf2_hmac", (PyCFunction) pbkdf2_hmac_py,
            METH_VARARGS|METH_KEYWORDS, PBKDF2_HMAC_DOCSTRING },
    {"des_cipher_block", (PyCFunction) des_cipher_block_py,
            METH_VARARGS|METH_KEYWORDS, DES_CIPHER_BLOCK_DOCSTRING },
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_speedup(void)
{
    PyObject *mod = Py_InitModule("passlib.utils._speedup", SpeedupMethods);
    if(!mod)
        return;

    UnknownDigestError = PyErr_NewException(
                    "passlib.utils._speedup.UnknownDigestError",
                    PyExc_ValueError, NULL);
    Py_INCREF(UnknownDigestError);
    PyModule_AddObject(mod, "UnknownDigestError", UnknownDigestError);
}

/**************************************************************************
 * eof
 **************************************************************************/
