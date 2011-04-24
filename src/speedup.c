/**************************************************************************
 **************************************************************************
 * passlib "speedup" C python extension - provides C routines of
 * various key derivation primitives
 **************************************************************************
 **************************************************************************/

/**************************************************************************
 * includes
 **************************************************************************/
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static PyObject *UnknownDigestError;

/**************************************************************************
 * pbkdf2
 **************************************************************************/

#define PBKDF2_HMAC_DOCSTRING "pbkdf2_hmac(pwd, msg, rounds, keylen, digest)"

static char *pbkdf2_hmac_kwds[] = {"password", "salt", "rounds", "keylen", "digest", NULL};

static PyObject *
pbkdf2_hmac(PyObject *self, PyObject *args, PyObject *kwds)
{
    const char *digest_name;
    uint8_t *pwdbuf, *saltbuf, *keybuf, *inbuf, *workbuf, *outbuf;
    Py_ssize_t pwdlen, saltlen, keylen, rklen;
    unsigned long rounds, blocks, block, round;
    const EVP_MD *digest_ref;
    HMAC_CTX hmac_ctx;
    unsigned int digest_size, i;
    PyObject *result = NULL;

    /* parse python args*/
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#kns", pbkdf2_hmac_kwds,
                                     &pwdbuf, &pwdlen, &saltbuf, &saltlen,
                                     &rounds, &keylen, &digest_name))
        return NULL;

/*    printf("parms: %d %d %d %d %s\n", pwdlen, saltlen, rounds, keylen, digest_name); */

    /* locate digest in openssl*/
    digest_ref = EVP_get_digestbyname(digest_name);
    if(!digest_ref){
        PyErr_Format(UnknownDigestError, "unknown digest: %s", digest_name);
        return NULL;
    }

    /* initialize hmac */
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init_ex(&hmac_ctx, (void *)pwdbuf, pwdlen, digest_ref, NULL);

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

    /* alloc working buffer & output buffer */
    inbuf = PyMem_Malloc(saltlen+4);
    if(!inbuf)
        return PyErr_NoMemory();

    workbuf = PyMem_Malloc(digest_size);
    if(!workbuf){
        PyMem_Free(inbuf);
        return PyErr_NoMemory();
    }

    keybuf = PyMem_Malloc(rklen);
    if(!keybuf){
        PyMem_Free(inbuf);
        PyMem_Free(workbuf);
        return PyErr_NoMemory();
    }

    /* begin pbkdf2 main loop */
    Py_BEGIN_ALLOW_THREADS;
    memcpy(inbuf, saltbuf, saltlen);
    outbuf = keybuf; /* points to part of keybuf we're building next block in */
    for(block=1; block<=blocks; ++block){
        /* do hmac(password, salt + block) -> workbuf & outbuf */
        inbuf[saltlen] = (uint8_t)(block>>24);
        inbuf[saltlen+1] = (uint8_t)(block>>16);
        inbuf[saltlen+2] = (uint8_t)(block>>8);
        inbuf[saltlen+3] = (uint8_t)(block);

        HMAC_Init_ex(&hmac_ctx, NULL, 0, NULL, NULL);
        HMAC_Update(&hmac_ctx, inbuf, saltlen+4);
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

    /* cleanup buffers, return result */
    HMAC_CTX_cleanup(&hmac_ctx);
    memset(inbuf, 0, saltlen+4);
    memset(workbuf, 0, digest_size);
    memset(keybuf, 0, rklen);
    PyMem_Free(inbuf);
    PyMem_Free(workbuf);
    PyMem_Free(keybuf);
    return result;
}

/**************************************************************************
 * module init
 **************************************************************************/

static PyMethodDef SpeedupMethods[] = {
    {"pbkdf2_hmac", (PyCFunction) pbkdf2_hmac, METH_VARARGS|METH_KEYWORDS, PBKDF2_HMAC_DOCSTRING },
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
