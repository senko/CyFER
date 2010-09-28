#include <Python.h>
#include <cyfer/cipher.h>
#include <string.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

staticforward PyTypeObject BlockCipherType;

typedef struct {
	PyObject_HEAD;
	CYFER_BLOCK_CIPHER_CTX *ctx;
	size_t keylen;
	size_t length;
} BlockCipherObject;

#define BLOCK_CREATE(x, len) x = alloca(len)
#define BLOCK_CREATE_ZERO(x, len) { x = alloca(len); memset(x, 0, len); }
#define BLOCK_CREATE_FROM(x, len, img, imglen) \
	{ x = alloca(len); memset(x, 0, len); memcpy(x, img, (len > imglen) ? imglen : len); }

static PyObject *supported_bcipher(PyObject *self, PyObject *args)
{
	int i;
	CYFER_BlockCipher_t *CYFER_BlockCiphers;
	PyObject *list, *val;

	if (!PyArg_ParseTuple(args, ":Supported")) return NULL;

	CYFER_BlockCiphers = CYFER_BlockCipher_Get_Supported();

	list = PyList_New(0);
	for (i = 0; CYFER_BlockCiphers[i].name; i++) {
		val = Py_BuildValue("s", CYFER_BlockCiphers[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static PyObject *size(PyObject *self, PyObject *args)
{
	char *name;
	size_t len, klen;
	int type = CYFER_CIPHER_NONE;

	if (!PyArg_ParseTuple(args, "s:Size", &name)) return NULL;
	if (name) type = CYFER_BlockCipher_Select(name, &klen, NULL, &len);
	if (type == CYFER_CIPHER_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported block cipher");
		return NULL;
	}

	return Py_BuildValue("l", len);
}

static PyObject *keysize(PyObject *self, PyObject *args)
{
	char *name;
	size_t len, klen, mklen;
	int type = CYFER_CIPHER_NONE;
	PyObject *tuple, *first, *second;

	if (!PyArg_ParseTuple(args, "s:KeySize", &name)) return NULL;
	if (name) type = CYFER_BlockCipher_Select(name, &klen, &mklen, &len);
	if (type == CYFER_CIPHER_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported block cipher");
		return NULL;
	}

	tuple = PyTuple_New(2);
	first = Py_BuildValue("l", mklen);
	second = Py_BuildValue("l", klen);
	PyTuple_SetItem(tuple, 0, first);
	PyTuple_SetItem(tuple, 1, second);

	return tuple;
}

static PyObject *supported_bcipher_modes(PyObject *self, PyObject *args)
{
	int i;
	CYFER_BlockMode_t *CYFER_BlockModes;
	PyObject *list, *val;

	if (!PyArg_ParseTuple(args, ":SupportedModes")) return NULL;

	CYFER_BlockModes = CYFER_BlockCipher_Get_SupportedModes();

	list = PyList_New(0);
	for (i = 0; CYFER_BlockModes[i].name; i++) {
		val = Py_BuildValue("s", CYFER_BlockModes[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static PyObject *mode_size(PyObject *self, PyObject *args)
{
	char *name;
	size_t len;
	int type = CYFER_MODE_NONE;

	if (!PyArg_ParseTuple(args, "s:ModeSize", &name)) return NULL;
	if (name) type = CYFER_BlockCipher_SelectMode(name, &len);
	if (type == CYFER_MODE_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported block cipher mode");
		return NULL;
	}

	return Py_BuildValue("l", len);
}

static int init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	BlockCipherObject *cipher;
	char *name, *mode;
    unsigned char *k, *keydata, *iv, *ivdata;
	int type = CYFER_CIPHER_NONE;
	int mtype = CYFER_MODE_NONE;
	size_t klen, len, k_len, iv_len, mlen, mklen;

	cipher = (BlockCipherObject *) self;

	if (!PyArg_ParseTuple(args, "ss#sz#:BlockCipher", &name, &k, &k_len, &mode, &iv, &iv_len)) return -1;
	if (name) type = CYFER_BlockCipher_Select(name, &klen, &mklen, &len);
	if (type == CYFER_CIPHER_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported block cipher");
		return -1;
	}
	if (mode) mtype = CYFER_BlockCipher_SelectMode(name, &mlen);
	if (type == CYFER_MODE_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported block cipher mode");
		return -1;
	}

	if (mlen) len = mlen;

	/* allow for variable-length keys */
	if (k_len < klen) {
		klen = (mklen > k_len) ? mklen : k_len;
	}

	cipher->keylen = klen;
	cipher->length = len;

	BLOCK_CREATE_FROM(keydata, klen, k, k_len);
	ivdata = NULL;
	if (iv_len) BLOCK_CREATE_FROM(ivdata, len, iv, iv_len);

	cipher->ctx = CYFER_BlockCipher_Init(type, keydata, klen, mtype, ivdata);
	if (!cipher->ctx) {
		Py_DECREF(cipher);
		PyErr_SetString(PyExc_ValueError, "out of memory");
		return -1;
	}
	return 0;
}

static PyObject *new(PyTypeObject *objtype, PyObject *args, PyObject *kwargs)
{
	BlockCipherObject *obj = PyObject_New(BlockCipherObject, &BlockCipherType);

	obj->ctx = NULL;
	obj->keylen = 0;
	obj->length = 0;

	return (PyObject *) obj;
}


static PyObject *bcipher_encrypt(BlockCipherObject *self, PyObject *args)
{
	unsigned char *s, *in, *out;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Encrypt", &s, &s_len)) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized");
		return NULL;
	}

	BLOCK_CREATE_FROM(in, self->length, s, s_len);
	BLOCK_CREATE(out, self->length);
	CYFER_BlockCipher_Encrypt(self->ctx, in, out);
	return Py_BuildValue("s#", out, self->length);
}

static PyObject *bcipher_decrypt(BlockCipherObject *self, PyObject *args)
{
	unsigned char *s, *in, *out;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Decrypt", &s, &s_len)) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized");
		return NULL;
	}

	BLOCK_CREATE_FROM(in, self->length, s, s_len);
	BLOCK_CREATE(out, self->length);
	CYFER_BlockCipher_Decrypt(self->ctx, in, out);
	return Py_BuildValue("s#", out, self->length);
}

static void bcipher_dealloc(PyObject *self)
{
	BlockCipherObject *cipher;
	
	cipher = (BlockCipherObject *) self;

	if (cipher->ctx) {
		CYFER_BlockCipher_Finish(cipher->ctx);
	}
	PyObject_Del(self);
}

static PyMethodDef BlockCipherTypeMethods[] = {
	{ "Encrypt", (PyCFunction) bcipher_encrypt, METH_VARARGS, "Encrypt block of data." },
	{ "Decrypt", (PyCFunction) bcipher_decrypt, METH_VARARGS, "Decrypt block of data." },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject BlockCipherType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"blockcipher.BlockCipher",
	sizeof(BlockCipherObject),
	0,
	bcipher_dealloc,
};

static PyMethodDef CipherMethods[] = {
	{ "Supported", supported_bcipher, METH_VARARGS, "List supported block ciphers." },
	{ "KeySize", keysize, METH_VARARGS, "Return minimum and maximum key lengths." },
	{ "Size", size, METH_VARARGS, "Return block length for given algorithm." },
	{ "SupportedModes", supported_bcipher_modes, METH_VARARGS, "List supported block cipher modes." },
	{ "ModeSize", mode_size, METH_VARARGS, "Return block lengths for given mode." },
    {NULL, NULL, 0, NULL}
};

void initblockcipher(void)
{
	PyObject *module;

	BlockCipherType.ob_type = &PyType_Type;
	BlockCipherType.tp_methods = BlockCipherTypeMethods;
	BlockCipherType.tp_flags = Py_TPFLAGS_DEFAULT;
	BlockCipherType.tp_new = new;
	BlockCipherType.tp_init = init;

	if (PyType_Ready(&BlockCipherType) < 0) return;

	module = Py_InitModule("cyfer.blockcipher", CipherMethods);

	PyModule_AddObject(module, "BlockCipher", (PyObject *)&BlockCipherType);

}


