#include <Python.h>
#include <cyfer/cipher.h>
#include <string.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

staticforward PyTypeObject StreamCipherType;

typedef struct {
	PyObject_HEAD;
	CYFER_STREAM_CIPHER_CTX *ctx;
	size_t keylen;
} StreamCipherObject;

#define BLOCK_CREATE(x, len) x = alloca(len)
#define BLOCK_CREATE_ZERO(x, len) { x = alloca(len); memset(x, 0, len); }
#define BLOCK_CREATE_FROM(x, len, img, imglen) \
	{ x = alloca(len); memset(x, 0, len); memcpy(x, img, (len > imglen) ? imglen : len); }

static PyObject *supported_scipher(PyObject *self, PyObject *args)
{
	int i;
	CYFER_StreamCipher_t *CYFER_StreamCiphers;
	PyObject *list, *val;

	if (!PyArg_ParseTuple(args, ":Supported")) return NULL;

	CYFER_StreamCiphers = CYFER_StreamCipher_Get_Supported();

	list = PyList_New(0);
	for (i = 0; CYFER_StreamCiphers[i].name; i++) {
		val = Py_BuildValue("s", CYFER_StreamCiphers[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static PyObject *keysize(PyObject *self, PyObject *args)
{
	char *name;
	size_t klen, mklen;
	int type = CYFER_CIPHER_NONE;
	PyObject *tuple, *first, *second;

	if (!PyArg_ParseTuple(args, "s:KeySize", &name)) return NULL;
	if (name) type = CYFER_StreamCipher_Select(name, &klen, &mklen);
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

static int init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	StreamCipherObject *cipher;
	char *name;
	unsigned char *k, *keydata;
	int type = CYFER_CIPHER_NONE;
	size_t klen, k_len, mklen;

	cipher = (StreamCipherObject *) self;

	if (!PyArg_ParseTuple(args, "ss#:StreamCipher", &name, &k, &k_len)) return -1;
	if (name) type = CYFER_StreamCipher_Select(name, &klen, &mklen);
	if (type == CYFER_CIPHER_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported stream cipher");
		return -1;
	}

	/* allow for variable-length keys */
	if (k_len < klen) {
		klen = (mklen > k_len) ? mklen : k_len;
	}

	cipher->keylen = klen;

	BLOCK_CREATE_FROM(keydata, klen, k, k_len);
	cipher->ctx = CYFER_StreamCipher_Init(type, keydata, klen);
	if (!cipher->ctx) {
		Py_DECREF(cipher);
		PyErr_SetString(PyExc_ValueError, "out of memory");
		return -1;
	}
	
	return 0;
}

static PyObject *new(PyTypeObject *objtype, PyObject *args, PyObject *kwargs)
{
	StreamCipherObject *obj = PyObject_New(StreamCipherObject, &StreamCipherType);

	obj->ctx = NULL;
	obj->keylen = 0;

	return (PyObject *) obj;
}

static PyObject *scipher_encrypt(StreamCipherObject *self, PyObject *args)
{
	unsigned char *s, *out;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Encrypt", &s, &s_len)) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized");
		return NULL;
	}

	BLOCK_CREATE(out, s_len);
	CYFER_StreamCipher_Encrypt(self->ctx, s, out, s_len);
	return Py_BuildValue("s#", out, s_len);
}

static PyObject *scipher_decrypt(StreamCipherObject *self, PyObject *args)
{
	unsigned char *s, *out;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Decrypt", &s, &s_len)) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized");
		return NULL;
	}

	BLOCK_CREATE(out, s_len);
	CYFER_StreamCipher_Decrypt(self->ctx, s, out, s_len);
	return Py_BuildValue("s#", out, s_len);
}

static void scipher_dealloc(PyObject *self)
{
	StreamCipherObject *cipher;
	
	cipher = (StreamCipherObject *) self;
	if (cipher->ctx) {
		CYFER_StreamCipher_Finish(cipher->ctx);
	}
	PyObject_Del(self);
}

static PyMethodDef StreamCipherTypeMethods[] = {
	{ "Encrypt", (PyCFunction) scipher_encrypt, METH_VARARGS, "Encrypt block of data of any size." },
	{ "Decrypt", (PyCFunction) scipher_decrypt, METH_VARARGS, "Decrypt block of data of any size." },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject StreamCipherType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"streamcipher.StreamCipher",
	sizeof(StreamCipherObject),
	0,
	scipher_dealloc,
};

static PyMethodDef CipherMethods[] = {
	{ "Supported", supported_scipher, METH_VARARGS, "List supported stream ciphers." },
	{ "KeySize", keysize, METH_VARARGS, "Return minimum and maximum key lengths." },
    {NULL, NULL, 0, NULL}
};

void initstreamcipher(void)
{
	PyObject *module;

	StreamCipherType.ob_type = &PyType_Type;
	StreamCipherType.tp_methods = StreamCipherTypeMethods;
	StreamCipherType.tp_flags = Py_TPFLAGS_DEFAULT;
	StreamCipherType.tp_new = new;
	StreamCipherType.tp_init = init;

	if (PyType_Ready(&StreamCipherType) < 0) return;

	module = Py_InitModule("cyfer.streamcipher", CipherMethods);

	PyModule_AddObject(module, "StreamCipher", (PyObject *)&StreamCipherType);

}

