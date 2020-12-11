/* rizin - LGPL - Copyright 2016-2019 - pancake */

#include "core.h"

RzCore *core = NULL;

/* TODO : move into a struct stored in the plugin struct */
static void *py_core_call_cb = NULL;

static int py_core_call(void *user, const char *str) {
	if (py_core_call_cb) {
		PyObject *arglist = Py_BuildValue ("(z)", str);
		PyObject *result = PyEval_CallObject (py_core_call_cb, arglist);
		const char * str_res = NULL;
		if (result) {
			if (PyLong_Check (result)) {
				return (int)PyLong_AsLong (result);
			} else if (PyLong_Check (result)) {
				return (int)PyLong_AsLong (result);
			} else if (PyUnicode_Check (result)) {
				int n = PyUnicode_KIND (result);
				switch (n) {
				case 1:
					str_res = (char*)PyUnicode_1BYTE_DATA (result);
					break;
				case 2:
					str_res = (char*)PyUnicode_2BYTE_DATA (result);
					break;
				case 4:
				default:
					str_res = (char*)PyUnicode_4BYTE_DATA (result);
					break;
				}
			} else
			if (PyUnicode_Check (result)) {
				str_res = PyBytes_AS_STRING (result);
			}
			if (str_res) {
				rz_cons_print (str_res);
				return 1;
			}
		}
	}
	return 0;
}

void Rizin_plugin_core_free(RzCorePlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->license);
	free ((char *)ap->desc);
	free (ap);
}

PyObject *Rizin_plugin_core(Rizin* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RzCorePlugin *ap = RZ_NEW0 (RzCorePlugin);
	ap->name = getS (o, "name");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ptr = getF (o, "call");
	if (ptr) {
		Py_INCREF (ptr);
		py_core_call_cb = ptr;
		ap->call = py_core_call;
	}
	Py_DECREF (o);

	RzLibStruct lp = {};
	lp.type = RZ_LIB_TYPE_CORE;
	lp.data = ap;
	lp.free = (void (*)(void *data))Rizin_plugin_core_free;
	rz_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
