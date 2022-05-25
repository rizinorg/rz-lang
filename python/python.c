// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "python/common.h"
#include "python/core.h"
#include "python/io.h"
#include "python/asm.h"
#include "python/analysis.h"
#include "python/bin.h"

#define PLUGIN_NAME rz_lang_plugin_python

RzCore *core;

typedef struct {
	const char *type;
	PyObject *(*handler)(Rizin *, PyObject *);
} RzPlugins;

RzPlugins plugins[] = {
	{ "asm", &Rizin_plugin_asm },
	{ "analysis", &Rizin_plugin_analysis },
	{ "bin", &Rizin_plugin_bin },
	{ "io", &Rizin_plugin_io },
	{ NULL }
};

static int run(RzLang *lang, const char *code, int len) {
	core = (RzCore *)lang->user;
	PyRun_SimpleString(code);
	return true;
}

static int slurp_python(const char *file) {
	FILE *fd = rz_sys_fopen(file, "r");
	if (fd) {
		PyRun_SimpleFile(fd, file);
		fclose(fd);
		return true;
	}
	return false;
}

static int run_file(struct rz_lang_t *lang, const char *file) {
	return slurp_python(file);
}

static char *py_nullstr = "";

static void Rizin_dealloc(Rizin *self) {
	Py_XDECREF(self->first);
	Py_XDECREF(self->last);
	// self->ob_type->tp_free((PyObject*)self);
}

static PyObject *Rizin_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	Rizin *self = (Rizin *)type->tp_alloc(type, 0);
	if (self) {
		self->first = PyUnicode_FromString("");
		if (!self->first) {
			Py_DECREF(self);
			return NULL;
		}
		self->last = PyUnicode_FromString("");
		if (!self->last) {
			Py_DECREF(self);
			return NULL;
		}
		self->number = 0;
	}
	return (PyObject *)self;
}

static PyObject *Rizin_plugin(Rizin *self, PyObject *args) {
	char *type = NULL;
	void *cb = NULL;
	int i;

	if (!PyArg_ParseTuple(args, "sO", &type, &cb)) {
		return Py_False;
	}
	if (!PyCallable_Check(cb)) {
		PyErr_SetString(PyExc_TypeError, "second parameter must be callable");
		return Py_False;
	}
	for (i = 0; plugins[i].type; i++) {
		if (!strcmp(type, plugins[i].type)) {
			return plugins[i].handler(self, cb);
		}
	}
	eprintf("TODO: rzlang.plugin does not supports '%s' plugins yet\n", type);
	return Py_False;
}

static PyObject *Rizin_cmd(Rizin *self, PyObject *args) {
	char *str, *cmd = NULL;
	if (!PyArg_ParseTuple(args, "s", &cmd)) {
		return NULL;
	}
	str = rz_core_cmd_str(core, cmd);
	return PyUnicode_FromString(str ? str : py_nullstr);
}

static int Rizin_init(Rizin *self, PyObject *args, PyObject *kwds) {
	static char *kwlist[] = { "first", "last", "number", NULL };
	PyObject *first = NULL, *last = NULL, *tmp;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOi",
		    (char **)kwlist, &first, &last, &self->number)) {
		return -1;
	}
	if (first) {
		tmp = self->first;
		Py_INCREF(first);
		self->first = first;
		Py_XDECREF(tmp);
	}
	if (last) {
		tmp = self->last;
		Py_INCREF(last);
		self->last = last;
		Py_XDECREF(tmp);
	}
	return 0;
}

static PyMemberDef Rizin_members[] = {
	{ "first", T_OBJECT_EX, offsetof(Rizin, first), 0, "first name" },
	{ "last", T_OBJECT_EX, offsetof(Rizin, last), 0, "last name" },
	{ "number", T_INT, offsetof(Rizin, number), 0, "noddy number" },
	{ NULL } /* Sentinel */
};

static PyMethodDef Rizin_methods[] = {
	{ "cmd", (PyCFunction)Rizin_cmd, METH_VARARGS,
		"Executes a rizin command and returns a string" },
	{ "plugin", (PyCFunction)Rizin_plugin, METH_VARARGS,
		"Register plugins in rizin" },
	{ NULL } /* Sentinel */
};

static PyTypeObject RizinType = {
	PyVarObject_HEAD_INIT(NULL, 0) "rizin.RizinInternal", /*tp_name*/
	sizeof(Rizin), /*tp_basicsize*/
	0, /*tp_itemsize*/
	(destructor)Rizin_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	0, /*tp_getattr*/
	0, /*tp_setattr*/
	0, /*tp_compare*/
	0, /*tp_repr*/
	0, /*tp_as_number*/
	0, /*tp_as_sequence*/
	0, /*tp_as_mapping*/
	0, /*tp_hash */
	0, /*tp_call*/
	0, /*tp_str*/
	0, /*tp_getattro*/
	0, /*tp_setattro*/
	0, /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	"Rizin objects", /* tp_doc */
	0, /* tp_traverse */
	0, /* tp_clear */
	0, /* tp_richcompare */
	0, /* tp_weaklistoffset */
	0, /* tp_iter */
	0, /* tp_iternext */
	Rizin_methods, /* tp_methods */
	Rizin_members, /* tp_members */
	0, /* tp_getset */
	0, /* tp_base */
	0, /* tp_dict */
	0, /* tp_descr_get */
	0, /* tp_descr_set */
	0, /* tp_dictoffset */
	(initproc)Rizin_init, /* tp_init */
	0, /* tp_alloc */
	Rizin_new, /* tp_new */
};

/*
SEE
static PyMethodDef EmbMethods[] = {
    {"numargs", emb_numargs, METH_VARARGS,
     "Return the number of arguments received by the process."},
    {NULL, NULL, 0, NULL}
};
*/

static PyModuleDef EmbModule = {
	PyModuleDef_HEAD_INIT,
	"rzlang",
	NULL, -1, Rizin_methods,
	NULL, NULL, NULL, NULL
};

static PyObject *init_rizin_module(void) {
	if (PyType_Ready(&RizinType) < 0) {
		return NULL;
	}
	RizinType.tp_dict = PyDict_New();
	py_export_analysis_enum(RizinType.tp_dict);
	py_export_asm_enum(RizinType.tp_dict);
	PyObject *m = PyModule_Create(&EmbModule);
	if (!m) {
		eprintf("Cannot create python3 rz module\n");
		return NULL;
	}
	Py_INCREF(&RizinType);
	PyModule_AddObject(m, "RZ", (PyObject *)&RizinType);
	return m;
}

/* -init- */

static int init(RzLang *user);
static bool setup(RzLang *user);

static int prompt(void *user) {
	return !PyRun_SimpleString(
		"rz = None\n"
		"try:\n"
		"	import rzlang\n"
		"	import rzpipe\n"
		"	rz = rzpipe.open()\n"
		"	import IPython\n"
		"	IPython.embed()\n"
		"except:\n"
		"	raise Exception(\"Cannot find IPython\")\n");
}

static bool setup(RzLang *lang) {
	RzListIter *iter;
	RzLangDef *def;
	char cmd[128];
	// Segfault if already initialized ?
	PyRun_SimpleString(
		"try:\n"
		"	from rz.rz_core import RzCore\n"
		"except:\n"
		"	pass\n");
	PyRun_SimpleString("import rzpipe");
	core = lang->user;
	rz_list_foreach (lang->defs, iter, def) {
		if (!def->type || !def->name) {
			continue;
		}
		if (!strcmp(def->type, "int"))
			snprintf(cmd, sizeof(cmd), "%s=%d", def->name, (int)(size_t)def->value);
		else if (!strcmp(def->type, "string"))
			snprintf(cmd, sizeof(cmd), "%s=\"%s\"", def->name, (char *)def->value);
		else
			snprintf(cmd, sizeof(cmd),
				"try:\n"
				"	%s=%s.ncast(%p)\n"
				"except:\n"
				"	pass",
				def->name, def->type, def->value);
		PyRun_SimpleString(cmd);
	}
	return true;
}

static int init(RzLang *lang) {
	if (lang) {
		core = lang->user;
	}
	// DO NOT INITIALIZE MODULE IF ALREADY INITIALIZED
	if (Py_IsInitialized()) {
		return 0;
	}
	PyImport_AppendInittab("rzlang", init_rizin_module);
	PyImport_AppendInittab("binfile", init_pybinfile_module);
	Py_Initialize();
	// Add a current directory to the PYTHONPATH
	PyObject *sys = PyImport_ImportModule("sys");
	PyObject *path = PyObject_GetAttrString(sys, "path");
	PyList_Append(path, PyUnicode_FromString("."));
	return true;
}

static int fini(void *user) {
#if (PY_MAJOR_VERSION >= 3) && (PY_MINOR_VERSION >= 6)
	return Py_FinalizeEx() ? false : true;
#else
	Py_Finalize();
	return true;
#endif
}

static const char *help =
	"  print rz.cmd(\"p8 10\");\n";

RzLangPlugin PLUGIN_NAME = {
	.name = "python",
	.alias = "python",
	.ext = "py",
	.desc = "Python language extension",
	.license = "LGPL",
	.init = &init,
	.setup = &setup,
	.fini = (void *)&fini,
	.help = &help,
	.prompt = (void *)&prompt,
	.run = &run,
	.run_file = &run_file,
};

#if !CORELIB
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_LANG,
	.data = &PLUGIN_NAME,
	.version = RZ_VERSION
};
#endif
