/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka */

// Exporting the RZ_analysis_* enum constants
#include <rz_reg.h>
#include "analysis.h"
#include "core.h"

void py_export_analysis_enum(PyObject *tp_dict) {

#define PYENUM(name) {\
		PyObject *o = PyLong_FromLong(name); \
		if (o) { \
			PyDict_SetItemString(tp_dict, #name, o); \
			Py_DECREF(o); \
		}\
	}

	// RZ_ANALYSIS_OP_FAMILY_*
	PYENUM(RZ_ANALYSIS_OP_FAMILY_UNKNOWN);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_CPU);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_FPU);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_MMX);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_SSE);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_PRIV);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_CRYPTO);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_VIRT);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_IO);
	PYENUM(RZ_ANALYSIS_OP_FAMILY_LAST);
	// RZ_ANALYSIS_OP_TYPE_*
	PYENUM(RZ_ANALYSIS_OP_TYPE_COND);
	PYENUM(RZ_ANALYSIS_OP_TYPE_REP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_MEM);
	PYENUM(RZ_ANALYSIS_OP_TYPE_REG);
	PYENUM(RZ_ANALYSIS_OP_TYPE_IND);
	PYENUM(RZ_ANALYSIS_OP_TYPE_NULL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_JMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_RJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_IJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_IRJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_MJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UCJMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UCALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_RCALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ICALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_IRCALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CCALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UCCALL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_RET);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CRET);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ILL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UNK);
	PYENUM(RZ_ANALYSIS_OP_TYPE_NOP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_MOV);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CMOV);
	PYENUM(RZ_ANALYSIS_OP_TYPE_TRAP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SWI);
	PYENUM(RZ_ANALYSIS_OP_TYPE_UPUSH);
	PYENUM(RZ_ANALYSIS_OP_TYPE_PUSH);
	PYENUM(RZ_ANALYSIS_OP_TYPE_POP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ACMP);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ADD);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SUB);
	PYENUM(RZ_ANALYSIS_OP_TYPE_IO);
	PYENUM(RZ_ANALYSIS_OP_TYPE_MUL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_DIV);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SHR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SHL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SAL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SAR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_OR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_AND);
	PYENUM(RZ_ANALYSIS_OP_TYPE_XOR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_NOR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_NOT);
	PYENUM(RZ_ANALYSIS_OP_TYPE_STORE);
	PYENUM(RZ_ANALYSIS_OP_TYPE_LOAD);
	PYENUM(RZ_ANALYSIS_OP_TYPE_LEA);
	PYENUM(RZ_ANALYSIS_OP_TYPE_LEAVE);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ROR);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ROL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_XCHG);
	PYENUM(RZ_ANALYSIS_OP_TYPE_MOD);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SWITCH);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CASE);
	PYENUM(RZ_ANALYSIS_OP_TYPE_LENGTH);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CAST);
	PYENUM(RZ_ANALYSIS_OP_TYPE_NEW);
	PYENUM(RZ_ANALYSIS_OP_TYPE_ABS);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CPL);
	PYENUM(RZ_ANALYSIS_OP_TYPE_CRYPTO);
	PYENUM(RZ_ANALYSIS_OP_TYPE_SYNC);
	// RZ_ANALYSIS_STACK
	PYENUM(RZ_ANALYSIS_STACK_NULL);
	PYENUM(RZ_ANALYSIS_STACK_NOP);
	PYENUM(RZ_ANALYSIS_STACK_INC);
	PYENUM(RZ_ANALYSIS_STACK_GET);
	PYENUM(RZ_ANALYSIS_STACK_SET);
	PYENUM(RZ_ANALYSIS_STACK_RESET);
	PYENUM(RZ_ANALYSIS_STACK_ALIGN);
#undef E
}

#define READ_REG(dict, reg) \
	if (dict && PyDict_Check(dict)) { \
		reg->name = getS (dict, "name"); \
		reg->type = getI (dict, "type"); \
		reg->size = getI (dict, "size"); \
		reg->offset = getI (dict, "offset"); \
		reg->packed_size = getI (dict, "packed_size"); \
		reg->is_float = getB (dict, "is_float"); \
		reg->flags = getS (dict, "flags"); \
		reg->index = getI (dict, "index"); \
		reg->arena = getI (dict, "arena"); \
	}

#define READ_VAL(dict, val, tmpreg) \
	if (dict && PyDict_Check(dict)) { \
		val->absolute = getI (dict, "absolute"); \
		val->memref = getI (dict, "memref"); \
		val->base = getI (dict, "base"); \
		val->delta = getI (dict, "delta"); \
		val->imm = getI (dict, "imm"); \
		val->mul = getI (dict, "mul"); \
		/* val->seg = getI (dict, "seg"); */ \
		tmpreg = getO (dict, "reg"); \
		READ_REG(tmpreg, val->reg) \
		tmpreg = getO (dict, "regdelta"); \
		READ_REG(tmpreg, val->regdelta) \
	}

static void *py_set_reg_profile_cb = NULL;
static void *py_analysis_cb = NULL;
static void *py_archinfo_cb = NULL;

static bool py_set_reg_profile(RzAnalysis *a) {
	const char *profstr = "";
	if (py_set_reg_profile_cb) {
		PyObject *result = PyObject_CallObject (py_set_reg_profile_cb, NULL);
		if (result) {
			profstr = PyUnicode_AsUTF8 (result);
			return rz_reg_set_profile_string (a->reg, profstr);
		} else {
			eprintf ("Unknown type returned. String was expected.\n");
			PyErr_Print();
		}
	}
	return -1;
}

static int py_analysis(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	PyObject *tmpreg = NULL;
	int size = 0;
	int seize = -1;
	int i = 0;
	if (!op) return -1;
	if (py_analysis_cb) {
		memset(op, 0, sizeof (RzAnalysisOp));
		// anal(addr, buf) - returns size + dictionary (structure) for RzAnalysisOp
		Py_buffer pybuf = {
			.buf = (void *) buf, // Warning: const is lost when casting
			.len = len,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1,
		};
		PyObject *memview = PyMemoryView_FromBuffer (&pybuf);
		PyObject *arglist = Py_BuildValue ("(NK)", memview, addr);
		PyObject *result = PyEval_CallObject (py_analysis_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *len = PyList_GetItem (result, 0);
			PyObject *dict = PyList_GetItem (result, 1);
			if (dict && PyDict_Check (dict)) {
				seize = PyNumber_AsSsize_t (len, NULL);
				op->type = getI (dict, "type");
				op->cycles = getI (dict, "cycles");
				op->size = seize;
				op->addr = getI (dict, "addr");
				op->delay = getI (dict, "delay");
				op->jump = getI (dict, "jump");
				op->fail = getI (dict, "fail");
				op->stackop = getI (dict, "stackop");
				op->stackptr = getI (dict, "stackptr");
				op->ptr = getI (dict, "ptr");
				op->eob = getB (dict, "eob");
				// Loading 'src' and 'dst' values
				// SRC is is a list of 3 elements
				PyObject *tmpsrc = getO (dict, "src");
				if (tmpsrc && PyList_Check (tmpsrc)) {
					for (i = 0; i < 3; i++) {
						PyObject *tmplst = PyList_GetItem (tmpsrc, i);
						// Read value and underlying regs
						READ_VAL (tmplst, op->src[i], tmpreg)
					}
				}
				PyObject *tmpdst = getO (dict, "dst");
				// Read value and underlying regs
				READ_VAL (tmpdst, op->dst, tmpreg)
				// Loading 'var' value if presented
				rz_strbuf_set (&op->esil, getS (dict, "esil"));
				op->mnemonic = rz_str_new (getS (dict, "mnemonic"));
				// TODO: Add opex support here
				Py_DECREF (dict);
			}
			Py_DECREF (result);
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
			PyErr_Print ();
		}
	}
	op->size = size = seize;
	return seize;
}

static int py_archinfo(RzAnalysis *a, int query) {
	if (py_archinfo_cb) {
		PyObject *arglist = Py_BuildValue ("(i)", query);
		PyObject *result = PyObject_CallObject (py_archinfo_cb, arglist);
		if (result) {
			return PyLong_AsLong (result); /* Python only returns long... */
		}
		eprintf ("Unknown type returned. Int was expected.\n");
	}
	return -1;
}

void Rizin_plugin_analysis_free(RzAnalysisPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->arch);
	free ((char *)ap->license);
	free ((char *)ap->desc);
	free (ap);
}

PyObject *Rizin_plugin_analysis(Rizin* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyObject_CallObject (args, arglist);

	RzAnalysisPlugin *ap = RZ_NEW0 (RzAnalysisPlugin);
	ap->name = getS (o,"name");
	ap->arch = getS (o, "arch");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ap->bits = getI (o, "bits");
	ap->esil = getI (o, "esil");
	ptr = getF (o, "op");
	if (ptr) {
		Py_INCREF (ptr);
		py_analysis_cb = ptr;
		ap->op = py_analysis;
	}
	ptr = getF (o, "set_reg_profile");
	if (ptr) {
		Py_INCREF (ptr);
		py_set_reg_profile_cb = ptr;
		ap->set_reg_profile = py_set_reg_profile;
	}
	ptr = getF (o, "archinfo");
	if (ptr) {
		Py_INCREF (ptr);
		py_archinfo_cb = ptr;
		ap->archinfo = py_archinfo;
	}
	Py_DECREF (o);

	RzLibStruct lp = {};
	lp.type = RZ_LIB_TYPE_ANALYSIS;
	lp.data = ap;
	lp.free = (void (*)(void *data))Rizin_plugin_analysis_free;
	rz_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
