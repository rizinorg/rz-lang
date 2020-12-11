/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_ASM_H
#define _PY_ASM_H

#include <rz_asm.h>
#include "common.h"

void py_export_asm_enum(PyObject *tp_dict);

void Rizin_plugin_asm_free(RzAsmPlugin *ap);

PyObject *Rizin_plugin_asm(Rizin* self, PyObject *args);

#endif /* _PY_ASM_H */
