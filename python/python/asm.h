// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2019 aronsky <aronsky@gmail.com>
// SPDX-FileCopyrightText: 2017-2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _PY_ASM_H
#define _PY_ASM_H

#include <rz_asm.h>
#include "common.h"

void py_export_asm_enum(PyObject *tp_dict);

void Rizin_plugin_asm_free(RzAsmPlugin *ap);

PyObject *Rizin_plugin_asm(Rizin *self, PyObject *args);

#endif /* _PY_ASM_H */
