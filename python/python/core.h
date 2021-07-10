/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_CORE_H
#define _PY_CORE_H

#include <rz_core.h>
#include "common.h"

extern RzCore *core;

void Rizin_plugin_core_free(RzCorePlugin *ap);

PyObject *Rizin_plugin_core(Rizin *self, PyObject *args);

#endif /* _PY_CORE_H */
