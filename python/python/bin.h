/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_BIN_H
#define _PY_BIN_H

#include <rz_bin.h>
#include "common.h"

PyObject *init_pybinfile_module(void);

void Rizin_plugin_bin_free(RzBinPlugin *bp);

PyObject *Rizin_plugin_bin(Rizin* self, PyObject *args);

#endif /* _PY_BIN_H */
