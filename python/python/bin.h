// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2019 aronsky <aronsky@gmail.com>
// SPDX-FileCopyrightText: 2017-2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _PY_BIN_H
#define _PY_BIN_H

#include <rz_bin.h>
#include "common.h"

PyObject *init_pybinfile_module(void);

void Rizin_plugin_bin_free(RzBinPlugin *bp);

PyObject *Rizin_plugin_bin(Rizin *self, PyObject *args);

#endif /* _PY_BIN_H */
