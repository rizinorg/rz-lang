// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2019 aronsky <aronsky@gmail.com>
// SPDX-FileCopyrightText: 2017-2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _PY_CORE_H
#define _PY_CORE_H

#include <rz_core.h>
#include "common.h"

void Rizin_plugin_core_free(RzCorePlugin *ap);

PyObject *Rizin_plugin_core(Rizin *self, PyObject *args);

#endif /* _PY_CORE_H */
