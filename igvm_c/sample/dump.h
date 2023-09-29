// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

#ifndef DUMP_H
#define DUMP_H

#include "include/igvm.h"

void hexdump(const void* data, size_t size, int columns, int address);
void igvm_dump_variable_header(IgvmVariableHeaderType typ, const uint8_t *header);

#endif
