// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Extern function used to ensure cbindgen generates definitions for
//! every structure in the generated C header file.

#![allow(unsafe_code)]

use crate::*;

#[no_mangle]
extern "C" fn __export_structs(
    _: *mut IGVM_FIXED_HEADER,
    //    _: *mut IGVM_FIXED_HEADER_V2,
    _: *mut IGVM_VHS_VARIABLE_HEADER,
    _: *mut IGVM_VHS_SUPPORTED_PLATFORM,
    _: *mut IGVM_VHS_GUEST_POLICY,
    _: *mut SnpPolicy,
    _: *mut TdxPolicy,
    _: *mut IGVM_VHS_RELOCATABLE_REGION,
    _: *mut IGVM_VHS_PAGE_TABLE_RELOCATION,
    _: *mut IGVM_VHS_PARAMETER_AREA,
    _: *mut IGVM_VHS_PAGE_DATA,
    _: *mut IGVM_VHS_PARAMETER_INSERT,
    _: *mut IGVM_VHS_PARAMETER,
    _: *mut IGVM_VHS_VP_CONTEXT,
    _: *mut VbsVpContextHeader,
    _: *mut VbsVpContextRegister,
    _: *mut IGVM_VHS_REQUIRED_MEMORY,
    _: *mut IGVM_VHS_MEMORY_RANGE,
    _: *mut IGVM_VHS_MMIO_RANGES,
    _: *mut IGVM_VHS_SNP_ID_BLOCK_SIGNATURE,
    _: *mut IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
    _: *mut IGVM_VHS_SNP_ID_BLOCK,
    _: *mut IGVM_VHS_VBS_MEASUREMENT,
    _: *mut IGVM_VHS_MEMORY_MAP_ENTRY,
    _: *mut IGVM_VHS_ERROR_RANGE,
) {
}
