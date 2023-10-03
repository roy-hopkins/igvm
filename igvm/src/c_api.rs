// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
#![allow(unsafe_code)]

use std::{
    collections::BTreeMap,
    ptr::null,
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex,
    },
};

use crate::{Error, IgvmFile};
use open_enum::open_enum;

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum IgvmApiError {
    IGVMAPI_OK = 0,
    IGVMAPI_INVALID_PARAMETER = -1,
    IGVMAPI_NO_DATA = -2,
    IGVMAPI_INVALID_FILE = -3,
    IGVMAPI_INVALID_HANDLE = -4,
    IGVMAPI_NO_PLATFORM_HEADERS = -5,
    IGVMAPI_FILE_DATA_SECTION_TOO_LARGE = -6,
    IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE = -7,
    IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE = -8,
    IGVMAPI_INVALID_BINARY_PLATFORM_HEADER = -9,
    IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER = -10,
    IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER = -11,
    IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION = -12,
    IGVMAPI_INVALID_PARAMETER_AREA_INDEX = -13,
    IGVMAPI_INVALID_PLATFORM_TYPE = -14,
    IGVMAPI_NO_FREE_COMPATIBILITY_MASKS = -15,
    IGVMAPI_INVALID_FIXED_HEADER = -16,
    IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION = -17,
    IGVMAPI_INVALID_CHECKSUM = -18,
    IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS = -19,
    IGVMAPI_RELOCATION_REGIONS_OVERLAP = -20,
    IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION = -21,
    IGVMAPI_NO_MATCHING_VP_CONTEXT = -22,
    IGVMAPI_PLATFORM_ARCH_UNSUPPORTED = -23,
    IGVMAPI_INVALID_HEADER_ARCH = -24,
    IGVMAPI_UNSUPPORTED_PAGE_SIZE = -25,
    IGVMAPI_INVALID_FIXED_HEADER_ARCH = -26,
    IGVMAPI_MERGE_REVISION = -27,
}

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmHeaderSection {
    HEADER_SECTION_PLATFORM,
    HEADER_SECTION_INITIALIZATION,
    HEADER_SECTION_DIRECTIVE,
}

fn translate_error(error: Error) -> IgvmApiError {
    match error {
        Error::NoPlatformHeaders => IgvmApiError::IGVMAPI_NO_PLATFORM_HEADERS,
        Error::FileDataSectionTooLarge => IgvmApiError::IGVMAPI_FILE_DATA_SECTION_TOO_LARGE,
        Error::VariableHeaderSectionTooLarge => {
            IgvmApiError::IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE
        }
        Error::TotalFileSizeTooLarge => IgvmApiError::IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE,
        Error::InvalidBinaryPlatformHeader(_) => {
            IgvmApiError::IGVMAPI_INVALID_BINARY_PLATFORM_HEADER
        }
        Error::InvalidBinaryInitializationHeader(_) => {
            IgvmApiError::IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER
        }
        Error::InvalidBinaryDirectiveHeader(_) => {
            IgvmApiError::IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER
        }
        Error::MultiplePlatformHeadersWithSameIsolation => {
            IgvmApiError::IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION
        }
        Error::InvalidParameterAreaIndex => IgvmApiError::IGVMAPI_INVALID_PARAMETER_AREA_INDEX,
        Error::InvalidPlatformType => IgvmApiError::IGVMAPI_INVALID_PLATFORM_TYPE,
        Error::NoFreeCompatibilityMasks => IgvmApiError::IGVMAPI_NO_FREE_COMPATIBILITY_MASKS,
        Error::InvalidFixedHeader => IgvmApiError::IGVMAPI_INVALID_FIXED_HEADER,
        Error::InvalidBinaryVariableHeaderSection => {
            IgvmApiError::IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION
        }
        Error::InvalidChecksum {
            expected: _,
            header_value: _,
        } => IgvmApiError::IGVMAPI_INVALID_CHECKSUM,
        Error::MultiplePageTableRelocationHeaders => {
            IgvmApiError::IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS
        }
        Error::RelocationRegionsOverlap => IgvmApiError::IGVMAPI_RELOCATION_REGIONS_OVERLAP,
        Error::ParameterInsertInsidePageTableRegion => {
            IgvmApiError::IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION
        }
        Error::NoMatchingVpContext => IgvmApiError::IGVMAPI_NO_MATCHING_VP_CONTEXT,
        Error::PlatformArchUnsupported {
            arch: _,
            platform: _,
        } => IgvmApiError::IGVMAPI_PLATFORM_ARCH_UNSUPPORTED,
        Error::InvalidHeaderArch {
            arch: _,
            header_type: _,
        } => IgvmApiError::IGVMAPI_INVALID_HEADER_ARCH,
        Error::UnsupportedPageSize(_) => IgvmApiError::IGVMAPI_UNSUPPORTED_PAGE_SIZE,
        Error::InvalidFixedHeaderArch(_) => IgvmApiError::IGVMAPI_INVALID_FIXED_HEADER_ARCH,
        Error::MergeRevision => IgvmApiError::IGVMAPI_MERGE_REVISION,
    }
}

type IgvmResult = i64;
type IgvmHandle = i64;

struct IgvmFileInstance {
    file: IgvmFile,
    buffers: BTreeMap<IgvmHandle, Vec<u8>>,
}

static mut IGVM_HANDLES: Mutex<BTreeMap<IgvmHandle, IgvmFileInstance>> =
    Mutex::new(BTreeMap::new());
static mut IGVM_HANDLE_FACTORY: AtomicI64 = AtomicI64::new(1);

fn igvm_create(file: IgvmFile) -> IgvmHandle {
    // SAFETY: The fetching and update of these global variables are safe because
    // they are using atomic types and protected using a Mutex.
    unsafe {
        let handle = IGVM_HANDLE_FACTORY.fetch_add(1, Ordering::Relaxed);
        let mut m = IGVM_HANDLES.lock().unwrap();
        m.insert(
            handle,
            IgvmFileInstance {
                file,
                buffers: BTreeMap::new(),
            },
        );
        handle
    }
}

/// Returns a pointer to the array of bytes in a buffer.
///
/// # Safety
///
/// The caller must ensure that the buffer handle remains valid for the duration
/// of accessing the data pointed to by the raw pointer returned by this
/// function. This requires that the `buffer_handle` is not freed with a call to
/// [`igvm_free_buffer()`] and that the `igvm_handle` is not freed with a call
/// to [`igvm_free()`].
///
/// Invalid handles are handled within this function and result in a return
/// value of `null()`. The caller must check the result before using the array.
#[no_mangle]
pub unsafe extern "C" fn igvm_get_buffer(
    igvm_handle: IgvmHandle,
    buffer_handle: IgvmHandle,
) -> *const u8 {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get(&igvm_handle);
    if let Some(igvm) = igvm_handle {
        if let Some(buffer) = igvm.buffers.get(&buffer_handle) {
            return buffer.as_ptr();
        }
    }
    null()
}

/// Returns the size of a buffer.
///
/// If either handle is invalid or if there is an error then the return value is
/// less then zero and signals an error defined in [`IgvmApiError`].
#[no_mangle]
pub extern "C" fn igvm_get_buffer_size(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> u32 {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get(&igvm_handle);
    if let Some(igvm) = igvm_handle {
        if let Some(buffer) = igvm.buffers.get(&buffer_handle) {
            return buffer.len() as u32;
        }
    }
    0
}

/// Frees a buffer.
///
/// If either handle is invalid then the function has no effect.
#[no_mangle]
pub extern "C" fn igvm_free_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let mut lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get_mut(&igvm_handle);
    if let Some(igvm) = igvm_handle {
        let _ = igvm.buffers.remove(&buffer_handle);
    }
}

/// Parse a binary array containing an IGVM file. The contents of the file are
/// validated and, if valid, a handle is returned to represent the file. This
/// handle must be freed with a call to igvm_free().
///
/// If any error occurs then an [`IgvmApiError`] value is returned instead of a
/// handle. Handles are always greater than zero so a return value greater than
/// zero indicates a valid handle has been returned.
///
/// # Safety
///
/// The function assumes that there are at least `len` valid bytes of memory
/// starting at the address pointed to by `data`. If this is violated then this
/// will result in undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn igvm_new_from_binary(data: *const u8, len: u32) -> IgvmResult {
    // Safety: data array must be at least as large as len
    let file_data = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let result = IgvmFile::new_from_binary(file_data, None);

    match result {
        Ok(file) => igvm_create(file),
        Err(e) => translate_error(e).0,
    }
}

/// Free a handle that was created with a prevoius call to
/// [`igvm_new_from_binary()`].
#[no_mangle]
pub extern "C" fn igvm_free(handle: IgvmHandle) {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    unsafe {
        let _ = IGVM_HANDLES.lock().unwrap().remove(&handle);
    }
}

/// Get the count of headers for a particular section in a previously parsed
/// IGVM file.
///
/// If any error occurs then an [`IgvmApiError`] value is returned instead of
/// the count. Errors can be detected by checking if the returned value is less
/// than zero.
#[no_mangle]
pub extern "C" fn igvm_header_count(handle: IgvmHandle, section: IgvmHeaderSection) -> IgvmResult {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get(&handle);
    if let Some(igvm) = igvm_handle {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
                igvm.file.platform_headers.len() as IgvmResult
            }
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                igvm.file.initialization_headers.len() as IgvmResult
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                igvm.file.directive_headers.len() as IgvmResult
            }
            _ => 0,
        }
    } else {
        IgvmApiError::IGVMAPI_INVALID_HANDLE.0
    }
}

/// Get the header type for the entry with the given index for a particular
/// section in a previously parsed IGVM file.
///
/// If any error occurs then an [`IgvmApiError`] value is returned instead of
/// the header type. Errors can be detected by checking if the returned value is
/// less than zero.
#[no_mangle]
pub extern "C" fn igvm_get_header_type(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> IgvmResult {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get(&handle);

    // Safety: Using pointer from C
    if let Some(igvm) = igvm_handle {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
                if let Some(header) = igvm.file.platform_headers.get(index as usize) {
                    header.header_type().0 as IgvmResult
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER.0
                }
            }
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                if let Some(header) = igvm.file.initialization_headers.get(index as usize) {
                    header.header_type().0 as IgvmResult
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER.0
                }
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = igvm.file.directive_headers.get(index as usize) {
                    header.header_type().0 as IgvmResult
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER.0
                }
            }
            _ => IgvmApiError::IGVMAPI_INVALID_PARAMETER.0,
        }
    } else {
        IgvmApiError::IGVMAPI_INVALID_FILE.0
    }
}

/// Prepare a buffer containing the header data in binary form for the entry
/// with the given index for a particular section in a previously parsed IGVM
/// file.
///
/// The buffer containing the data is returned via a handle from this function.
/// The handle can be used to access a raw pointer to the data and to query its
/// size. The buffer handle remains valid until it is closed with a call to
/// [`igvm_free_buffer()`] or the parsed file handle is closed with a call to
/// [`igvm_free()`].
///
/// If any error occurs then an [`IgvmApiError`] value is returned instead of a
/// handle. Handles are always greater than zero so a return value greater than
/// zero indicates a valid handle has been returned.
#[no_mangle]
pub extern "C" fn igvm_get_header(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> IgvmResult {
    let mut result = IgvmApiError::IGVMAPI_OK;
    let mut header_binary = Vec::<u8>::new();

    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let mut lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get_mut(&handle);

    if let Some(igvm) = igvm_handle {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
                if let Some(header) = igvm.file.platform_headers.get(index as usize) {
                    if header.write_binary_header(&mut header_binary).is_err() {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                if let Some(header) = igvm.file.initialization_headers.get(index as usize) {
                    if header.write_binary_header(&mut header_binary).is_err() {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = igvm.file.directive_headers.get(index as usize) {
                    if header
                        .write_binary_header(0, &mut header_binary, &mut Vec::<u8>::new())
                        .is_err()
                    {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            _ => {
                result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
            }
        }
        if result == IgvmApiError::IGVMAPI_OK {
            // SAFETY: The fetching and update of the global variable is safe because
            // it is using an Atomic type.
            let handle = unsafe { IGVM_HANDLE_FACTORY.fetch_add(1, Ordering::Relaxed) };
            igvm.buffers.insert(handle, header_binary);
            handle
        } else {
            result.0
        }
    } else {
        IgvmApiError::IGVMAPI_INVALID_HANDLE.0
    }
}

/// Prepare a buffer containing the associated file data in binary form for the
/// entry with the given index for a particular section in a previously parsed
/// IGVM file.
///
/// The buffer containing the data is returned via a handle from this function.
/// The handle can be used to access a raw pointer to the data and to query its
/// size. The buffer handle remains valid until it is closed with a call to
/// [`igvm_free_buffer()`] or the parsed file handle is closed with a call to
/// [`igvm_free()`].
///
/// If any error occurs then an [`IgvmApiError`] value is returned instead of a
/// handle. Handles are always greater than zero so a return value greater than
/// zero indicates a valid handle has been returned.
#[no_mangle]
pub extern "C" fn igvm_get_header_data(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> IgvmResult {
    // SAFETY: Safe access to the IGVM_HANDLES map through a mutex.
    let mut lock = unsafe { IGVM_HANDLES.lock().unwrap() };
    let igvm_handle = lock.get_mut(&handle);

    if let Some(igvm) = igvm_handle {
        match section {
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = igvm.file.directive_headers.get(index as usize) {
                    let mut file_data = Vec::<u8>::new();
                    let _result =
                        header.write_binary_header(0, &mut Vec::<u8>::new(), &mut file_data);
                    if !file_data.is_empty() {
                        // SAFETY: The fetching and update of the global variable is safe because
                        // it is using an Atomic type.
                        let handle = unsafe { IGVM_HANDLE_FACTORY.fetch_add(1, Ordering::Relaxed) };
                        igvm.buffers.insert(handle, file_data);
                        handle
                    } else {
                        IgvmApiError::IGVMAPI_NO_DATA.0
                    }
                } else {
                    IgvmApiError::IGVMAPI_NO_DATA.0
                }
            }
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => IgvmApiError::IGVMAPI_NO_DATA.0,
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => IgvmApiError::IGVMAPI_NO_DATA.0,
            _ => IgvmApiError::IGVMAPI_NO_DATA.0,
        }
    } else {
        IgvmApiError::IGVMAPI_INVALID_HANDLE.0
    }
}
