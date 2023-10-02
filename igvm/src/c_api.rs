// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
#![allow(unsafe_code)]

use crate::IgvmFile;
use igvm_defs::IgvmVariableHeaderType;
use open_enum::open_enum;

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmApiError {
    IGVMAPI_OK,
    IGVMAPI_INVALID_PARAMETER,
    IGVMAPI_BUFFER_TOO_SMALL,
    IGVMAPI_NO_DATA,
    IGVMAPI_INVALID_FILE,
    IGVMAPI_MEMORY_ERROR,
}

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmHeaderSection {
    HEADER_SECTION_PLATFORM,
    HEADER_SECTION_INITIALIZATION,
    HEADER_SECTION_DIRECTIVE,
}

fn copy_header_data(src: &Vec<u8>, dst: *mut u8, dst_len: *mut u32) -> IgvmApiError {
    // Safety: Using pointer from C
    unsafe {
        if src.len() > *dst_len as usize {
            *dst_len = src.len() as u32;
            return IgvmApiError::IGVMAPI_BUFFER_TOO_SMALL;
        }

        core::ptr::copy(src.as_ptr(), dst, src.len());
        *dst_len = src.len() as u32;
    }
    IgvmApiError::IGVMAPI_OK
}

/// Parse a binary array containing an IGVM file.
/// The contents of the file are validated and, if valid, a handle is returned
/// to represent the file. This handle must be freed with a call to
/// igvmfile_free().
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_new_from_binary(
    data: *const u8,
    len: u32,
    igvm: *mut *mut IgvmFile,
) -> IgvmApiError {
    // Safety: data array must be at least as large as len
    let file_data = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let result = IgvmFile::new_from_binary(file_data, None);

    if let Ok(file) = result {
        // Safety: Dereferences the C-provided pointer
        unsafe {
            *igvm = Box::into_raw(Box::new(file));
        }
        IgvmApiError::IGVMAPI_OK
    } else {
        IgvmApiError::IGVMAPI_MEMORY_ERROR
    }
}

/// Free a handle that was created with this library.
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_free(igvm: *mut IgvmFile) {
    // Safety: Using structure provided as a raw pointer from C
    unsafe {
        drop(Box::from_raw(igvm));
    };
}

/// Get the count of headers for a particular section in the parsed IGVM
/// file.
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_header_count(
    igvm: *mut IgvmFile,
    section: IgvmHeaderSection,
) -> u32 {
    // Safety: Using pointer from C
    unsafe {
        let len = match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => (*igvm).platform_headers.len(),
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                (*igvm).initialization_headers.len()
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => (*igvm).directive_headers.len(),
            _ => 0,
        };
        len as u32
    }
}

/// Get the header type for the entry with the given index for a particular
/// section in the parsed IGVM file.
///
/// This function can be called to determine which IGVM_VHS_* structure will
/// be returned by a call to igvmfile_get_header().
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_get_header_type(
    igvm: *mut IgvmFile,
    section: IgvmHeaderSection,
    index: u32,
    typ: *mut IgvmVariableHeaderType,
) -> IgvmApiError {
    // Safety: Using pointer from C
    unsafe {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
                if let Some(header) = (*igvm).platform_headers.get_mut(index as usize) {
                    *typ = header.header_type();
                    IgvmApiError::IGVMAPI_OK
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER
                }
            }
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                if let Some(header) = (*igvm).initialization_headers.get_mut(index as usize) {
                    *typ = header.header_type();
                    IgvmApiError::IGVMAPI_OK
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER
                }
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = (*igvm).directive_headers.get_mut(index as usize) {
                    *typ = header.header_type();
                    IgvmApiError::IGVMAPI_OK
                } else {
                    IgvmApiError::IGVMAPI_INVALID_PARAMETER
                }
            }
            _ => IgvmApiError::IGVMAPI_INVALID_PARAMETER,
        }
    }
}

/// Get the header data in binary form for the entry with the given index
/// for a particular section in the parsed IGVM file.
///
/// The caller must allocate a buffer that is large enough to hold the
/// entire header. The header type can be determined by calling
/// igvmfile_get_header_type.
///
/// On entry, buf_len must be set to the actual size of the buffer pointed
/// to by buf. On return, buf_len is updated to the actual length.
///
/// If the input buffer is too small then this function returns
/// IGVMAPI_BUFFER_TOO_SMALL and buf_len is set to the required size of
/// the buffer.
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_get_header(
    igvm: *mut IgvmFile,
    section: IgvmHeaderSection,
    index: u32,
    buf: *mut u8,
    buf_len: *mut u32,
) -> IgvmApiError {
    let mut result = IgvmApiError::IGVMAPI_OK;

    // Safety: Using pointer from C
    unsafe {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
                if let Some(header) = (*igvm).platform_headers.get_mut(index as usize) {
                    let mut header_binary = Vec::<u8>::new();
                    if header.write_binary_header(&mut header_binary).is_err() {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    } else {
                        result = copy_header_data(&header_binary, buf, buf_len);
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
                if let Some(header) = (*igvm).initialization_headers.get_mut(index as usize) {
                    let mut header_binary = Vec::<u8>::new();
                    if header.write_binary_header(&mut header_binary).is_err() {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    } else {
                        result = copy_header_data(&header_binary, buf, buf_len);
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = (*igvm).directive_headers.get_mut(index as usize) {
                    let mut header_binary = Vec::<u8>::new();
                    if header
                        .write_binary_header(0, &mut header_binary, &mut Vec::<u8>::new())
                        .is_err()
                    {
                        result = IgvmApiError::IGVMAPI_INVALID_FILE;
                    } else {
                        result = copy_header_data(&header_binary, buf, buf_len);
                    }
                } else {
                    result = IgvmApiError::IGVMAPI_INVALID_PARAMETER;
                }
            }
            _ => (),
        }
    }
    result
}

/// Get the associated file data in binary form for the entry with the given
/// index for a particular section in the parsed IGVM file. This function is
/// only relevant for headers that refer to a section in the 'file data'
/// portion of the IGVM file.
///
/// If called for an entry that does not contain file data then this function
/// returns IGVMAPI_NO_DATA.
///
/// The caller must allocate a buffer that is large enough to hold the
/// entire data. The size can be determined by examining the related header
/// or by calling this function with a buf_len of 0. On return, buf_len
/// will contain the required size.
///
/// On entry, buf_len must be set to the actual size of the buffer pointed
/// to by buf. On return, buf_len is updated to the actual length.
///
/// If the input buffer is too small then this function returns
/// IGVMAPI_BUFFER_TOO_SMALL and buf_len is set to the required size of
/// the buffer.
///
/// # Safety
/// This function is exported and designed to be called as a C API. As such
/// it works with raw pointers and is inherently unsafe due to this.
#[no_mangle]
pub unsafe extern "C" fn igvmfile_get_header_data(
    igvm: *mut IgvmFile,
    section: IgvmHeaderSection,
    index: u32,
    buf: *mut u8,
    buf_len: *mut u32,
) -> IgvmApiError {
    // Safety: Using pointer from C
    unsafe {
        match section {
            IgvmHeaderSection::HEADER_SECTION_PLATFORM => {}
            IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {}
            IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
                if let Some(header) = (*igvm).directive_headers.get_mut(index as usize) {
                    let mut file_data = Vec::<u8>::new();
                    let _result =
                        header.write_binary_header(0, &mut Vec::<u8>::new(), &mut file_data);

                    if file_data.len() > *buf_len as usize {
                        return IgvmApiError::IGVMAPI_BUFFER_TOO_SMALL;
                    }

                    core::ptr::copy(file_data.as_ptr(), buf, file_data.len());
                    *buf_len = file_data.len() as u32;
                    return IgvmApiError::IGVMAPI_OK;
                }
            }
            _ => (),
        }
    }
    IgvmApiError::IGVMAPI_NO_DATA
}
