# IGVM C API

This folder contains a Makefile project that is used to build a C compatible API
from the igvm crate. The C API provides functions that can be used to parse and
validate a binary IGVM file and provides access to the fixed header and all of
the variable headers and associated file data.

The C API is generated directly from the rust source files. This includes the
definitions of the structures and enums in igvm_defs. This ensures that the C
API does not need to be manually updated inline with any changes to the rust
definitions.

## Dependencies
The C API header files are generated using the `cbindgen` tool. This tool needs
to be installed before the API can be built. This can be achieved using:

```bash
cargo install --force cbindgen
```

In addition, the C sample requires `gcc` to be installed.

## Building
The C API can be built with:

```bash
make -f Makefile
```

This builds both the igvm and igvm_defs rust projects enabling the `igvm-c`
feature. In order to keep the C API build separated from the normal build, the
cargo target directory is set to `target_c`.

The following output files are generated for the build:

`target_c/[debug | release]/libigvm.a`: Static library that includes the
exported C functions.

`igvm_c/include/igvm_defs.h`: Definitions of the IGVM structures.
`igvm_c/include/igvm.h`: Declarations of the C API functions.

The file `igvm.h` includes `igvm_defs.h` so only this file needs to be included
in C projects source files.

