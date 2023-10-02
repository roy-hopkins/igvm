# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Roy Hopkins <rhopkins@suse.de>

ifdef RELEASE
TARGET_PATH="../target_c/release"
else
TARGET_PATH="../target_c/debug"
endif

CARGO=CARGO_TARGET_DIR=../target_c cargo

FEATURES = "igvm-c"

RUST_SOURCE := ../igvm/src/c_api.rs ../igvm/src/lib.rs ../igvm_defs/src/c_api.rs ../igvm_defs/src/lib.rs

all: include/igvm.h ${TARGET_PATH}/igvm_c_sample

${TARGET_PATH}/libigvm.a:
	${CARGO} build --features ${FEATURES} --manifest-path=../igvm/Cargo.toml

${TARGET_PATH}/libigvm_defs.rlib:
	${CARGO} build --features ${FEATURES} --manifest-path=../igvm_defs/Cargo.toml

include/igvm.h: ${RUST_SOURCE}
	./scripts/gen_igvm_h.sh ${TARGET_PATH}

${TARGET_PATH}/igvm_c_sample: include/igvm.h sample/igvm_c_sample.c sample/dump.c ${TARGET_PATH}/libigvm.a
	gcc -g3 -O0 -I . -L ${TARGET_PATH} -o $@ $^ -ligvm 

clean:
	${CARGO} clean --manifest-path=../igvm/Cargo.toml
	${CARGO} clean --manifest-path=../igvm_defs/Cargo.toml
	rm -f include/igvm.h ${TARGET_PATH}/_igvm_defs.h ${TARGET_PATH}/_igvm.h ${TARGET_PATH}/igvm_c_sample