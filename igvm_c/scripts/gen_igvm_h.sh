set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ -z "$1" ]; then
    echo "Build directory not provided"
    exit 1
fi

cbindgen -l c ../igvm -o "$1/_igvm.h"
cbindgen -l c ../igvm_defs -o "$1/_igvm_defs.h"

sed -i 's\U32<LittleEndian>\uint32_t\g' "$1/_igvm_defs.h"
sed -i 's\U64<LittleEndian>\uint64_t\g' "$1/_igvm_defs.h"

cat ${SCRIPT_DIR}/igvm_tpl_top.h "$1/_igvm_defs.h" $1/_igvm.h ${SCRIPT_DIR}/igvm_tpl_bot.h > ${SCRIPT_DIR}/../include/igvm.h
