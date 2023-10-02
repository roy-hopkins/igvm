#include <stdio.h>
#include "../include/igvm.h"
#include "dump.h"

static char *section_name[] = { "platform", "initialization", "directive" };

int main(void)
{
	uint8_t buf[16384];
	FILE *fp = fopen("/home/rhopkins/src/igvm/igvm_c/build/igvm.bin", "rb");
	long len = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);

	IgvmFile *igvm = NULL;
	if (igvmfile_new_from_binary(buf, len, &igvm) != IGVMAPI_OK) {
		printf("igvm is null\n");
		return -1;
	}

	for (long section = 0; section <= HEADER_SECTION_DIRECTIVE; ++section) {
		long count = igvmfile_header_count(igvm, (IgvmHeaderSection)section);
		printf("%s count = %ld\n", section_name[section], count);
		
		for (long i = 0; i < count; ++i) {
			IgvmVariableHeaderType typ = 0;
			if (igvmfile_get_header_type(igvm, section, i, &typ) == IGVMAPI_OK) {
				uint32_t buf_size = sizeof(buf);

				igvmfile_get_header(igvm, section, i, (uint8_t *)buf, &buf_size);
				igvm_dump_variable_header(typ, (uint8_t *)buf + sizeof(IGVM_VHS_VARIABLE_HEADER));

				buf_size = sizeof(buf);
				if (igvmfile_get_header_data(igvm, section, i, (uint8_t *)buf, &buf_size) != IGVMAPI_NO_DATA) {
					printf("Got %d bytes of file data:\n", buf_size);
					hexdump(buf, buf_size, 32, 0);
				}
			}
		}
	}

	igvmfile_free(igvm);
	
	return 0;
}
