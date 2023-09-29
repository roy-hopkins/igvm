// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

#include "include/igvm.h"
#include <stdio.h>

void hexdump(const void* data, size_t size, int columns, int address) {
    int rows = (size + (columns - 1)) / columns;
    int row;
    int col;

    for (row = 0; row < rows; ++row) {
        printf("| %08X | ", address + row * columns);
        for (col = 0; col < columns; ++col) {
            size_t index = row * columns + col;
            if (index >= size)
                printf("   ");
            else
                printf("%02X ", ((unsigned char *)data)[index]);
        }
        printf("| ");
        for (col = 0; col < columns; ++col) {
            size_t index = row * columns + col;
            if (index >= size)
                printf(" ");
            else {
                char c = ((char *)data)[index];
                if ((c >= 32) && (c < 127))
                    printf("%c", c);
                else
                    printf(".");
            }
        }
        printf(" |\n");
    }
}

static char *igvm_type_to_text(uint32_t type)
{
	switch (type & 0x7fffffff) {
	case IGVM_VHT_SUPPORTED_PLATFORM:
		return "IGVM_VHT_SUPPORTED_PLATFORM";
	case IGVM_VHT_GUEST_POLICY:
		return "IGVM_VHT_GUEST_POLICY";
	case IGVM_VHT_RELOCATABLE_REGION:
		return "IGVM_VHT_RELOCATABLE_REGION";
	case IGVM_VHT_PAGE_TABLE_RELOCATION_REGION:
		return "IGVM_VHT_PAGE_TABLE_RELOCATION_REGION";
	case IGVM_VHT_PARAMETER_AREA:
		return "IGVM_VHT_PARAMETER_AREA";
	case IGVM_VHT_PAGE_DATA:
		return "IGVM_VHT_PAGE_DATA";
	case IGVM_VHT_PARAMETER_INSERT:
		return "IGVM_VHT_PARAMETER_INSERT";
	case IGVM_VHT_VP_CONTEXT:
		return "IGVM_VHT_VP_CONTEXT";
	case IGVM_VHT_REQUIRED_MEMORY:
		return "IGVM_VHT_REQUIRED_MEMORY";
	case IGVM_VHT_VP_COUNT_PARAMETER:
		return "IGVM_VHT_VP_COUNT_PARAMETER";
	case IGVM_VHT_SRAT:
		return "IGVM_VHT_SRAT";
	case IGVM_VHT_MADT:
		return "IGVM_VHT_MADT";
	case IGVM_VHT_MMIO_RANGES:
		return "IGVM_VHT_MMIO_RANGES";
	case IGVM_VHT_SNP_ID_BLOCK:
		return "IGVM_VHT_SNP_ID_BLOCK";
	case IGVM_VHT_MEMORY_MAP:
		return "IGVM_VHT_MEMORY_MAP";
	case IGVM_VHT_ERROR_RANGE:
		return "IGVM_VHT_ERROR_RANGE";
	case IGVM_VHT_COMMAND_LINE:
		return "IGVM_VHT_COMMAND_LINE";
	case IGVM_VHT_SLIT:
		return "IGVM_VHT_SLIT";
	case IGVM_VHT_PPTT:
		return "IGVM_VHT_PPTT";
	case IGVM_VHT_VBS_MEASUREMENT:
		return "IGVM_VHT_VBS_MEASUREMENT";
	case IGVM_VHT_DEVICE_TREE:
		return "IGVM_VHT_DEVICE_TREE";
	default:
		return "Unknown type";
	}
}

static void igvm_dump_parameter(IGVM_VHS_PARAMETER *param)
{
	printf("  IGVM_VHS_PARAMETER:\n");
	printf("    ParameterPageIndex: %08X\n", param->parameter_area_index);
	printf("    ByteOffset: %08X\n", param->byte_offset);
	printf("\n");
}

void igvm_dump_variable_header(IgvmVariableHeaderType typ, const uint8_t *header)
{
	printf("%s:\n", igvm_type_to_text(typ));
	switch (typ) {
	case IGVM_VHT_SUPPORTED_PLATFORM: {
		IGVM_VHS_SUPPORTED_PLATFORM *vhs =
			(IGVM_VHS_SUPPORTED_PLATFORM *)header;
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  HighestVtl: %02X\n", vhs->highest_vtl);
		printf("  PlatformType: %02X\n", vhs->platform_type);
		printf("  PlatformVersion: %04X\n", vhs->platform_version);
		printf("  SharedGPABoundary: %lX\n", vhs->shared_gpa_boundary);
		break;
	}
	case IGVM_VHT_GUEST_POLICY: {
		IGVM_VHS_GUEST_POLICY *vhs = (IGVM_VHS_GUEST_POLICY *)header;
		printf("  Policy: %016lX\n", vhs->policy);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  Reserved: %08X\n", vhs->reserved);
		break;
	}
	case IGVM_VHT_RELOCATABLE_REGION: {
		IGVM_VHS_RELOCATABLE_REGION *vhs =
			(IGVM_VHS_RELOCATABLE_REGION *)header;
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  VpIndex: %04X\n", vhs->vp_index);
		printf("  VTL: %02X\n", vhs->vtl);
		printf("  Flags: %02X\n", vhs->flags);
		printf("  RelocationAlignment: %016lX\n",
		       vhs->relocation_alignment);
		printf("  RelocationRegionGPA: %016lX\n",
		       vhs->relocation_region_gpa);
		printf("  RelocationRegionSize: %016lX\n",
		       vhs->relocation_region_size);
		printf("  MinimumRelocationGPA: %016lX\n",
		       vhs->minimum_relocation_gpa);
		printf("  MaximumRelocationGPA: %016lX\n",
		       vhs->maximum_relocation_gpa);
		break;
	}
	case IGVM_VHT_PAGE_TABLE_RELOCATION_REGION: {
		IGVM_VHS_PAGE_TABLE_RELOCATION *vhs =
			(IGVM_VHS_PAGE_TABLE_RELOCATION *)header;
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  VpIndex: %04X\n", vhs->vp_index);
		printf("  VTL: %02X\n", vhs->vtl);
		printf("  Reserved: %02X\n", vhs->reserved);
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  Size: %016lX\n", vhs->size);
		printf("  UsedSize: %016lX\n", vhs->used_size);
		break;
	}
	case IGVM_VHT_PARAMETER_AREA: {
		IGVM_VHS_PARAMETER_AREA *vhs =
			(IGVM_VHS_PARAMETER_AREA *)header;
		printf("  NumberOfBytes: %016lX\n", vhs->number_of_bytes);
		printf("  ParameterAreaIndex: %08X\n",
		       vhs->parameter_area_index);
		printf("  FileOffset: %08X\n", vhs->file_offset);
		break;
	}
	case IGVM_VHT_PAGE_DATA: {
		IGVM_VHS_PAGE_DATA *vhs = (IGVM_VHS_PAGE_DATA *)header;
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  FileOffset: %08X\n", vhs->file_offset);
		printf("  Flags: %08X\n", UINT32_FLAGS_VALUE(vhs->flags));
		printf("  Reserved: %08X\n", vhs->reserved);
		break;
	}
	case IGVM_VHT_PARAMETER_INSERT: {
		IGVM_VHS_PARAMETER_INSERT *vhs =
			(IGVM_VHS_PARAMETER_INSERT *)header;
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  ParameterAreaIndex: %08X\n",
		       vhs->parameter_area_index);
		break;
	}
	case IGVM_VHT_VP_CONTEXT: {
		IGVM_VHS_VP_CONTEXT *vhs = (IGVM_VHS_VP_CONTEXT *)header;
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  FileOffset: %08X\n", vhs->file_offset);
		printf("  VPIndex: %04X\n", vhs->vp_index);
		printf("  Reserved: %04X\n", vhs->reserved);
		break;
	}
	case IGVM_VHT_REQUIRED_MEMORY: {
		IGVM_VHS_REQUIRED_MEMORY *vhs =
			(IGVM_VHS_REQUIRED_MEMORY *)header;
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  NumberOfBytes: %08X\n", vhs->number_of_bytes);
		printf("  Flags: %08X\n", UINT32_FLAGS_VALUE(vhs->flags));
		printf("  Reserved: %08X\n", vhs->reserved);
		break;
	}
	case IGVM_VHT_VP_COUNT_PARAMETER:
	case IGVM_VHT_SRAT:
	case IGVM_VHT_MADT:
	case IGVM_VHT_MMIO_RANGES:
	case IGVM_VHT_MEMORY_MAP:
	case IGVM_VHT_COMMAND_LINE:
	case IGVM_VHT_SLIT:
	case IGVM_VHT_PPTT: {
		IGVM_VHS_PARAMETER *vhs = (IGVM_VHS_PARAMETER *)header;
		igvm_dump_parameter(vhs);
		break;
	}
	case IGVM_VHT_SNP_ID_BLOCK: {
		IGVM_VHS_SNP_ID_BLOCK *vhs = (IGVM_VHS_SNP_ID_BLOCK *)header;
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  AuthorKeyEnabled: %02X\n", vhs->author_key_enabled);
		printf("  Reserved: %02X%02X%02X\n", vhs->reserved[0],
		       vhs->reserved[1], vhs->reserved[2]);
		printf("  Ld:\n");
		hexdump(vhs->ld, 32, 16, 0);
		printf("  FamilyId:\n");
		hexdump(vhs->ld, 16, 16, 0);
		printf("  ImageId:\n");
		hexdump(vhs->ld, 16, 16, 0);
		printf("  Version: %08X\n", vhs->version);
		printf("  GuestSvn: %08X\n", vhs->guest_svn);
		printf("  IdKeyAlgorithm: %08X\n", vhs->id_key_algorithm);
		printf("  AuthorKeyAlgorithm: %08X\n",
		       vhs->author_key_algorithm);
		break;
	}
	case IGVM_VHT_ERROR_RANGE: {
		IGVM_VHS_ERROR_RANGE *vhs =
			(IGVM_VHS_ERROR_RANGE *)header;
		printf("  GPA: %016lX\n", vhs->gpa);
		printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
		printf("  SizeBytes: %08X\n", vhs->size_bytes);
		break;
	}
	default:
		break;
	}
	printf("\n");
}

static void igvm_dump_fixed_header(IGVM_FIXED_HEADER *header)
{
	printf("IGVM_FIXED_HEADER:\n");
	printf("  Magic: 0x%08X\n", header->magic);
	printf("  FormatVersion: 0x%08X\n", header->format_version);
	printf("  VariableHeaderOffset: 0x%08X\n",
	       header->variable_header_offset);
	printf("  VariableHeaderSize: 0x%08X\n", header->variable_header_size);
	printf("  TotalFileSize: 0x%08X\n", header->total_file_size);
	printf("  Checksum: 0x%08X\n", header->checksum);
	printf("\n");
}
