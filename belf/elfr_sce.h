#ifndef __ELFR_SCE_H__
#define __ELFR_SCE_H__

#include <map>
#include <set>

#ifndef __ELFBASE_H__
#include <elfbase.h>
#endif

enum elf_ET_SCE
{
	ET_SCE_EXEC = 0xfe00,  // PS4 Executable
	ET_SCE_DYNEXEC = 0xfe10,  // PS4 Main module
	ET_SCE_RELEXEC = 0xfe04,  // PS4 Reloacatable PRX
	ET_SCE_STUBLIB = 0xfe0c,  // PS4 Stub library
	ET_SCE_DYNAMIC = 0xfe18,  // PS4 Dynamic PRX
};

enum elf_DTAG_SCE
{
	DT_SCE_FINGERPRINT = 0x61000007,
	DT_SCE_ORIGINAL_FILENAME = 0x61000009,
	DT_SCE_MODULE_INFO = 0x6100000d,
	DT_SCE_NEEDED_MODULE = 0x6100000f,
	DT_SCE_MODULE_ATTR = 0x61000011,
	DT_SCE_EXPORT_LIB = 0x61000013,
	DT_SCE_IMPORT_LIB = 0x61000015,
	DT_SCE_EXPORT_LIB_ATTR = 0x61000017,
	DT_SCE_IMPORT_LIB_ATTR = 0x61000019,
	DT_SCE_STUB_MODULE_NAME = 0x6100001d,
	DT_SCE_STUB_MODULE_VERSION = 0x6100001f,
	DT_SCE_STUB_LIBRARY_NAME = 0x61000021,
	DT_SCE_STUB_LIBRARY_VERSION = 0x61000023,
	DT_SCE_HASH = 0x61000025,
	DT_SCE_PLTGOT = 0x61000027,
	DT_SCE_JMPREL = 0x61000029,
	DT_SCE_PLTREL = 0x6100002b,
	DT_SCE_PLTRELSZ = 0x6100002d,
	DT_SCE_RELA = 0x6100002f,
	DT_SCE_RELASZ = 0x61000031,
	DT_SCE_RELAENT = 0x61000033,
	DT_SCE_STRTAB = 0x61000035,
	DT_SCE_STRSZ = 0x61000037,
	DT_SCE_SYMTAB = 0x61000039,
	DT_SCE_SYMENT = 0x6100003b,
	DT_SCE_HASHSZ = 0x6100003d,
	DT_SCE_SYMTABSZ = 0x6100003f
};

enum elf_SEGTYPE_SCE
{
	PT_SCE_DYNLIBDATA = 0x61000000,
	PT_SCE_PROCPARAM = 0x61000001,
	PT_SCE_MODULEPARAM = 0x61000002,
	PT_SCE_RELRO = 0x61000010,
};

/* Relocation types for AMD x86-64 architecture */
#define R_X86_64_NONE             0 /* No reloc */
#define R_X86_64_64               1 /* Direct 64 bit  */
#define R_X86_64_PC32             2 /* PC relative 32 bit signed */
#define R_X86_64_GOT32            3 /* 32 bit GOT entry */
#define R_X86_64_PLT32            4 /* 32 bit PLT address */
#define R_X86_64_COPY             5 /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT         6 /* Create GOT entry */
#define R_X86_64_JUMP_SLOT        7 /* Create PLT entry */
#define R_X86_64_RELATIVE	      8 /* Adjust by program base */
#define R_X86_64_GOTPCREL	      9 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_32		         10 /* Direct 32 bit zero extended */
#define R_X86_64_32S		     11 /* Direct 32 bit sign extended */
#define R_X86_64_16		         12 /* Direct 16 bit zero extended */
#define R_X86_64_PC16		     13 /* 16 bit sign extended pc relative */
#define R_X86_64_8		         14 /* Direct 8 bit sign extended  */
#define R_X86_64_PC8		     15 /* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64        16 /* ID of module containing symbol */
#define R_X86_64_DTPOFF64        17 /* Offset in module's TLS block */
#define R_X86_64_TPOFF64         18 /* Offset in initial TLS block */
#define R_X86_64_TLSGD           19 /* 32 bit signed PC relative offset
to two GOT entries for GD symbol */
#define R_X86_64_TLSLD           20 /* 32 bit signed PC relative offset
to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32        21 /* Offset in TLS block */
#define R_X86_64_GOTTPOFF        22 /* 32 bit signed PC relative offset
to GOT entry for IE symbol */
#define R_X86_64_TPOFF32         23 /* Offset in initial TLS block */
#define R_X86_64_PC64            24 /* PC relative 64 bit */
#define R_X86_64_GOTOFF64        25 /* 64 bit offset to GOT */
#define R_X86_64_GOTPC32         26 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_GOT64           27 /* 64-bit GOT entry offset */
#define R_X86_64_GOTPCREL64      28 /* 64-bit PC relative offset to GOT entry */
#define R_X86_64_GOTPC64         29 /* 64-bit PC relative offset to GOT */
#define R_X86_64_GOTPLT64        30 /* like GOT64, says PLT entry needed */
#define R_X86_64_PLTOFF64        31 /* 64-bit GOT relative offset to PLT entry */
#define R_X86_64_SIZE32          32 /* Size of symbol plus 32-bit addend */
#define R_X86_64_SIZE64          33 /* Size of symbol plus 64-bit addend */
#define R_X86_64_GOTPC32_TLSDESC 34 /* GOT offset for TLS descriptor */
#define R_X86_64_TLSDESC_CALL    35 /* Marker for call through TLS descriptor */
#define R_X86_64_TLSDESC         36 /* TLS descriptor */
#define R_X86_64_IRELATIVE       37 /* Adjust indirectly by program base */
#define R_X86_64_RELATIVE64      38 /* 64bit adjust by program base */
#define R_X86_64_ORBIS_GOTPCREL_LOAD   40

#endif
