#include <ida.hpp>
#include <elfbase.h>
#include "elfr_sce.h"

#include "utils.h"

qstring ph_type_to_string(uint32 p_type)
{
	switch (p_type)
	{
	case PT_NULL: return "PT_NULL";
	case PT_LOAD: return "PT_LOAD";
	case PT_DYNAMIC: return "PT_DYNAMIC";
	case PT_INTERP: return "PT_INTERP";
	case PT_NOTE: return "PT_NOTE";
	case PT_SHLIB: return "PT_SHLIB";
	case PT_PHDR: return "PT_PHDR";
	case PT_TLS: return "PT_TLS";
	case PT_LOOS: return "PT_LOOS";
	case PT_HIOS: return "PT_HIOS";
	case PT_LOPROC: return "PT_LOPROC";
	case PT_HIPROC: return "PT_HIPROC";

	case PT_PAX_FLAGS: return "PT_PAX_FLAGS";

	case PT_GNU_EH_FRAME: return "PT_GNU_EH_FRAME";
	case PT_GNU_STACK: return "PT_GNU_STACK";
	case PT_GNU_RELRO: return "PT_GNU_RELRO";

	case PT_SUNW_UNWIND: return "PT_SUNW_UNWIND / PT_SUNW_EH_FRAME";
	case PT_SUNWBSS: return "PT_SUNWBSS";
	case PT_SUNWSTACK: return "PT_SUNWSTACK";
	case PT_SUNWDTRACE: return "PT_SUNWDTRACE";
	case PT_SUNWCAP: return "PT_SUNWCAP";

	case PT_SCE_DYNLIBDATA: return "PT_SCE_DYNLIBDATA";
	case PT_SCE_PROCPARAM: return "PT_SCE_PROCPARAM";
	case PT_SCE_MODULEPARAM: return "PT_SCE_MODULEPARAM";
	case PT_SCE_RELRO: return "PT_SCE_RELRO";
	}

	qstring ret;
	ret.sprnt("UNK_%x", p_type);
	return ret;
}

qstring dyntag_to_string(uint64 tag)
{
	switch (tag)
	{
	case DT_NULL: return "DT_NULL";
	case DT_NEEDED: return "DT_NEEDED";
	case DT_PLTRELSZ: return "DT_PLTRELSZ";
	case DT_PLTGOT: return "DT_PLTGOT";
	case DT_HASH: return "DT_HASH";
	case DT_STRTAB: return "DT_STRTAB";
	case DT_SYMTAB: return "DT_SYMTAB";
	case DT_RELA: return "DT_RELA";
	case DT_RELASZ: return "DT_RELASZ";
	case DT_RELAENT: return "DT_RELAENT";
	case DT_STRSZ: return "DT_STRSZ";
	case DT_SYMENT: return "DT_SYMENT";
	case DT_INIT: return "DT_INIT";
	case DT_FINI: return "DT_FINI";
	case DT_SONAME: return "DT_SONAME";
	case DT_RPATH: return "DT_RPATH";
	case DT_SYMBOLIC: return "DT_SYMBOLIC";
	case DT_REL: return "DT_REL";
	case DT_RELSZ: return "DT_RELSZ";
	case DT_RELENT: return "DT_RELENT";
	case DT_PLTREL: return "DT_PLTREL";
	case DT_DEBUG: return "DT_DEBUG";
	case DT_TEXTREL: return "DT_TEXTREL";
	case DT_JMPREL: return "DT_JMPREL";
	case DT_BIND_NOW: return "DT_BIND_NOW";
	case DT_INIT_ARRAY: return "DT_INIT_ARRAY";
	case DT_FINI_ARRAY: return "DT_FINI_ARRAY";
	case DT_INIT_ARRAYSZ: return "DT_INIT_ARRAYSZ";
	case DT_FINI_ARRAYSZ: return "DT_FINI_ARRAYSZ";
	case DT_RUNPATH: return "DT_RUNPATH";
	case DT_FLAGS: return "DT_FLAGS";
	case DT_ENCODING: return "DT_ENCODING";
	case DT_PREINIT_ARRAY: return "DT_PREINIT_ARRAY";
	case DT_PREINIT_ARRAYSZ: return "DT_PREINIT_ARRAYSZ";
	case DT_LOOS: return "DT_LOOS";
	case DT_HIOS: return "DT_HIOS/DT_VERNEEDNUM";
	case DT_SUNW_AUXILIARY: return "DT_SUNW_AUXILIARY";
	case DT_SUNW_RTLDINF: return "DT_SUNW_RTLDINF/DT_SUNW_FILTER";
	case DT_SUNW_CAP: return "DT_SUNW_CAP";
	case DT_SUNW_SYMTAB: return "DT_SUNW_SYMTAB";
	case DT_SUNW_SYMSZ: return "DT_SUNW_SYMSZ";
	case DT_SUNW_ENCODING: return "DT_SUNW_ENCODING/DT_SUNW_SORTENT";
	case DT_SUNW_SYMSORT: return "DT_SUNW_SYMSORT";
	case DT_SUNW_SYMSORTSZ: return "DT_SUNW_SYMSORTSZ";
	case DT_SUNW_TLSSORT: return "DT_SUNW_TLSSORT";
	case DT_SUNW_TLSSORTSZ: return "DT_SUNW_TLSSORTSZ";
	case DT_SUNW_CAPINFO: return "DT_SUNW_CAPINFO";
	case DT_SUNW_STRPAD: return "DT_SUNW_STRPAD";
	case DT_SUNW_CAPCHAIN: return "DT_SUNW_CAPCHAIN";
	case DT_SUNW_LDMACH: return "DT_SUNW_LDMACH";
	case DT_SUNW_CAPCHAINENT: return "DT_SUNW_CAPCHAINENT";
	case DT_SUNW_CAPCHAINSZ: return "DT_SUNW_CAPCHAINSZ";
	case DT_SUNW_PARENT: return "DT_SUNW_PARENT";
	case DT_SUNW_ASLR: return "DT_SUNW_ASLR";
	case DT_SUNW_RELAX: return "DT_SUNW_RELAX";
	case DT_SUNW_NXHEAP: return "DT_SUNW_NXHEAP";
	case DT_SUNW_NXSTACK: return "DT_SUNW_NXSTACK";
	case DT_VALRNGLO: return "DT_VALRNGLO";
	case DT_GNU_PRELINKED: return "DT_GNU_PRELINKED";
	case DT_GNU_CONFLICTSZ: return "DT_GNU_CONFLICTSZ";
	case DT_GNU_LIBLISTSZ: return "DT_GNU_LIBLISTSZ";
	case DT_CHECKSUM: return "DT_CHECKSUM";
	case DT_PLTPADSZ: return "DT_PLTPADSZ";
	case DT_MOVEENT: return "DT_MOVEENT";
	case DT_MOVESZ: return "DT_MOVESZ";
	case DT_FEATURE: return "DT_FEATURE";
	case DT_POSFLAG_1: return "DT_POSFLAG_1";
	case DT_SYMINSZ: return "DT_SYMINSZ";
	case DT_SYMINENT: return "DT_SYMINENT/DT_VALRNGHI";
	case DT_ADDRRNGLO: return "DT_ADDRRNGLO";
	case DT_GNU_HASH: return "DT_GNU_HASH";
	case DT_TLSDESC_PLT: return "DT_TLSDESC_PLT";
	case DT_TLSDESC_GOT: return "DT_TLSDESC_GOT";
	case DT_GNU_CONFLICT: return "DT_GNU_CONFLICT";
	case DT_GNU_LIBLIST: return "DT_GNU_LIBLIST";
	case DT_CONFIG: return "DT_CONFIG";
	case DT_DEPAUDIT: return "DT_DEPAUDIT";
	case DT_AUDIT: return "DT_AUDIT";
	case DT_PLTPAD: return "DT_PLTPAD";
	case DT_MOVETAB: return "DT_MOVETAB";
	case DT_SYMINFO: return "DT_SYMINFO/DT_ADDRRNGHI";
	case DT_RELACOUNT: return "DT_RELACOUNT";
	case DT_RELCOUNT: return "DT_RELCOUNT";
	case DT_FLAGS_1: return "DT_FLAGS_1";
	case DT_VERDEF: return "DT_VERDEF";
	case DT_VERDEFNUM: return "DT_VERDEFNUM";
	case DT_VERNEED: return "DT_VERNEED";
	case DT_VERSYM: return "DT_VERSYM";
	case DT_LOPROC: return "DT_LOPROC";
	case DT_HIPROC: return "DT_HIPROC";
	case DT_AUXILIARY: return "DT_AUXILIARY/DT_FILTER";
	case DT_USED: return "DT_USED";

	case DT_SCE_FINGERPRINT: return "DT_SCE_FINGERPRINT";
	case DT_SCE_ORIGINAL_FILENAME: return "DT_SCE_ORIGINAL_FILENAME";
	case DT_SCE_MODULE_INFO: return "DT_SCE_MODULE_INFO";
	case DT_SCE_NEEDED_MODULE: return "DT_SCE_NEEDED_MODULE";
	case DT_SCE_MODULE_ATTR: return "DT_SCE_MODULE_ATTR";
	case DT_SCE_EXPORT_LIB: return "DT_SCE_EXPORT_LIB";
	case DT_SCE_IMPORT_LIB: return "DT_SCE_IMPORT_LIB";
	case DT_SCE_EXPORT_LIB_ATTR: return "DT_SCE_EXPORT_LIB_ATTR";
	case DT_SCE_IMPORT_LIB_ATTR: return "DT_SCE_IMPORT_LIB_ATTR";
	case DT_SCE_STUB_MODULE_NAME: return "DT_SCE_STUB_MODULE_NAME";
	case DT_SCE_STUB_MODULE_VERSION: return "DT_SCE_STUB_MODULE_VERSION";
	case DT_SCE_STUB_LIBRARY_NAME: return "DT_SCE_STUB_LIBRARY_NAME";
	case DT_SCE_STUB_LIBRARY_VERSION: return "DT_SCE_STUB_LIBRARY_VERSION";
	case DT_SCE_HASH: return "DT_SCE_HASH";
	case DT_SCE_PLTGOT: return "DT_SCE_PLTGOT";
	case DT_SCE_JMPREL: return "DT_SCE_JMPREL";
	case DT_SCE_PLTREL: return "DT_SCE_PLTREL";
	case DT_SCE_PLTRELSZ: return "DT_SCE_PLTRELSZ";
	case DT_SCE_RELA: return "DT_SCE_RELA";
	case DT_SCE_RELASZ: return "DT_SCE_RELASZ";
	case DT_SCE_RELAENT: return "DT_SCE_RELAENT";
	case DT_SCE_STRTAB: return "DT_SCE_STRTAB";
	case DT_SCE_STRSZ: return "DT_SCE_STRSZ";
	case DT_SCE_SYMTAB: return "DT_SCE_SYMTAB";
	case DT_SCE_SYMENT: return "DT_SCE_SYMENT";
	case DT_SCE_HASHSZ: return "DT_SCE_HASHSZ";
	case DT_SCE_SYMTABSZ: return "DT_SCE_SYMTABSZ";
	}

	qstring ret;
	ret.sprnt("UNK_%llx", tag);
	return ret;
}

int decode_base64(const char *str, int *a2)
{
	char chr; // dl@1
	int v3; // rcx@1
	const char *v4; // rdi@2
	int v5; // rcx@3
	int result; // rax@11

	chr = *str;
	v3 = 0LL;
	if (*str) {
		v4 = str + 1;
		v3 = 0LL;
		do {
			v5 = v3 << 6;
			if ((unsigned __int8)(chr - 0x61) > 0x19u) {
				if ((unsigned __int8)(chr - 0x41) > 0x19u) {
					if ((unsigned __int8)(chr - 0x30) > 9u) {
						if (chr == '-')
							v3 = v5 | 0x3F;
						else {
							result = 22LL;
							if (chr != '+')
								return result;
							v3 = v5 | 0x3E;
						}
					}
					else {
						v3 = chr + (v5 | 4);
					}
				}
				else {
					v3 = v5 + chr - 0x41;
				}
			}
			else {
				v3 = v5 + chr - 0x47;
			}
			chr = *v4++;
		} while (chr);
	}
	*a2 = v3;
	return 0LL;
}