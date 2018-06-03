#include "dynlib.h"

#include <ida.hpp>
#include <loader.hpp>
#include <idp.hpp>

#include "TinyXML/tinyxml.h"
#include "utils.h"

DynLib::DynLib(const char *xml)
{
	LoadXML(xml);
}

DynLib::~DynLib()
{

}

void DynLib::LoadXML(const char *db)
{
	TiXmlDocument xml;
	if (!xml.LoadFile(db))
		loader_failure("Failed to load database file (%s).", db);

	TiXmlElement *DynlibDatabase = xml.FirstChildElement();
	if (!DynlibDatabase || strcmp(DynlibDatabase->Value(), "DynlibDatabase"))
		loader_failure("Database requires \"DynlibDatabase\" header.");

	TiXmlElement *e = DynlibDatabase->FirstChildElement();
	if (!e)
		loader_failure("Database has no entries in  \"DynlibDatabase\".");

	do {
		const char *obf = e->Attribute("obf");
		if (!obf)
			loader_failure("Entry needs to have an \"obf\" attribute.");
		const char *lib = e->Attribute("lib");
		if (!lib)
			loader_failure("Entry needs to have an \"lib\" attribute.");
		const char *sym = e->Attribute("sym");
		if (!sym)
			loader_failure("Entry needs to have an \"sym\" attribute.");

		dynlib_entry entry;
		entry.obf.sprnt(obf);
		entry.lib.sprnt(lib);
		entry.sym.sprnt(sym);
		m_entries.push_back(entry);
	} while (e = e->NextSiblingElement());
}

bool DynLib::isObfuscated(const char *sym)
{
	const char *p;
	if (strlen(sym) >= 13)
		if ((p = strchr(sym, '#')) != NULL) // contains first #
			if ((p - sym) == 11)                // obfuscated symbol is 11 chars
				if ((p = strchr(p + 1, '#')) != NULL) // contains second #
					return true;

	return false;
}

uint32 DynLib::lookup(const char *obf)
{
	int modid;

	const char *lib = strchr(obf, '#');
	if (lib == NULL) {
		msg("No lib id in this symbol.\n");
		return -1;
	}

	lib = strchr(lib + 1, '#');
	if (lib == NULL) {
		msg("No mod id in this symbol.\n");
		return -1;
	}

	if (decode_base64(lib + 1, &modid)) {
		msg("Invalid module id!\n");
		return -1;
	}

	if (modid == 0)
		return m_selfModuleStrIndex;

	if (m_module_map.find(modid) != m_module_map.end())
	{
		return m_module_map.at(modid);
	}

	return -1;
}

qstring DynLib::deobfuscate(qstring lib, qstring obf)
{
	for (const dynlib_entry& entry : m_entries)
	{
		if (entry.lib == lib && obf.substr(0, 11) == entry.obf)
			return entry.sym;
	}

	return "";
}