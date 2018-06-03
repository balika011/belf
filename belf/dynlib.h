#ifndef __DYNLIB_H__
#define __DYNLIB_H__

#include <pro.h>
#include <unordered_map>

class DynLib
{
public:
	DynLib(const char *xml);
	~DynLib();
	void LoadXML(const char *);
	void setSelfModuleStrIndex(uint32 idx) { m_selfModuleStrIndex = idx; }
	void addModule(uint32 id, uint32 nameidx) { m_module_map[id] = nameidx; }

	bool isObfuscated(const char *sym);
	uint32 lookup(const char *obf);
	qstring deobfuscate(qstring lib, qstring obf);

private:
	struct dynlib_entry
	{
		qstring obf;
		qstring lib;
		qstring sym;
	};
	std::vector<dynlib_entry> m_entries;

	uint32 m_selfModuleStrIndex = 0;
	std::unordered_map<uint32, uint32> m_module_map;
};

#endif