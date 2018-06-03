#ifndef __UTILS_H__
#define __UTILS_H__

#include <pro.h>

qstring ph_type_to_string(uint32 p_type);
qstring dyntag_to_string(uint64 tag);
int decode_base64(const char *str, int *a2);

#endif