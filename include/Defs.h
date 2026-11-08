#ifndef DEVAPATH_DEFS_H
#define DEVAPATH_DEFS_H

#include <Common.h>

typedef struct _BUFFER {
    PVOID  Buffer;
    ULONG  Length;
} BUFFER, *PBUFFER;


// DJB2 hashing constants

#define H_MAGIC_KEY       5381
#define H_MAGIC_SEED      5


// Pre-computed DJB2 module name hashes (case-insensitive)
// These are hashed via HashString() which upper-cases before hashing.

#define H_MODULE_NTDLL    0x70e61753
#define H_MODULE_KERNEL32 0xadd31df0

#endif //DEVAPATH_DEFS_H
