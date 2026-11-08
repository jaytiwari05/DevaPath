#ifndef DEVAPATH_RESOLVE_H
#define DEVAPATH_RESOLVE_H

#include <Common.h>


// DevaPath uses Thread Entry Point at Stack Bottom + MZ Walk
// ntdll!RtlUserThreadStart  →  kernel32!BaseThreadInitThunk


// RslModule - resolve a module base by its hash.

// Scans the bottom of the thread stack (near StackBase) for return addresses left by ntdll/kernel32 thread initialization,
// MZ-walks backward to find the PE base, and matches via the
// export directory DLL name hash.

// Usage:
//   Instance()->Modules.Ntdll    = RslModule( H_MODULE_NTDLL );
//   Instance()->Modules.Kernel32 = RslModule( H_MODULE_KERNEL32 );
//
PVOID RslModule(
    _In_ ULONG Hash
);

//
// RslFunction - resolve a function from a module's PE export
//               table by DJB2 hash. Pure PE parsing.

// Usage:
//   Instance()->Win32.LoadLibraryW = RslFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryW" ) );

PVOID RslFunction(
    _In_ PVOID Module,
    _In_ ULONG Function
);

#endif //DEVAPATH_RESOLVE_H
