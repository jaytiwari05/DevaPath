#ifndef DEVAPATH_COMMON_H
#define DEVAPATH_COMMON_H

#include <windows.h>

// DevaPath headers

#include <Native.h>
#include <Macros.h>
#include <Resolve.h>
#include <Defs.h>
#include <Utils.h>


// Global instance symbol (written by asm, patched at runtime)

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;


//  DevaPath Instance Structure

typedef struct _INSTANCE {

    BUFFER Base;

    struct {
        //
        // Ntdll.dll
        //
        D_API( RtlAllocateHeap )
        D_API( NtProtectVirtualMemory )

        //
        // Kernel32.dll - the two master keys
        //
        D_API( LoadLibraryW )
        D_API( GetProcAddress )

        //
        // User32.dll (resolved at runtime via LoadLibraryW)
        //
        D_API( MessageBoxW )

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID User32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID DpRipStart();
EXTERN_C PVOID DpRipEnd();

VOID Main(
    _In_ PVOID Param
);

#endif //DEVAPATH_COMMON_H
