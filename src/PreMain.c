#include <Common.h>
#include <Constexpr.h>

DP_GLOBAL PVOID __Instance = C_PTR( 'dvp5' );

EXTERN_C FUNC VOID PreMain(
    PVOID Param
) {
    INSTANCE DevaPath = { 0 };
    PVOID    Heap     = { 0 };
    PVOID    MmAddr   = { 0 };
    SIZE_T   MmSize   = { 0 };
    ULONG    Protect  = { 0 };

    MmZero( & DevaPath, sizeof( DevaPath ) );

    Heap = NtCurrentPeb()->ProcessHeap;

    DevaPath.Base.Buffer = DpRipStart();
    DevaPath.Base.Length = U_PTR( DpRipEnd() ) - U_PTR( DevaPath.Base.Buffer );

    MmAddr = DevaPath.Base.Buffer + InstanceOffset();
    MmSize = sizeof( PVOID );

    if ( ( DevaPath.Modules.Ntdll = RslModule( H_MODULE_NTDLL ) ) ) {
        if ( ! ( DevaPath.Win32.RtlAllocateHeap       = RslFunction( DevaPath.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"       ) ) ) ||
             ! ( DevaPath.Win32.NtProtectVirtualMemory = RslFunction( DevaPath.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) )
        ) {
            return;
        }
    }

    if ( ! NT_SUCCESS( DevaPath.Win32.NtProtectVirtualMemory(
        NtCurrentProcess(),
        & MmAddr,
        & MmSize,
        PAGE_READWRITE,
        & Protect
    ) ) ) {
        return;
    }

    if ( ! ( C_DEF( MmAddr ) = DevaPath.Win32.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
        return;
    }

    MmCopy( C_DEF( MmAddr ), &DevaPath, sizeof( INSTANCE ) );
    MmZero( & DevaPath, sizeof( INSTANCE ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    Main( Param );
}
