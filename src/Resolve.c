#include <Common.h>
#include <Constexpr.h>


//  Internal PE helpers

FUNC PIMAGE_NT_HEADERS PeValidateHeader(
    _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER Dos = C_PTR( Image );

    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    PIMAGE_NT_HEADERS Nt = C_PTR( U_PTR( Image ) + Dos->e_lfanew );

    if ( Nt->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return Nt;
}

// MZ Backward Walk - align to 64KB, scan backward for MZ+PE.
// Caller must guarantee that Addr points to committed memory inside a PE mapping.

FUNC PVOID PeFindModuleBase(
    _In_ UINT_PTR Addr
) {
    Addr &= ~( (UINT_PTR) 0xFFFF );

    for ( INT i = 0; i < 256; i++ ) {

        if ( * (USHORT *) Addr == IMAGE_DOS_SIGNATURE ) {
            LONG Lfanew = * (LONG *) ( Addr + 0x3C );
            if ( Lfanew > 0 && Lfanew < 0x1000 &&
                 * (DWORD *) ( Addr + Lfanew ) == IMAGE_NT_SIGNATURE ) {
                return C_PTR( Addr );
            }
        }

        if ( Addr < 0x10000 ) break;
        Addr -= 0x10000;
    }

    return NULL;
}

// Hash the DLL name from the PE Export Directory.
// Converts the ANSI export name to WIDE so the hash matches the WIDE BaseDllName-derived H_MODULE_* constants.

FUNC ULONG PeModuleNameHash(
    _In_ PVOID Base
) {
    PIMAGE_NT_HEADERS Nt = PeValidateHeader( Base );
    if ( ! Nt ) return 0;

    DWORD ExpRva = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    if ( ! ExpRva ) return 0;

    PIMAGE_EXPORT_DIRECTORY ExpDir = C_PTR( U_PTR( Base ) + ExpRva );
    if ( ! ExpDir->Name ) return 0;

    PCHAR DllName = A_PTR( U_PTR( Base ) + ExpDir->Name );

    WCHAR WideName[ 64 ];
    INT   Len = 0;

    while ( DllName[ Len ] && Len < 63 ) {
        WideName[ Len ] = (WCHAR) DllName[ Len ];
        Len++;
    }
    WideName[ Len ] = 0;

    return HashString( WideName, Len * sizeof( WCHAR ) );
}



//  RslModule - Thread Entry Point + MZ Walk

FUNC PVOID RslModule(
    _In_ ULONG Hash
) {
    UINT_PTR Teb       = U_PTR( NtCurrentTeb() );
    UINT_PTR StackBase = C_DEF64( Teb + 0x08 );
    UINT_PTR StackLim  = C_DEF64( Teb + 0x10 );

    PVOID    Seen[ 16 ];
    INT      SeenCount = 0;
    for ( INT s = 0; s < 16; s++ ) Seen[ s ] = NULL;

    // Phase 1: Bootstrap - targeted scan near StackBase.

    UINT_PTR BootEnd = StackBase - 0x600;
    if ( BootEnd < StackLim ) BootEnd = StackLim;

    __typeof__( NtQueryVirtualMemory ) * pQuery = NULL;
    PVOID NtdllBase = NULL;

    for ( UINT_PTR Ptr = StackBase - sizeof( UINT_PTR );
          Ptr >= BootEnd;
          Ptr -= sizeof( UINT_PTR ) )
    {
        UINT_PTR Val = * (UINT_PTR *) Ptr;

        if ( Val < 0x7FF000000000ULL || Val > 0x7FFFFFFFFFFFULL )
            continue;

        if ( ( Val & 0xFFFFFFFF ) < 0x10000 )
            continue;

        if ( ( Val & 0xFFF ) == 0 )
            continue;

        PVOID Base = PeFindModuleBase( Val );
        if ( ! Base ) continue;

        BOOL Dup = FALSE;
        for ( INT j = 0; j < SeenCount; j++ ) {
            if ( Seen[ j ] == Base ) { Dup = TRUE; break; }
        }
        if ( Dup ) continue;
        if ( SeenCount < 16 ) Seen[ SeenCount++ ] = Base;

        ULONG NameHash = PeModuleNameHash( Base );

        if ( NameHash == Hash ) {
            return Base;
        }

        if ( NameHash == H_MODULE_NTDLL ) {
            NtdllBase = Base;
            pQuery    = C_PTR( RslFunction( Base, HASH_STR( "NtQueryVirtualMemory" ) ) );
        }
    }

    // Phase 2: Safe scan - broader stack with NtQueryVirtualMemory.

    if ( ! pQuery ) return NULL;

    for ( UINT_PTR Ptr = BootEnd - sizeof( UINT_PTR );
          Ptr >= StackLim;
          Ptr -= sizeof( UINT_PTR ) )
    {
        UINT_PTR Val = * (UINT_PTR *) Ptr;

        if ( Val < 0x7FF000000000ULL || Val > 0x7FFFFFFFFFFFULL )
            continue;

        if ( ( Val & 0xFFFFFFFF ) < 0x10000 )
            continue;

        MEMORY_BASIC_INFORMATION Mbi;
        UINT_PTR Aligned = Val & ~( (UINT_PTR) 0xFFFF );

        if ( ! NT_SUCCESS( pQuery(
            NtCurrentProcess(),
            C_PTR( Aligned ),
            MemoryBasicInformation,
            & Mbi,
            sizeof( Mbi ),
            NULL
        ) ) ) {
            continue;
        }

        if ( Mbi.State != 0x1000 ) {
            continue;
        }

        PVOID Base = PeFindModuleBase( Val );
        if ( ! Base ) continue;

        if ( Base == NtdllBase ) continue;

        BOOL Dup = FALSE;
        for ( INT j = 0; j < SeenCount; j++ ) {
            if ( Seen[ j ] == Base ) { Dup = TRUE; break; }
        }
        if ( Dup ) continue;
        if ( SeenCount < 16 ) Seen[ SeenCount++ ] = Base;

        if ( PeModuleNameHash( Base ) == Hash ) {
            return Base;
        }
    }

    return NULL;
}



//  RslFunction - PE Export Table hash-based function resolution

FUNC PVOID RslFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };

    if ( ! Library || ! Function ) {
        return NULL;
    }

    if ( ! ( NtHeader = PeValidateHeader( Library ) ) ) {
        return NULL;
    }

    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {

        FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

        if ( HashString( FuncName, 0 ) != Function ) {
            continue;
        }

        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            PCHAR FwdStr = A_PTR( Address );
            PCHAR Dot    = FwdStr;

            while ( *Dot && *Dot != '.' ) Dot++;
            if ( ! *Dot ) return NULL;

            CHAR  DllBuf[ 64 ];
            INT   d = 0;
            PCHAR p = FwdStr;

            while ( p < Dot && d < 59 ) DllBuf[ d++ ] = *p++;
            DllBuf[ d++ ] = '.';
            DllBuf[ d++ ] = 'd';
            DllBuf[ d++ ] = 'l';
            DllBuf[ d++ ] = 'l';
            DllBuf[ d ]   = 0;

            WCHAR WideDll[ 64 ];
            for ( INT w = 0; w < d; w++ )
                WideDll[ w ] = (WCHAR) DllBuf[ w ];

            PVOID FwdMod = RslModule( HashString( WideDll, d * sizeof( WCHAR ) ) );
            if ( ! FwdMod ) return NULL;

            return RslFunction( FwdMod, HashString( Dot + 1, 0 ) );
        }

        break;
    }

    return Address;
}
