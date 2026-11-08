#ifndef DEVAPATH_CONSTEXPR_H
#define DEVAPATH_CONSTEXPR_H

#include <Common.h>


// Compile-time hash macro - resolves to a constant in optimized builds.
// Used as:  HASH_STR( "LoadLibraryW" )  →  0xADD31DF0  (at compile time)

#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = { 0 };
    CHAR  Char = { 0 };

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

#endif //DEVAPATH_CONSTEXPR_H
