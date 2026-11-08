#ifndef DEVAPATH_MACROS_H
#define DEVAPATH_MACROS_H

//
// Instance access macros
//
#define InstanceOffset()  ( U_PTR( & __Instance_offset ) )
#define InstancePtr()     ( ( PINSTANCE ) C_DEF( C_PTR( U_PTR( DpRipStart() ) + InstanceOffset() ) ) )
#define Instance()        ( ( PINSTANCE ) __LocalInstance )
#define DEVAPATH_INSTANCE PINSTANCE __LocalInstance = InstancePtr();

//
// Function declaration macro - declares a function pointer
// matching the signature of the given Win32 API
//
#define D_API( x )  __typeof__( x ) * x;

//
// Section placement macros for PIC ordering
//
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define DP_GLOBAL   __attribute__( ( section( ".global" ) ) )
#define DP_READONLY __attribute__( ( section( ".rdata" ) ) )

//
// Casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// Dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )


// Memory intrinsics

#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory


// C++ compat

#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

#endif //DEVAPATH_MACROS_H
