#include <Common.h>
#include <Constexpr.h>

FUNC VOID Main(
    _In_ PVOID Param
) {
    DEVAPATH_INSTANCE

    //
    // Resolve kernel32 via thread-entry stack scan + MZ walk
    //
    Instance()->Modules.Kernel32 = RslModule( H_MODULE_KERNEL32 );
    if ( ! Instance()->Modules.Kernel32 ) return;

    Instance()->Win32.LoadLibraryW   = RslFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryW"  ) );
    Instance()->Win32.GetProcAddress  = RslFunction( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress" ) );

    if ( ! Instance()->Win32.LoadLibraryW || ! Instance()->Win32.GetProcAddress ) return;

    //
    // Load user32 and show proof of execution
    //
    Instance()->Modules.User32 = Instance()->Win32.LoadLibraryW( L"user32.dll" );
    if ( ! Instance()->Modules.User32 ) return;

    Instance()->Win32.MessageBoxW = Instance()->Win32.GetProcAddress( Instance()->Modules.User32, "MessageBoxW" );
    if ( ! Instance()->Win32.MessageBoxW ) return;

    Instance()->Win32.MessageBoxW( NULL, L"DevaPath PIC Shellcode", L"Rsl", MB_OK );
}
