# DevaPath

A Position-Independent Code (PIC) shellcode framework for x64 Windows that resolves DLL modules and functions **without walking the PEB→Ldr linked lists**.

Built as an educational project for studying Windows internals and alternative module resolution techniques.

## Technique

**Thread Entry Point at Stack Bottom** - every user-mode thread's stack bottoms out at `ntdll!RtlUserThreadStart` and `kernel32!BaseThreadInitThunk`. Their return addresses always sit near `TEB.StackBase`. DevaPath scans that region to bootstrap module resolution.

### How It Works

1. **Read TEB** - `gs:[0x30]` gives us the Thread Environment Block. We grab `StackBase` and `StackLimit` from it.

2. **Phase 1 (Bootstrap)** - Scan the last ~0x600 bytes near `StackBase` for return addresses. For each candidate, walk backward on 64KB-aligned boundaries looking for `MZ` + `PE` signatures. No `NtQueryVirtualMemory` needed - strict address filters keep it safe.

3. **Phase 2 (Safe Scan)** - Once ntdll is found, resolve `NtQueryVirtualMemory` from its export table. Use it to probe the broader stack safely for remaining modules like kernel32.

4. **Export Resolution** - Pure PE export table parsing with DJB2 hashing. Supports **forwarded exports** (e.g., `kernel32!HeapAlloc` → `NTDLL.RtlAllocateHeap`).

5. **Runtime** - With `LoadLibraryW` and `GetProcAddress` resolved from kernel32, any additional DLL/function can be loaded normally.

## Project Structure

```
DevaPath/
  asm/x64/DevaPath.asm    -- NASM entry point (RIP-relative instance access)
  include/
    Common.h               -- Instance structure (Modules + Win32 function pointers)
    Constexpr.h            -- Compile-time DJB2 hashing (HASH_STR macro)
    Defs.h                 -- Hash constants (H_MODULE_NTDLL, H_MODULE_KERNEL32)
    Macros.h               -- PIC helpers (C_PTR, U_PTR, FUNC section placement)
    Native.h               -- NT API definitions
    Resolve.h              -- RslModule / RslFunction declarations
    Utils.h                -- HashString declaration
  src/
    PreMain.c              -- Bootstrap: resolve ntdll, allocate instance on heap
    Main.c                 -- Resolve kernel32 → LoadLibraryW/GetProcAddress → MessageBoxW
    Resolve.c              -- Module + function resolution (Technique 2 + PE exports)
    Utils.c                -- DJB2 HashString (ANSI + WIDE paths)
  scripts/
    Linker.ld              -- Custom linker script for PIC section ordering
    build.py               -- Extract .text section into raw shellcode .bin
    loader.c               -- Test loader for running the shellcode
  bin/                     -- Build output (.bin shellcode payload)
  Makefile                 -- Cross-platform build (Windows + Linux)
```

## Build

Requires `x86_64-w64-mingw32-g++`, `nasm`, and `python3`.

```
make
```

This produces `bin/devapath.x64.bin` - the raw shellcode payload.

## Run

Use the included loader to test:

```
scripts\loader.exe bin\devapath.x64.bin
```

A MessageBox confirms successful execution.

## Key Design Decisions

- **Zero PEB→Ldr walking** - The only PEB access is `NtCurrentPeb()->ProcessHeap` for heap allocation. No `InLoadOrderModuleList`, no `InMemoryOrderModuleList`.
- **Two-phase bootstrap** - Phase 1 works without any resolved functions. Phase 2 only activates after ntdll is found and `NtQueryVirtualMemory` is available.
- **Forwarded export support** - When a PE export address falls within the export directory, DevaPath parses the forwarder string (`"DLL.Function"`), finds the target module via `RslModule`, and recursively resolves through `RslFunction`.
- **DJB2 hashing** - Case-insensitive (uppercased before hashing). Module hashes use WIDE byte-by-byte processing to match `BaseDllName` format. Function hashes use ANSI.

## Credits

Based on [Stardust](https://github.com/Cracked5pider/Stardust) by [C5pทder (Paul)](https://github.com/Cracked5pider). DevaPath extends the Stardust architecture with an alternative module resolution technique (Thread Entry Point at Stack Bottom instead of PEB→Ldr walking) and adds forwarded export resolution where Stardust has a placeholder.
