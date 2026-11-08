##
## Project name
##
Project := devapath

##
## Compilers
##
CC_X64	:= x86_64-w64-mingw32-g++

##
## Compiler flags
##
CFLAGS  := -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS  += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS  += -falign-labels=1 -fPIC -Wl,-Tscripts/Linker.ld
CFLAGS  += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS  += -Iinclude -masm=intel -fpermissive -mrdrnd

##
## Source and object files
##
SRC := $(wildcard src/*.c)
OBJ := $(SRC:%.c=%.o)

##
## x64 binaries
##
EXE-X64	:= bin/$(Project).x64.exe
BIN-X64	:= bin/$(Project).x64.bin

##
## Main target
##
all: x64

##
## Build: clean → asm → compile → link → extract
## .NOTPARALLEL prevents clean from racing with asm/compile
##
x64: clean asm-x64 $(OBJ)
	@ echo "[+] link x64 executable"
	@ $(CC_X64) bin/obj/*.x64.o -o $(EXE-X64) $(CFLAGS)
	@ python3 scripts/build.py -f $(EXE-X64) -o $(BIN-X64)
ifeq ($(OS),Windows_NT)
	-@ cmd /c "del /Q $(subst /,\,$(EXE-X64)) 2>NUL"
else
	@ rm -f $(EXE-X64)
endif

##
## Build source to object files
##
$(OBJ):
	@ $(CC_X64) -o bin/obj/$(Project)_$(basename $(notdir $@)).x64.o -c $(basename $@).c $(CFLAGS)

##
## Build assembly source to object files
##
asm-x64:
	@ echo "[*] compile assembly files"
	@ nasm -f win64 asm/x64/DevaPath.asm -o bin/obj/asm_DevaPath.x64.o

##
## Clean object files and other binaries
##
clean:
ifeq ($(OS),Windows_NT)
	-@ cmd /c "del /Q bin\obj\*.o 2>NUL"
	-@ cmd /c "del /Q bin\*.bin 2>NUL"
	-@ cmd /c "del /Q bin\*.exe 2>NUL"
else
	@ rm -f bin/obj/*.o
	@ rm -f bin/*.bin
	@ rm -f bin/*.exe
endif

.PHONY: all x64 asm-x64 clean
.NOTPARALLEL:
