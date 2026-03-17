; prog_equiv.s — matches the shipped prog_equiv.hex (equiv smoke test)
;
; Expected behavior:
;   - call fid 0x0001 (pops=2, pushes=1 in primtab_example)
;   - compare result against 0x3333
;   - TRAP 1 on mismatch, HALT on success

        LIT16 0x1111
        LIT16 0x2222
        INVOKE 0x0001
        ST 0x80
        LD 0x80
        LIT16 0x3333
        EQ
        JNZ ok
        TRAP 0x01
ok:
        HALT
