#!/usr/bin/env python3
"""
j16sim.py — J16 v2 Python Reference Simulator

Direct translation of j16_ref_pkg.sv. Behaviour is normative: any
divergence from the SV reference model is a bug in this file.

Usage:
    python3 tools/j16sim.py --hex prog.hex
    python3 tools/j16sim.py --hex prog.hex --primtab primtab.hex --trace
    python3 tools/j16sim.py --hex prog.hex --max-steps 100000
    python3 tools/j16sim.py --hex prog.hex --dump-mem

Exit codes:
    0  clean HALT (ST_OK)
    1  fault / bad args
    2  step budget exceeded
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# ISA constants  (mirrors j16_isa.svh)
# ---------------------------------------------------------------------------

# Primary opcodes  [15:12]
OP_NOP    = 0x0
OP_ALU    = 0x1
OP_LIT    = 0x2
OP_MEM    = 0x3
OP_CTRL   = 0x4
OP_STACK  = 0x5
OP_LIT16  = 0x6
OP_INVOKE = 0xB
OP_SYS    = 0xF

# ALU subops  [11:8]
ALU_XOR  = 0x0
ALU_AND  = 0x1
ALU_OR   = 0x2
ALU_NOT  = 0x3
ALU_ADD  = 0x4
ALU_SUB  = 0x5
ALU_SHL  = 0x6
ALU_SHR  = 0x7
ALU_ROTL = 0x8
ALU_ROTR = 0x9
ALU_EQ   = 0xA
ALU_LT   = 0xB
ALU_NEQ  = 0xC

# MEM subops
MEM_LD  = 0x0
MEM_ST  = 0x1
MEM_LDI = 0x2
MEM_STI = 0x3

# STACK subops
STACK_DUP  = 0x0
STACK_DROP = 0x1
STACK_SWAP = 0x2
STACK_OVER = 0x3

# CTRL subops  (A >= 3 is ILLEGAL_ENC; CALL/RET do not exist)
CTRL_JMP = 0x0
CTRL_JZ  = 0x1
CTRL_JNZ = 0x2

# SYS subops
SYS_HALT = 0x0
SYS_TRAP = 0x1

# Memory map (frozen)
ARG_BASE    = 0x00
RES_BASE    = 0x20
USER_START  = 0x40
USER_END    = 0xFD
AUX_ADDR    = 0xFE
STATUS_ADDR = 0xFF
PROT_LO_END    = 0x3F   # 0x00..0x3F  protected (ARG/RES)
PROT_HI_START  = 0xFE   # 0xFE..0xFF  protected (AUX/STATUS)

# Status codes (frozen)
ST_OK             = 0x0000
ST_UNKNOWN_INVOKE = 0x0001
ST_DSTACK_UF      = 0x0002
ST_DSTACK_OF      = 0x0003
ST_PC_OOB         = 0x0004
ST_ILLEGAL_ENC    = 0x0005
ST_TRAP           = 0x0006
ST_MEM_PROT       = 0x0007
ST_INVOKE_TIMEOUT = 0x0008

STATUS_NAMES = {
    ST_OK:             "ST_OK",
    ST_UNKNOWN_INVOKE: "ST_UNKNOWN_INVOKE",
    ST_DSTACK_UF:      "ST_DSTACK_UF",
    ST_DSTACK_OF:      "ST_DSTACK_OF",
    ST_PC_OOB:         "ST_PC_OOB",
    ST_ILLEGAL_ENC:    "ST_ILLEGAL_ENC",
    ST_TRAP:           "ST_TRAP",
    ST_MEM_PROT:       "ST_MEM_PROT",
    ST_INVOKE_TIMEOUT: "ST_INVOKE_TIMEOUT",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def u16(v: int) -> int:
    """Mask to unsigned 16-bit."""
    return v & 0xFFFF

def sext8(b: int) -> int:
    """Sign-extend 8-bit to Python int."""
    b = b & 0xFF
    return b if b < 0x80 else b - 0x100

def rotl16(x: int, sh: int) -> int:
    x = u16(x)
    sh = sh & 0xF
    if sh == 0:
        return x
    return u16((x << sh) | (x >> (16 - sh)))

def rotr16(x: int, sh: int) -> int:
    x = u16(x)
    sh = sh & 0xF
    if sh == 0:
        return x
    return u16((x >> sh) | (x << (16 - sh)))

def mem_protected(addr: int) -> bool:
    addr = addr & 0xFF
    return addr <= PROT_LO_END or addr >= PROT_HI_START

def ctrl_b_legal(b: int) -> bool:
    """Forward-only: B[7] must be 0."""
    return (b & 0x80) == 0

def ctrl_target(pc: int, b: int) -> int:
    """Target = (PC+1) + sext8(B). Always forward if B[7]=0."""
    return pc + 1 + sext8(b)

def load_readmemh(path: Path, word_bytes: int = 2, max_words: int = 1024) -> list[int]:
    """
    Parse a $readmemh-compatible hex file.
    Supports one value per line, optional // comments, @address directives.
    Returns a flat list of integers (zero-padded to max_words).
    """
    words = [0] * max_words
    cursor = 0
    with open(path) as f:
        for line in f:
            line = line.split("//")[0].split(";")[0].split("#")[0].strip()
            if not line:
                continue
            if line.startswith("@"):
                cursor = int(line[1:], 16)
                if cursor >= max_words:
                    print(f"J16SIM WARN: @address directive 0x{cursor:x} in {path.name} "
                          f"is >= max_words ({max_words}); subsequent words will be discarded.",
                          file=sys.stderr)
                continue
            # May be multiple tokens per line
            for tok in line.split():
                if cursor < max_words:
                    words[cursor] = int(tok, 16)
                    cursor += 1
    return words

# ---------------------------------------------------------------------------
# Primitive metadata
# ---------------------------------------------------------------------------

@dataclass
class PrimMeta:
    full_id:       int
    model:         int
    max_units:     int
    base_cycles:   int
    per_cycles:    int
    cap_id:        int
    pops:          int
    pushes:        int
    deterministic: bool

    @classmethod
    def from_row128(cls, row: int) -> "PrimMeta":
        """Unpack a 128-bit primtab row (same bit layout as primtab_format.md)."""
        full_id       = (row >> 112) & 0xFFFF
        model         = (row >> 108) & 0xF
        # unit [107:104] unused
        max_units     = (row >> 88)  & 0xFFFF
        base_cycles   = (row >> 72)  & 0xFFFF
        per_cycles    = (row >> 56)  & 0xFFFF
        cap_id        = (row >> 48)  & 0xFF
        pops          = (row >> 40)  & 0xFF
        pushes        = (row >> 32)  & 0xFF
        deterministic = bool((row >> 31) & 0x1)
        return cls(full_id, model, max_units, base_cycles, per_cycles,
                   cap_id, pops, pushes, deterministic)


# PrimImpl: (mem: bytearray[256], status_out: list[int], aux_out: list[int]) -> None
# The callable receives the full 256-word RAM as a list[int], and must set
# status_out[0] and aux_out[0] to signal success/fault.
PrimImpl = Callable[[list[int], list[int], list[int]], None]

# ---------------------------------------------------------------------------
# Main simulator class  (mirrors J16Ref in j16_ref_pkg.sv)
# ---------------------------------------------------------------------------

class J16Sim:
    """
    J16 v2 reference simulator.

    Mirrors J16Ref from j16_ref_pkg.sv. The step() return value and fault
    semantics are identical to the SV version.
    """

    def __init__(self) -> None:
        self.rom:      list[int] = [0] * 1024
        self.prog_len: int = 0

        self.mem:    list[int] = [0] * 256   # 256-word flat RAM
        self.dstack: list[int] = []           # data stack (Python list as stack)

        self.halted:  bool = False
        self.faulted: bool = False
        self.pc:      int  = 0
        self.steps:   int  = 0

        self.prim_meta: dict[int, PrimMeta]  = {}
        self.prim_impl: dict[int, PrimImpl]  = {}

        # Trace log — populated if trace=True passed to run()
        self.trace_log: list[str] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_hex(self, path: Path | str) -> None:
        """Load a $readmemh .hex file into ROM. Computes prog_len as in the SV model."""
        path = Path(path)
        raw = load_readmemh(path, word_bytes=2, max_words=1024)
        self.rom = raw

        # prog_len = index of last SYS HALT (0xF000) + 1
        halt_idx = -1
        for i in range(1023, -1, -1):
            if raw[i] == 0xF000:
                halt_idx = i
                break

        if halt_idx < 0:
            self.prog_len = 1
            print("J16SIM WARN: no SYS HALT (0xF000) terminator found; prog_len forced to 1.",
                  file=sys.stderr)
        else:
            self.prog_len = halt_idx + 1
            for j in range(halt_idx + 1, 1024):
                if raw[j] != 0:
                    print(f"J16SIM WARN: nonzero word after terminating HALT at rom[{halt_idx}]: "
                          f"rom[{j}]=0x{raw[j]:04x}", file=sys.stderr)
                    break

    def load_primtab(self, path: Path | str) -> None:
        """Load a primtab.hex file (128-bit rows, 32 hex chars per line)."""
        path = Path(path)
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.split("//")[0].strip()
                if not line:
                    continue
                # Each line is 32 hex chars = 128 bits
                try:
                    row = int(line, 16)
                except ValueError:
                    print(f"J16SIM WARN: primtab line {lineno}: bad hex '{line}'",
                          file=sys.stderr)
                    continue
                if row == 0:
                    continue
                meta = PrimMeta.from_row128(row)
                if not meta.deterministic:
                    print(f"J16SIM WARN: primtab line {lineno}: fid=0x{meta.full_id:04x} "
                          f"is non-deterministic, skipping", file=sys.stderr)
                    continue
                self.prim_meta[meta.full_id] = meta

    def register_prim(self, meta: PrimMeta, impl: Optional[PrimImpl] = None) -> None:
        """Register a primitive with optional Python implementation."""
        self.prim_meta[meta.full_id] = meta
        if impl is not None:
            self.prim_impl[meta.full_id] = impl

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fault(self, status: int, aux: int = 0) -> None:
        self.mem[STATUS_ADDR] = u16(status)
        self.mem[AUX_ADDR]    = u16(aux)
        self.halted  = True
        self.faulted = True

    def _push(self, v: int) -> bool:
        if len(self.dstack) >= 256:
            self._fault(ST_DSTACK_OF, self.pc & 0xFFFF)
            return False
        self.dstack.append(u16(v))
        return True

    def _pop(self) -> tuple[int, bool]:
        if not self.dstack:
            self._fault(ST_DSTACK_UF, self.pc & 0xFFFF)
            return 0xDEAD, False
        return self.dstack.pop(), True

    def _tos(self) -> int:
        return self.dstack[-1] if self.dstack else 0

    # ------------------------------------------------------------------
    # Single step  (mirrors J16Ref::step())
    # ------------------------------------------------------------------

    def step(self) -> bool:
        """
        Execute one instruction. Returns True to continue, False if halted/faulted.
        Semantics are identical to j16_ref_pkg.sv J16Ref::step().
        """
        if self.halted or self.faulted:
            return False

        if self.pc >= self.prog_len:
            self._fault(ST_PC_OOB, self.pc & 0xFFFF)
            return False

        ir = self.rom[self.pc] & 0xFFFF
        op = (ir >> 12) & 0xF
        A  = (ir >> 8)  & 0xF
        B  =  ir        & 0xFF
        self.steps += 1

        # ---- NOP -------------------------------------------------------
        if op == OP_NOP:
            if A != 0 or B != 0:
                self._fault(ST_ILLEGAL_ENC, ir)
                return False
            self.pc += 1

        # ---- LIT -------------------------------------------------------
        elif op == OP_LIT:
            if not self._push((A << 8) | B):
                return False
            self.pc += 1

        # ---- LIT16 -----------------------------------------------------
        elif op == OP_LIT16:
            if A != 0 or B != 0:
                self._fault(ST_ILLEGAL_ENC, ir)
                return False
            if self.pc + 1 >= self.prog_len:
                self._fault(ST_PC_OOB, (self.pc + 1) & 0xFFFF)
                return False
            lit = self.rom[self.pc + 1] & 0xFFFF
            if not self._push(lit):
                return False
            self.pc += 2

        # ---- STACK -----------------------------------------------------
        elif op == OP_STACK:
            if A == STACK_DUP:
                if not self.dstack:
                    self._fault(ST_DSTACK_UF, ir); return False
                if not self._push(self.dstack[-1]):
                    return False
            elif A == STACK_DROP:
                if not self.dstack:
                    self._fault(ST_DSTACK_UF, ir); return False
                self.dstack.pop()
            elif A == STACK_SWAP:
                if len(self.dstack) < 2:
                    self._fault(ST_DSTACK_UF, ir); return False
                self.dstack[-1], self.dstack[-2] = self.dstack[-2], self.dstack[-1]
            elif A == STACK_OVER:
                if len(self.dstack) < 2:
                    self._fault(ST_DSTACK_UF, ir); return False
                if not self._push(self.dstack[-2]):
                    return False
            else:
                self._fault(ST_ILLEGAL_ENC, ir); return False
            self.pc += 1

        # ---- ALU -------------------------------------------------------
        elif op == OP_ALU:
            # Unary ops
            if A in (ALU_NOT, ALU_SHL, ALU_SHR, ALU_ROTL, ALU_ROTR):
                if not self.dstack:
                    self._fault(ST_DSTACK_UF, ir); return False
                x = self.dstack[-1]
                if   A == ALU_NOT:  self.dstack[-1] = u16(~x)
                elif A == ALU_SHL:  self.dstack[-1] = u16(x << (B & 0xF))
                elif A == ALU_SHR:  self.dstack[-1] = u16(x >> (B & 0xF))
                elif A == ALU_ROTL: self.dstack[-1] = rotl16(x, B)
                elif A == ALU_ROTR: self.dstack[-1] = rotr16(x, B)
            # Binary ops (nos op tos → result; pops TOS, replaces NOS)
            elif A in (ALU_XOR, ALU_AND, ALU_OR, ALU_ADD, ALU_SUB,
                       ALU_EQ, ALU_LT, ALU_NEQ):
                if len(self.dstack) < 2:
                    self._fault(ST_DSTACK_UF, ir); return False
                tos = self.dstack.pop()   # TOS
                nos = self.dstack[-1]     # NOS (stays, gets overwritten)
                if   A == ALU_XOR: self.dstack[-1] = u16(nos ^ tos)
                elif A == ALU_AND: self.dstack[-1] = u16(nos & tos)
                elif A == ALU_OR:  self.dstack[-1] = u16(nos | tos)
                elif A == ALU_ADD: self.dstack[-1] = u16(nos + tos)
                elif A == ALU_SUB: self.dstack[-1] = u16(nos - tos)
                elif A == ALU_EQ:  self.dstack[-1] = 1 if nos == tos else 0
                elif A == ALU_LT:  self.dstack[-1] = 1 if nos <  tos else 0  # unsigned
                elif A == ALU_NEQ: self.dstack[-1] = 1 if nos != tos else 0
            else:
                self._fault(ST_ILLEGAL_ENC, ir); return False
            self.pc += 1

        # ---- MEM -------------------------------------------------------
        elif op == OP_MEM:
            if A == MEM_LD:
                if mem_protected(B):
                    self._fault(ST_MEM_PROT, B); return False
                if not self._push(self.mem[B]):
                    return False
            elif A == MEM_ST:
                if mem_protected(B):
                    self._fault(ST_MEM_PROT, B); return False
                v, ok = self._pop()
                if not ok: return False
                self.mem[B] = v
            elif A == MEM_LDI:
                if not self.dstack:
                    self._fault(ST_DSTACK_UF, ir); return False
                addr = self.dstack[-1] & 0xFF
                if mem_protected(addr):
                    self._fault(ST_MEM_PROT, addr); return False
                self.dstack[-1] = self.mem[addr]   # net 0: pop addr, push mem[addr]
            elif A == MEM_STI:
                if len(self.dstack) < 2:
                    self._fault(ST_DSTACK_UF, ir); return False
                addr = self.dstack[-1] & 0xFF
                if mem_protected(addr):
                    self._fault(ST_MEM_PROT, addr); return False
                val = self.dstack[-2]
                self.dstack.pop(); self.dstack.pop()
                self.mem[addr] = val
            else:
                self._fault(ST_ILLEGAL_ENC, ir); return False
            self.pc += 1

        # ---- CTRL ------------------------------------------------------
        elif op == OP_CTRL:
            # Backward branch is a hard encoding error (structural, not a mode flag)
            if not ctrl_b_legal(B):
                self._fault(ST_ILLEGAL_ENC, ir)
                return False
            tgt = ctrl_target(self.pc, B)
            if A == CTRL_JMP:
                self.pc = tgt
            elif A == CTRL_JZ:
                cond, ok = self._pop()
                if not ok: return False
                self.pc = tgt if cond == 0 else self.pc + 1
            elif A == CTRL_JNZ:
                cond, ok = self._pop()
                if not ok: return False
                self.pc = tgt if cond != 0 else self.pc + 1
            else:
                # A >= 3: CALL/RET permanently removed
                self._fault(ST_ILLEGAL_ENC, ir)
                return False

        # ---- INVOKE ----------------------------------------------------
        elif op == OP_INVOKE:
            full_id = (A << 8) | B
            if full_id not in self.prim_meta:
                self._fault(ST_UNKNOWN_INVOKE, full_id)
                return False
            meta = self.prim_meta[full_id]
            # Pre-flight stack check (must happen before any mutation)
            net = meta.pushes - meta.pops
            if len(self.dstack) + net > 256:
                self._fault(ST_DSTACK_OF, full_id); return False
            if len(self.dstack) < meta.pops:
                self._fault(ST_DSTACK_UF, full_id); return False
            # Pop args into ARG region
            for i in range(meta.pops):
                v, ok = self._pop()
                if not ok: return False
                self.mem[ARG_BASE + i] = v
            # Dispatch
            status_out = [ST_OK]
            aux_out    = [0]
            if full_id in self.prim_impl:
                self.prim_impl[full_id](self.mem, status_out, aux_out)
            self.mem[STATUS_ADDR] = u16(status_out[0])
            self.mem[AUX_ADDR]    = u16(aux_out[0])
            if status_out[0] != ST_OK:
                self.halted  = True
                self.faulted = True
                return False
            # Push results from RES region
            for i in range(meta.pushes):
                if not self._push(self.mem[RES_BASE + i]):
                    return False
            self.pc += 1

        # ---- SYS -------------------------------------------------------
        elif op == OP_SYS:
            if A == SYS_HALT:
                self.mem[STATUS_ADDR] = ST_OK
                self.mem[AUX_ADDR]    = 0
                self.halted  = True
                self.faulted = False
                return False
            elif A == SYS_TRAP:
                self._fault(ST_TRAP, B)
                return False
            else:
                self._fault(ST_ILLEGAL_ENC, ir)
                return False

        # ---- Reserved --------------------------------------------------
        else:
            self._fault(ST_ILLEGAL_ENC, ir)
            return False

        return not (self.halted or self.faulted)

    # ------------------------------------------------------------------
    # Run loop  (mirrors J16Ref::run())
    # ------------------------------------------------------------------

    def run(self, max_steps: int = 1_000_000, trace: bool = False) -> int:
        """
        Run until halt/fault or max_steps exceeded.
        Returns the step count at termination.
        If trace=True, appends one line per step to self.trace_log.
        """
        self.trace_log = []
        for _ in range(max_steps):
            if trace:
                dsp = len(self.dstack)
                tos = self.dstack[-1] if self.dstack else 0
                ir  = self.rom[self.pc] if self.pc < len(self.rom) else 0
                self.trace_log.append(
                    f"pc={self.pc:04x} ir={ir:04x} dsp={dsp:3d} "
                    f"tos={tos:04x} mem[ff]={self.mem[STATUS_ADDR]:04x}"
                )
            if not self.step():
                return self.steps
        return self.steps

    # ------------------------------------------------------------------
    # Disassembly  (one instruction → mnemonic string)
    # ------------------------------------------------------------------

    def disasm_at(self, pc: int) -> tuple[str, int]:
        """
        Disassemble the instruction at rom[pc].
        Returns (mnemonic_string, word_count).
        """
        if pc >= len(self.rom):
            return "???", 1
        ir = self.rom[pc] & 0xFFFF
        op = (ir >> 12) & 0xF
        A  = (ir >> 8)  & 0xF
        B  =  ir        & 0xFF

        if op == OP_NOP:
            return "NOP", 1
        if op == OP_LIT:
            return f"LIT 0x{(A<<8)|B:03x}", 1
        if op == OP_LIT16:
            if pc + 1 < len(self.rom):
                lit = self.rom[pc + 1] & 0xFFFF
                return f"LIT16 0x{lit:04x}", 2
            return "LIT16 ???", 2
        if op == OP_STACK:
            names = {STACK_DUP: "DUP", STACK_DROP: "DROP",
                     STACK_SWAP: "SWAP", STACK_OVER: "OVER"}
            return names.get(A, f"STACK.{A:x} ???"), 1
        if op == OP_ALU:
            names = {
                ALU_XOR: "XOR", ALU_AND: "AND", ALU_OR: "OR", ALU_NOT: "NOT",
                ALU_ADD: "ADD", ALU_SUB: "SUB",
                ALU_SHL: f"SHL {B&0xF}", ALU_SHR: f"SHR {B&0xF}",
                ALU_ROTL: f"ROTL {B&0xF}", ALU_ROTR: f"ROTR {B&0xF}",
                ALU_EQ: "EQ", ALU_LT: "LT", ALU_NEQ: "NEQ",
            }
            return names.get(A, f"ALU.{A:x} ???"), 1
        if op == OP_MEM:
            names = {MEM_LD: f"LD 0x{B:02x}", MEM_ST: f"ST 0x{B:02x}",
                     MEM_LDI: "LDI", MEM_STI: "STI"}
            return names.get(A, f"MEM.{A:x} ???"), 1
        if op == OP_CTRL:
            tgt = ctrl_target(pc, B)
            names = {CTRL_JMP: "JMP", CTRL_JZ: "JZ", CTRL_JNZ: "JNZ"}
            tag = names.get(A, f"CTRL.{A:x}")
            legal = "" if ctrl_b_legal(B) else " [ILLEGAL_BACKWARD]"
            return f"{tag} {tgt}{legal}", 1
        if op == OP_INVOKE:
            return f"INVOKE 0x{(A<<8)|B:04x}", 1
        if op == OP_SYS:
            if A == SYS_HALT: return "HALT", 1
            if A == SYS_TRAP: return f"TRAP 0x{B:02x}", 1
            return f"SYS.{A:x} ???", 1
        return f"??? 0x{ir:04x}", 1

    def disasm_program(self) -> str:
        """Disassemble the full program ROM to a string."""
        lines = []
        pc = 0
        while pc < self.prog_len:
            mnem, wc = self.disasm_at(pc)
            words = " ".join(f"{self.rom[pc+i]:04x}" for i in range(wc))
            lines.append(f"{pc:04x}  {words:<12}  {mnem}")
            pc += wc
        return "\n".join(lines)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _status_str(code: int) -> str:
    return STATUS_NAMES.get(code, f"0x{code:04x}")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="J16 v2 Python reference simulator (mirrors j16_ref_pkg.sv)"
    )
    parser.add_argument("--hex",      required=True,  help="Program hex file (.hex)")
    parser.add_argument("--primtab",  default=None,   help="Primitive table hex file (primtab.hex)")
    parser.add_argument("--trace",    action="store_true", help="Print per-step trace")
    parser.add_argument("--disasm",   action="store_true", help="Disassemble program then exit")
    parser.add_argument("--dump-mem", action="store_true", help="Dump RAM after execution")
    parser.add_argument("--dump-stack", action="store_true", help="Dump data stack after execution")
    parser.add_argument("--max-steps", type=int, default=1_000_000,
                        help="Step budget (default: 1000000)")
    args = parser.parse_args()

    sim = J16Sim()

    try:
        sim.load_hex(Path(args.hex))
    except FileNotFoundError:
        print(f"error: hex file not found: {args.hex}", file=sys.stderr)
        return 1

    if args.primtab:
        try:
            sim.load_primtab(Path(args.primtab))
        except FileNotFoundError:
            print(f"error: primtab file not found: {args.primtab}", file=sys.stderr)
            return 1

    if args.disasm:
        print(sim.disasm_program())
        return 0

    steps = sim.run(max_steps=args.max_steps, trace=args.trace)

    if args.trace:
        for line in sim.trace_log:
            print(line)

    status = sim.mem[STATUS_ADDR]
    aux    = sim.mem[AUX_ADDR]

    if not sim.faulted:
        print(f"HALT  steps={steps}  status={_status_str(status)}")
    else:
        print(f"FAULT steps={steps}  status={_status_str(status)}  aux=0x{aux:04x}")

    if args.dump_mem:
        print("\n--- RAM ---")
        for row in range(0, 256, 8):
            vals = " ".join(f"{sim.mem[row+i]:04x}" for i in range(8))
            print(f"  {row:02x}: {vals}")

    if args.dump_stack:
        print("\n--- DATA STACK (bottom → top) ---")
        for i, v in enumerate(sim.dstack):
            print(f"  [{i}] 0x{v:04x}")

    if steps >= args.max_steps and not sim.halted:
        print("warning: step budget exceeded without HALT", file=sys.stderr)
        return 2

    return 1 if sim.faulted else 0


if __name__ == "__main__":
    sys.exit(main())
