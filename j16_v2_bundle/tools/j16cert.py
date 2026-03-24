#!/usr/bin/env python3
"""
j16cert.py — J16 v2 Python Static Certifier

Direct port of j16_certifier.sv.  Behaviour is normative: any divergence
from the SV certifier is a bug in this file.

Three-pass analysis:
  Pass 1 — encoding legality, LIT16 data-word marking, INVOKE allowlist /
            capability / budget checks, CTRL target range checks.
  Pass 2 — forward stack-depth propagation; proves unique, consistent depth
            at every reachable instruction.
  Pass 3 — reverse DP; proves every reachable instruction can reach HALT,
            computes worst-case instruction count and cycle budget.

Outputs a JSON certificate compatible with the SV certifier's EMIT_CERT_JSON
format (schema "j16_cert_v2").

Usage:
    python3 tools/j16cert.py --hex prog.hex
    python3 tools/j16cert.py --hex prog.hex --primtab primtab.hex
    python3 tools/j16cert.py --hex prog.hex --primtab primtab.hex \\
                             --allowfile allow_prims.hex
    python3 tools/j16cert.py --hex prog.hex --allow-all-invoke
    python3 tools/j16cert.py --hex prog.hex --prog-len 12

Exit codes:
    0  certification passed
    1  certification failed (or bad arguments)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# ISA constants  (mirrors j16_isa.svh)
# ---------------------------------------------------------------------------

OP_NOP    = 0x0
OP_ALU    = 0x1
OP_LIT    = 0x2
OP_MEM    = 0x3
OP_CTRL   = 0x4
OP_STACK  = 0x5
OP_LIT16  = 0x6
OP_INVOKE = 0xB
OP_SYS    = 0xF

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

# ALU_VALID_MASK = 0x1FFF — bits 0..12 set (A in 0x0..0xC are valid)
ALU_VALID_MASK = 0x1FFF

MEM_LD  = 0x0
MEM_ST  = 0x1
MEM_LDI = 0x2
MEM_STI = 0x3

STACK_DUP  = 0x0
STACK_DROP = 0x1
STACK_SWAP = 0x2
STACK_OVER = 0x3

CTRL_JMP = 0x0
CTRL_JZ  = 0x1
CTRL_JNZ = 0x2

SYS_HALT = 0x0
SYS_TRAP = 0x1

# Memory map (frozen)
PROT_LO_END   = 0x3F   # 0x00..0x3F  protected (ARG/RES)
PROT_HI_START = 0xFE   # 0xFE..0xFF  protected (AUX/STATUS)

# Canonical HALT encoding: OP=SYS (0xF), A=SYS_HALT (0x0), B=0x00
HALT_WORD = 0xF000

# Architectural stack depth limit
DSTACK_MAX = 256

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

# Certifier-only status codes (tooling, not architectural)
ST_CERT_NO_HALT_TERM = 0xF101
ST_CERT_TAIL_NONZERO = 0xF102

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
    ST_CERT_NO_HALT_TERM: "ST_CERT_NO_HALT_TERM",
    ST_CERT_TAIL_NONZERO: "ST_CERT_TAIL_NONZERO",
}

# Default core cycle cost (FETCH + EXEC)
CORE_CYCLES_PER_INSN = 2

# ---------------------------------------------------------------------------
# Helpers  (mirror j16_isa_pkg helper functions)
# ---------------------------------------------------------------------------

def sext8(b: int) -> int:
    """Sign-extend 8-bit value to Python int."""
    b = b & 0xFF
    return b if b < 0x80 else b - 0x100


def ctrl_target(pc: int, b: int) -> int:
    """Branch target = (pc + 1) + sext8(b).  Always forward when b[7]=0."""
    return pc + 1 + sext8(b)


def ctrl_b_legal(b: int) -> bool:
    """Forward-only constraint: B[7] must be 0."""
    return (b & 0x80) == 0


def mem_protected(addr: int) -> bool:
    addr = addr & 0xFF
    return addr <= PROT_LO_END or addr >= PROT_HI_START


def load_readmemh(path: Path, max_words: int = 1024) -> list[int]:
    """
    Parse a $readmemh-compatible hex file.
    Supports one value per line, optional // ; # comments, @address directives.
    Returns a flat list of integers zero-padded to max_words.
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
                    print(f"CERT WARN: @address directive 0x{cursor:x} in {path.name} "
                          f"is >= max_words ({max_words}); subsequent words will be discarded.",
                          file=sys.stderr)
                continue
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


def load_primtab(path: Path) -> dict[int, PrimMeta]:
    """
    Load a primtab.hex file (128-bit rows: 32 hex chars per line).
    Returns a dict keyed by full_id.
    """
    result: dict[int, PrimMeta] = {}
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.split("//")[0].strip()
            if not line:
                continue
            try:
                row = int(line, 16)
            except ValueError:
                print(f"CERT WARN: primtab line {lineno}: bad hex '{line}'",
                      file=sys.stderr)
                continue
            if row == 0:
                continue
            meta = PrimMeta.from_row128(row)
            if not meta.deterministic:
                print(f"CERT WARN: primtab line {lineno}: fid=0x{meta.full_id:04x} "
                      f"is non-deterministic, skipping", file=sys.stderr)
                continue
            result[meta.full_id] = meta
    return result


def load_allowfile(path: Path, max_words: int = 256) -> set[int]:
    """Load a $readmemh allowfile of 16-bit full_ids.  Returns a set of ints."""
    words = load_readmemh(path, max_words=max_words)
    return {w for w in words if w != 0}


# ---------------------------------------------------------------------------
# Encoding analysis helpers  (mirror j16_certifier.sv functions)
# ---------------------------------------------------------------------------

def is_term(w: int) -> bool:
    """True iff w is a canonical SYS HALT word (0xF000).  Only clean HALT terminates."""
    return w == HALT_WORD


def is_legal_enc(w: int) -> bool:
    """
    Encoding-level legality check.  Mirrors j16_certifier.sv::is_legal_enc().
    Does not check INVOKE existence/determinism — those are checked separately.
    """
    op = (w >> 12) & 0xF
    A  = (w >> 8)  & 0xF
    B  =  w        & 0xFF

    if op == OP_NOP:
        return A == 0 and B == 0

    if op == OP_ALU:
        # ALU_VALID_MASK bit[A] must be set (A in 0x0..0xC)
        return bool((ALU_VALID_MASK >> A) & 1)

    if op == OP_LIT:
        return True  # any 12-bit immediate is legal

    if op == OP_MEM:
        if A > MEM_STI:
            return False
        # Direct-address ops: B must be in user region
        if A in (MEM_LD, MEM_ST):
            if B <= PROT_LO_END or B >= PROT_HI_START:
                return False
        return True

    if op == OP_CTRL:
        if not ctrl_b_legal(B):   # backward branch — structural encoding error
            return False
        if A >= 0x3:               # CALL/RET slots permanently removed
            return False
        return True

    if op == OP_STACK:
        return A <= STACK_OVER

    if op == OP_LIT16:
        return A == 0 and B == 0

    if op == OP_INVOKE:
        return True  # existence/determinism checked in Pass 1 separately

    if op == OP_SYS:
        return A in (SYS_HALT, SYS_TRAP)

    return False  # reserved opcode


def stack_effect(w: int, prim: Optional[PrimMeta]) -> tuple[int, int]:
    """
    Returns (net, need) for instruction word w.
    net  — net change to stack depth after instruction commits.
    need — minimum stack depth required before instruction.
    Mirrors j16_certifier.sv::stack_effect().
    """
    op = (w >> 12) & 0xF
    A  = (w >> 8)  & 0xF

    if op == OP_NOP:
        return 0, 0

    if op == OP_LIT:
        return 1, 0

    if op == OP_LIT16:
        return 1, 0

    if op == OP_STACK:
        if A == STACK_DUP:   return  1, 1
        if A == STACK_DROP:  return -1, 1
        if A == STACK_SWAP:  return  0, 2
        if A == STACK_OVER:  return  1, 2
        return 0, 0  # unreachable after is_legal_enc

    if op == OP_ALU:
        # Unary: NOT, SHL, SHR, ROTL, ROTR
        if A in (ALU_NOT, ALU_SHL, ALU_SHR, ALU_ROTL, ALU_ROTR):
            return 0, 1
        # Binary: everything else
        return -1, 2

    if op == OP_MEM:
        if A == MEM_LD:   return  1, 0
        if A == MEM_ST:   return -1, 1
        if A == MEM_LDI:  return  0, 1   # pop addr, push mem[addr] — net 0
        if A == MEM_STI:  return -2, 2
        return 0, 0  # unreachable

    if op == OP_CTRL:
        if A == CTRL_JMP:  return  0, 0
        # JZ / JNZ consume the condition word
        return -1, 1

    if op == OP_INVOKE:
        assert prim is not None
        return prim.pushes - prim.pops, prim.pops

    if op == OP_SYS:
        return 0, 0

    return 0, 0  # unreachable


def own_cycle_cost(w: int, prim: Optional[PrimMeta],
                   core_cpi: int = CORE_CYCLES_PER_INSN) -> int:
    """
    Cycle cost of a single instruction, matching the SV certifier's model.

      Normal instruction:  core_cpi
      LIT16:               core_cpi + 2  (extra ROM fetch stall)
      INVOKE model=0:      base_cycles + pops + pushes + core_cpi + 2
                           (+2 for S_INV_ARG exit + S_INV_RES exit drain cycles)
      INVOKE model≠0:      base_cycles + per_cycles*max_units + pops + pushes + core_cpi + 2
    """
    op = (w >> 12) & 0xF

    if op == OP_INVOKE:
        assert prim is not None
        prim_budget = prim.base_cycles
        if prim.model != 0:
            prim_budget += prim.per_cycles * prim.max_units
        return prim_budget + prim.pops + prim.pushes + core_cpi + 2

    if op == OP_LIT16:
        return core_cpi + 2

    return core_cpi


# ---------------------------------------------------------------------------
# Certificate result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CertResult:
    ok:          bool
    prog_len:    int
    max_icount:  int
    max_cycles:  int
    fail_status: int = ST_OK
    fail_pc:     int = 0
    fail_word:   int = 0
    fail_msg:    str = ""
    dsp_at:      list[int] = None   # type: ignore[assignment]
    is_data:     list[bool] = None  # type: ignore[assignment]

    def to_dict(self) -> dict:
        if self.ok:
            return {
                "schema":     "j16_cert_v2",
                "ok":         True,
                "prog_len":   self.prog_len,
                "max_icount": self.max_icount,
                "max_cycles": self.max_cycles,
                # data words get sentinel value -2 (matches SV certifier output)
                "dsp_at":  [-2 if self.is_data[i] else self.dsp_at[i]
                             for i in range(self.prog_len)],
                "is_data": [1 if self.is_data[i] else 0
                            for i in range(self.prog_len)],
            }
        else:
            return {
                "schema":      "j16_cert_v2",
                "ok":          False,
                "fail_status": f"0x{self.fail_status:04x}",
                "fail_status_name": STATUS_NAMES.get(self.fail_status,
                                                     f"0x{self.fail_status:04x}"),
                "fail_pc":     self.fail_pc,
                "fail_word":   f"0x{self.fail_word:04x}",
                "fail_msg":    self.fail_msg,
            }


# ---------------------------------------------------------------------------
# Main certifier
# ---------------------------------------------------------------------------

def certify(
    rom:              list[int],
    primtab:          dict[int, PrimMeta],
    *,
    prog_len:         int  = 0,       # 0 = AUTO_LEN
    allow_all_invoke: bool = False,
    allow_set:        Optional[set[int]] = None,  # None = use default
    allow_caps:       int  = (1 << 256) - 1,      # all caps allowed
    core_cpi:         int  = CORE_CYCLES_PER_INSN,
) -> CertResult:
    """
    Run the three-pass static certifier.  Mirrors j16_certifier.sv::CERTIFY.

    Parameters
    ----------
    rom              : list[int] — flat 16-bit ROM words (length >= prog_len)
    primtab          : dict full_id → PrimMeta
    prog_len         : explicit length; 0 triggers AUTO_LEN
    allow_all_invoke : skip the allowlist check entirely
    allow_set        : set of allowed full_ids; None → use default bank-0 range
    allow_caps       : 256-bit bitmask of allowed cap_ids (as Python int)
    core_cpi         : core cycles per instruction (default 2)
    """
    max_words = len(rom)

    # -----------------------------------------------------------------------
    # Determine prog_len
    # -----------------------------------------------------------------------
    if prog_len != 0:
        length = min(prog_len, max_words)
    else:
        # AUTO_LEN: find last SYS HALT, reject nonzero tail
        halt_idx = -1
        for i in range(max_words - 1, -1, -1):
            if rom[i] == HALT_WORD:
                halt_idx = i
                break

        if halt_idx < 0:
            return CertResult(
                ok=False, prog_len=0, max_icount=0, max_cycles=0,
                fail_status=ST_CERT_NO_HALT_TERM, fail_pc=0, fail_word=0,
                fail_msg="AUTO_LEN requires a terminating SYS HALT (0xF000) within ROM.",
                dsp_at=[], is_data=[],
            )

        for i in range(halt_idx + 1, max_words):
            if rom[i] != 0:
                return CertResult(
                    ok=False, prog_len=halt_idx + 1, max_icount=0, max_cycles=0,
                    fail_status=ST_CERT_TAIL_NONZERO,
                    fail_pc=i, fail_word=rom[i],
                    fail_msg=(f"Nonzero ROM word after terminating HALT at "
                              f"word[{halt_idx}]: word[{i}]=0x{rom[i]:04x}"),
                    dsp_at=[], is_data=[],
                )

        length = halt_idx + 1

    if length == 0:
        length = 1

    # Final HALT terminator check
    if rom[length - 1] != HALT_WORD:
        return CertResult(
            ok=False, prog_len=length, max_icount=0, max_cycles=0,
            fail_status=ST_CERT_NO_HALT_TERM,
            fail_pc=length - 1, fail_word=rom[length - 1],
            fail_msg=(f"Program must end with SYS HALT (0xF000). "
                      f"word[{length-1}]=0x{rom[length-1]:04x}"),
            dsp_at=[], is_data=[],
        )

    # -----------------------------------------------------------------------
    # Build allowlist  (mirrors SV certifier's allow_set logic)
    # -----------------------------------------------------------------------
    if allow_all_invoke:
        effective_allow: Optional[set[int]] = None  # sentinel: skip check
    elif allow_set is not None:
        effective_allow = allow_set
    else:
        # Default: bank-0 primitives 0x0000..0x001F
        effective_allow = {(0 << 8) | i for i in range(32)}

    # -----------------------------------------------------------------------
    # Per-instruction analysis arrays
    # Sized to max_words (mirrors SV certifier's PROG_WORDS-sized arrays)
    # so that pc_next references beyond `length` stay at their init values
    # (False / -1 / 0) and are caught by the can_halt final check rather
    # than raising an IndexError.
    # -----------------------------------------------------------------------
    dsp_at:     list[int]  = [-1]    * max_words   # -1 = unreachable / unset
    is_data:    list[bool] = [False] * max_words
    reach:      list[bool] = [False] * max_words
    can_halt:   list[bool] = [False] * max_words
    icount_at:  list[int]  = [0]     * max_words
    cycles_at:  list[int]  = [0]     * max_words

    def fail(status: int, pc: int, w: int, msg: str = "") -> CertResult:
        return CertResult(
            ok=False, prog_len=length, max_icount=0, max_cycles=0,
            fail_status=status, fail_pc=pc, fail_word=w,
            fail_msg=msg or STATUS_NAMES.get(status, f"0x{status:04x}"),
            dsp_at=dsp_at, is_data=is_data,
        )

    # -----------------------------------------------------------------------
    # PASS 1 — encoding legality, LIT16 data-word marking, INVOKE checks,
    #           CTRL target range validation
    # -----------------------------------------------------------------------
    for i in range(length):
        if is_data[i]:
            continue  # skip LIT16 data words

        w  = rom[i] & 0xFFFF
        op = (w >> 12) & 0xF
        A  = (w >> 8)  & 0xF
        B  =  w        & 0xFF

        if not is_legal_enc(w):
            return fail(ST_ILLEGAL_ENC, i, w,
                        f"Illegal encoding at PC {i}: 0x{w:04x}")

        # LIT16: mark the following word as a data word (not an instruction)
        if op == OP_LIT16:
            if i + 1 >= length:
                return fail(ST_PC_OOB, i, w,
                            f"LIT16 at PC {i} has no data word within prog_len")
            is_data[i + 1] = True

        # INVOKE: allowlist, registry, determinism, capability, budget
        if op == OP_INVOKE:
            fid = (A << 8) | B

            if effective_allow is not None and fid not in effective_allow:
                return fail(ST_UNKNOWN_INVOKE, i, w,
                            f"INVOKE 0x{fid:04x} at PC {i} not in allowlist")

            if fid not in primtab:
                return fail(ST_UNKNOWN_INVOKE, i, w,
                            f"INVOKE 0x{fid:04x} at PC {i} not in primtab")

            prim = primtab[fid]

            if not prim.deterministic:
                return fail(ST_ILLEGAL_ENC, i, w,
                            f"INVOKE 0x{fid:04x} at PC {i} is non-deterministic")

            if not ((allow_caps >> prim.cap_id) & 1):
                return fail(ST_UNKNOWN_INVOKE, i, w,
                            f"INVOKE 0x{fid:04x} at PC {i}: cap_id {prim.cap_id} denied")

            # Budget must be non-zero (zero budget → immediate timeout)
            if prim.model == 0:
                budget = prim.base_cycles
            else:
                budget = prim.base_cycles + prim.per_cycles * prim.max_units
            if budget == 0:
                return fail(ST_ILLEGAL_ENC, i, w,
                            f"INVOKE 0x{fid:04x} at PC {i} has zero cycle budget")

        # CTRL: target must be within [0, length), not a data word
        if op == OP_CTRL:
            tgt = ctrl_target(i, B)
            if tgt < 0 or tgt >= length or is_data[tgt]:
                return fail(ST_ILLEGAL_ENC, i, w,
                            f"CTRL at PC {i}: target {tgt} out of range or points at data word")

    # -----------------------------------------------------------------------
    # PASS 2 — forward stack-depth propagation
    # -----------------------------------------------------------------------
    dsp_at[0] = 0
    reach[0]  = True

    for i in range(length):
        if is_data[i] or not reach[i]:
            continue

        if dsp_at[i] < 0:
            # Reached but depth unknown — internal analysis error
            return fail(ST_ILLEGAL_ENC, i, rom[i] & 0xFFFF,
                        f"Reached PC {i} without a known stack depth (internal error)")

        w  = rom[i] & 0xFFFF
        op = (w >> 12) & 0xF
        A  = (w >> 8)  & 0xF
        B  =  w        & 0xFF

        cur  = dsp_at[i]
        prim = primtab.get((A << 8) | B) if op == OP_INVOKE else None

        net, need = stack_effect(w, prim)

        # Stack underflow check
        if cur < need:
            return fail(ST_DSTACK_UF, i, w,
                        f"Stack underflow at PC {i}: depth={cur}, need={need}")

        # Stack overflow check
        if cur + net > DSTACK_MAX:
            return fail(ST_DSTACK_OF, i, w,
                        f"Stack overflow at PC {i}: depth after={cur + net}")

        after = cur + net

        # Terminal instruction — no successors to propagate to
        if is_term(w):
            continue

        # Determine successor PC(s)
        pc_next = (i + 2) if op == OP_LIT16 else (i + 1)

        if op == OP_CTRL:
            tgt = ctrl_target(i, B)

            if A == CTRL_JMP:
                # Unconditional: only tgt is reachable
                successors = [tgt]
            else:
                # Conditional: fall-through and branch target both reachable
                successors = [pc_next, tgt]

        else:
            successors = [pc_next]

        for dst in successors:
            if not reach[dst]:
                reach[dst]  = True
                dsp_at[dst] = after
            elif dsp_at[dst] != after:
                return fail(
                    ST_DSTACK_UF, i, w,
                    f"Conflicting stack depths at PC {dst}: "
                    f"already {dsp_at[dst]}, now arriving with {after}",
                )

    # -----------------------------------------------------------------------
    # PASS 3 — reverse DP: can_halt + worst-case icount / cycle budget
    # -----------------------------------------------------------------------
    for i in range(length - 1, -1, -1):
        if is_data[i] or not reach[i]:
            can_halt[i]  = False
            icount_at[i] = 0
            cycles_at[i] = 0
            continue

        w  = rom[i] & 0xFFFF
        op = (w >> 12) & 0xF
        A  = (w >> 8)  & 0xF
        B  =  w        & 0xFF

        prim     = primtab.get((A << 8) | B) if op == OP_INVOKE else None
        own_cost = own_cycle_cost(w, prim, core_cpi)

        if is_term(w):
            can_halt[i]  = True
            icount_at[i] = 1
            cycles_at[i] = own_cost
            continue

        if op == OP_CTRL:
            pc_next = i + 1
            tgt     = ctrl_target(i, B)

            if A == CTRL_JMP:
                # Unconditional: only path is through tgt
                can_halt[i] = can_halt[tgt]
                if can_halt[i]:
                    icount_at[i] = 1 + icount_at[tgt]
                    cycles_at[i] = own_cost + cycles_at[tgt]

            else:
                # Conditional: worst case over both branches
                ok1 = can_halt[pc_next]
                ok2 = can_halt[tgt]
                can_halt[i] = ok1 and ok2
                if can_halt[i]:
                    worst_icount = max(icount_at[pc_next], icount_at[tgt])
                    worst_cycles = max(cycles_at[pc_next], cycles_at[tgt])
                    icount_at[i] = 1 + worst_icount
                    cycles_at[i] = own_cost + worst_cycles

        else:
            # Sequential (including LIT16 which skips 2 words)
            pc_next = (i + 2) if op == OP_LIT16 else (i + 1)
            can_halt[i]  = can_halt[pc_next]
            if can_halt[i]:
                icount_at[i] = 1 + icount_at[pc_next]
                cycles_at[i] = own_cost + cycles_at[pc_next]

    # Every reachable instruction must reach HALT
    for i in range(length):
        if is_data[i] or not reach[i]:
            continue
        if not can_halt[i]:
            return fail(ST_ILLEGAL_ENC, i, rom[i] & 0xFFFF,
                        f"Reachable instruction at PC {i} has no path to HALT")

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------
    return CertResult(
        ok=True,
        prog_len=length,
        max_icount=icount_at[0],
        max_cycles=cycles_at[0],
        dsp_at=dsp_at,
        is_data=is_data,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="J16 v2 Python static certifier (mirrors j16_certifier.sv)"
    )
    parser.add_argument("--hex",       required=True,
                        help="Program hex file (.hex)")
    parser.add_argument("--primtab",   default=None,
                        help="Primitive table hex file (primtab.hex)")
    parser.add_argument("--allowfile", default=None,
                        help="INVOKE allowlist hex file (allow_prims.hex)")
    parser.add_argument("--allow-all-invoke", action="store_true",
                        help="Skip INVOKE allowlist check entirely")
    parser.add_argument("--prog-len",  type=int, default=0,
                        help="Explicit program length (0 = AUTO_LEN)")
    parser.add_argument("--core-cpi",  type=int, default=CORE_CYCLES_PER_INSN,
                        help=f"Core cycles per instruction (default {CORE_CYCLES_PER_INSN})")
    parser.add_argument("--no-cert-json", action="store_true",
                        help="Suppress JSON certificate output")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress all output except exit code")
    args = parser.parse_args()

    # Load ROM
    try:
        rom = load_readmemh(Path(args.hex), max_words=1024)
    except FileNotFoundError:
        print(f"error: hex file not found: {args.hex}", file=sys.stderr)
        return 1

    # Load primitive table
    primtab: dict[int, PrimMeta] = {}
    if args.primtab:
        try:
            primtab = load_primtab(Path(args.primtab))
        except FileNotFoundError:
            print(f"error: primtab file not found: {args.primtab}", file=sys.stderr)
            return 1

    # Load allowfile
    allow_set: Optional[set[int]] = None
    if args.allowfile:
        try:
            allow_set = load_allowfile(Path(args.allowfile))
        except FileNotFoundError:
            print(f"error: allowfile not found: {args.allowfile}", file=sys.stderr)
            return 1

    # Run certifier
    result = certify(
        rom,
        primtab,
        prog_len=args.prog_len,
        allow_all_invoke=args.allow_all_invoke,
        allow_set=allow_set,
        core_cpi=args.core_cpi,
    )

    if args.quiet:
        return 0 if result.ok else 1

    if not args.no_cert_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.ok:
            print(f"CERT OK  prog_len={result.prog_len}  "
                  f"max_icount={result.max_icount}  max_cycles={result.max_cycles}")
        else:
            sname = STATUS_NAMES.get(result.fail_status,
                                     f"0x{result.fail_status:04x}")
            print(f"CERT FAIL  status={sname}  "
                  f"pc={result.fail_pc}  word=0x{result.fail_word:04x}  "
                  f"msg={result.fail_msg}")

    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
