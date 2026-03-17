#!/usr/bin/env python3
"""j16asm.py — J16 v2 manifest-driven assembler

Goals (spec-lock philosophy):
  - Derive encodings (op/subop values, field widths) from docs/isa_v2.json.
  - Two-pass assembly (labels + forward branches).
  - Output a simulator-safe 16-bit $readmemh hex file (one word per line).

Supported:
  - Labels:   foo:
  - Comments: ';' or '//' or '#'
  - Directives:
      .org <addr>
      .equ <name>, <expr>
      .word <expr>
      .fill <count>, <expr>
  - Instructions:
      NOP
      LIT <imm12>
      LIT16 <imm16>
      <ALU_TAG> [<b8>]            (e.g., ADD, XOR, SHL 3, EQ)
      <STACK_TAG>                 (DUP, DROP, SWAP, OVER)
      <MEM_TAG> [<addr8>]         (LD 0x80, ST 0x80, LDI, STI)
      <CTRL_TAG> <label|expr>     (JMP/JZ/JNZ target; encodes forward rel8)
      <SYS_TAG> [<aux8>]          (HALT, TRAP 1)
      INVOKE <fid16>

Exit codes:
  0 on success, 1 on any assembly error.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


def load_symbols_aliases(path: str) -> Dict[str, dict]:
    if not path:
        return {}
    data = json.loads(open(path, 'r', encoding='utf-8').read())
    if data.get('format') != 'j16.symbol_aliases.v0':
        die(f"symbols file has wrong format: {data.get('format')}")
    syms = data.get('symbols', {}) or {}
    # normalize keys to UPPER
    return {str(k).upper(): v for k, v in syms.items()}


def _collect_local_defs(lines):
    labels = set()
    equs = set()
    for _, s in lines:
        m = _LABEL_DEF_RE.match(s)
        if m:
            labels.add(m.group(1))
        if s.lower().startswith('.equ'):
            # .equ NAME, EXPR
            parts = s.split(None, 1)
            rest = parts[1] if len(parts) == 2 else ''
            if ',' in rest:
                name = rest.split(',', 1)[0].strip()
                if _NAME_RE.match(name):
                    equs.add(name)
    return labels, equs


def expand_symbol_source(sym_name: str, sym_text: str, unique_prefix: str) -> List[str]:
    # Returns assembly lines for one expansion of sym_text.
    # - Strips comments/blank lines.
    # - Renames local labels and .equ names to avoid collisions.
    parsed = parse_source(sym_text)
    labels, equs = _collect_local_defs(parsed)
    renames = {n: f"{unique_prefix}{n}" for n in sorted(labels | equs)}

    out: List[str] = []
    for _, s in parsed:
        # rewrite label defs
        m = _LABEL_DEF_RE.match(s)
        if m:
            lab = m.group(1)
            rest = m.group(2).strip()
            lab2 = renames.get(lab, lab)
            s = f"{lab2}:" + (f" {rest}" if rest else "")
        else:
            # rewrite .equ NAME, ...
            if s.lower().startswith('.equ'):
                parts = s.split(None, 1)
                if len(parts) == 2 and ',' in parts[1]:
                    name, expr = [x.strip() for x in parts[1].split(',', 1)]
                    name2 = renames.get(name, name)
                    s = f".equ {name2}, {expr}"

        # rewrite references (whole word)
        for old, new in renames.items():
            s = re.sub(rf"\\b{re.escape(old)}\\b", new, s)
        out.append(s)

    return out


def preprocess_call_symbols(src_path: str, src_text: str, symbols: Dict[str, dict], require_certified: bool = False) -> str:
    # Expands lines of the form: CALL <SYMBOL>.
    # Note: J16 v2 has no CALL/RET ISA instruction; CALL is toolchain-level.
    if not symbols:
        return src_text

    text = src_text
    for _round in range(16):
        changed = False
        out_lines: List[str] = []
        call_id = 0
        for raw in text.splitlines():
            stripped = strip_comment(raw).strip()
            m = re.match(r'^CALL\s+([A-Za-z_][A-Za-z0-9_]*)\s*$', stripped, flags=re.IGNORECASE)
            if m:
                name = m.group(1).upper()
                if name not in symbols:
                    die(f"{src_path}: unknown symbol in CALL: {name}")
                ent = symbols[name]
                if require_certified:
                    abi = ent.get('abi') or {}
                    bud = ent.get('budget') or {}
                    if ('pops' not in abi) or ('pushes' not in abi) or ('max_cycles' not in bud and 'max_icount' not in bud):
                        die(f"{src_path}: CALL {name} requires a certified symbol entry (missing abi/budget). Run `make sym-cert` and pass --symbols build/symbols_aliases.json")
                sym_src = ent.get('src', '')
                base = os.path.dirname(os.path.abspath(src_path))
                cand1 = os.path.normpath(os.path.join(base, sym_src))
                cand2 = os.path.normpath(os.path.join(os.path.dirname(base), sym_src))
                path = cand1 if os.path.exists(cand1) else (cand2 if os.path.exists(cand2) else sym_src)
                if not os.path.exists(path):
                    die(f"{src_path}: CALL {name} refers to missing src: {sym_src}")
                sym_text = open(path, 'r', encoding='utf-8').read()
                prefix = f"__SYM_{name}_{call_id}_"
                fid = int(ent.get('fid', 0))
                out_lines.append(f"; CALL {name} (fid=0x{fid:04X}) expands {sym_src}")
                out_lines.extend(expand_symbol_source(name, sym_text, prefix))
                changed = True
                call_id += 1
            else:
                out_lines.append(raw)

        text2 = '\n'.join(out_lines)
        text = text2
        if not changed:
            break

    return text


class AsmError(Exception):
    pass


def die(msg: str) -> None:
    raise AsmError(msg)


# -------------------------- Expression eval ----------------------------

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class _ExprEval(ast.NodeVisitor):
    def __init__(self, sym: Dict[str, int]):
        self.sym = sym

    def visit_Expression(self, node: ast.Expression):
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            return int(node.value)
        if isinstance(node.value, int):
            return int(node.value)
        die(f"bad constant in expression: {node.value!r}")

    def visit_Name(self, node: ast.Name):
        if node.id not in self.sym:
            die(f"undefined symbol: {node.id}")
        return int(self.sym[node.id])

    def visit_UnaryOp(self, node: ast.UnaryOp):
        v = self.visit(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +v
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.Invert):
            return ~v
        die("unsupported unary op")

    def visit_BinOp(self, node: ast.BinOp):
        a = self.visit(node.left)
        b = self.visit(node.right)
        op = node.op
        if isinstance(op, ast.Add):
            return a + b
        if isinstance(op, ast.Sub):
            return a - b
        if isinstance(op, ast.Mult):
            return a * b
        if isinstance(op, ast.FloorDiv):
            return a // b
        if isinstance(op, ast.Mod):
            return a % b
        if isinstance(op, ast.LShift):
            return a << b
        if isinstance(op, ast.RShift):
            return a >> b
        if isinstance(op, ast.BitAnd):
            return a & b
        if isinstance(op, ast.BitOr):
            return a | b
        if isinstance(op, ast.BitXor):
            return a ^ b
        die("unsupported binary op")

    def visit_Call(self, node: ast.Call):
        die("function calls are not allowed in expressions")

    def generic_visit(self, node):
        die(f"unsupported expression node: {node.__class__.__name__}")


def eval_expr(expr: str, sym: Dict[str, int]) -> int:
    """Evaluate a small, safe expression language."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        die(f"bad expression syntax: {expr!r} ({e})")
    return int(_ExprEval(sym).visit(tree))


# ----------------------------- ISA model --------------------------------

@dataclass(frozen=True)
class ISAModel:
    word_bits: int
    op_bits: int
    a_bits: int
    b_bits: int
    op_by_family: Dict[str, int]
    subop_a_by_family_tag: Dict[str, Dict[str, int]]  # family -> TAG -> A


def load_isa(json_path: str) -> ISAModel:
    spec = json.loads(open(json_path, "r", encoding="utf-8").read())

    enc = spec.get("encoding", {})
    word_bits = int(enc.get("word_bits", 16))
    layout = enc.get("layout", {})

    def bits_of(field: str) -> int:
        try:
            hi, lo = layout[field]["bits"]
            return int(hi) - int(lo) + 1
        except Exception:
            die(f"encoding.layout.{field}.bits missing or malformed in {json_path}")

    op_bits = bits_of("op")
    a_bits = bits_of("a")
    b_bits = bits_of("b")

    op_by_family: Dict[str, int] = {}
    subop_a_by_family_tag: Dict[str, Dict[str, int]] = {}
    for insn in spec.get("instructions", []):
        fam = insn.get("family")
        if not fam:
            continue
        op = int(str(insn.get("op", "0x0")), 16)
        op_by_family[fam] = op

        tag_map: Dict[str, int] = {}
        for so in insn.get("subops", []) or []:
            tag = so.get("tag")
            a = so.get("a")
            if tag is None or a is None:
                continue
            tag_map[str(tag).upper()] = int(str(a), 16)
        if tag_map:
            subop_a_by_family_tag[fam] = tag_map

    return ISAModel(
        word_bits=word_bits,
        op_bits=op_bits,
        a_bits=a_bits,
        b_bits=b_bits,
        op_by_family=op_by_family,
        subop_a_by_family_tag=subop_a_by_family_tag,
    )


# ------------------------------ Parsing ---------------------------------

@dataclass
class LineItem:
    kind: str  # 'insn' | 'dir'
    addr: int
    words: int
    text: str
    lineno: int
    mnemonic: Optional[str] = None
    operands: Optional[str] = None
    dir_name: Optional[str] = None
    dir_args: Optional[str] = None


def strip_comment(line: str) -> str:
    for sep in ("//", ";", "#"):
        idx = line.find(sep)
        if idx != -1:
            line = line[:idx]
    return line.rstrip("\n")


_LABEL_DEF_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def parse_source(src_text: str) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for i, raw in enumerate(src_text.splitlines(), start=1):
        s = strip_comment(raw).strip()
        if not s:
            continue
        out.append((i, s))
    return out


def parse_tokens(line: str) -> Tuple[Optional[str], str]:
    m = _LABEL_DEF_RE.match(line)
    if not m:
        return None, line.strip()
    return m.group(1), m.group(2).strip()


def split_mnemonic(rest: str) -> Tuple[str, str]:
    parts = rest.split(None, 1)
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1].strip()


def insn_words(mn: str) -> int:
    return 2 if mn.upper() == "LIT16" else 1


# ------------------------------ Encoding --------------------------------

def enc_word(op: int, a: int, b: int) -> int:
    return ((op & 0xF) << 12) | ((a & 0xF) << 8) | (b & 0xFF)


def u16(x: int) -> int:
    return x & 0xFFFF


# ------------------------------ Assembler --------------------------------

def assemble(
    isa: ISAModel,
    src_path: str,
    src_text: str,
    require_halt: bool,
) -> Tuple[List[int], Dict[str, int], List[str]]:
    lines = parse_source(src_text)
    sym: Dict[str, int] = {}
    items: List[LineItem] = []
    pc = 0

    def define(name: str, value: int, lineno: int) -> None:
        if not _NAME_RE.match(name):
            die(f"{src_path}:{lineno}: invalid symbol name: {name}")
        if name in sym:
            die(f"{src_path}:{lineno}: duplicate symbol: {name}")
        sym[name] = int(value)

    # Pass 1
    for lineno, line in lines:
        label, rest = parse_tokens(line)
        if label is not None:
            define(label, pc, lineno)
        if not rest:
            continue

        if rest.startswith("."):
            dmn, dargs = split_mnemonic(rest)
            dmn = dmn.lower()

            if dmn == ".equ":
                if "," not in dargs:
                    die(f"{src_path}:{lineno}: .equ expects: .equ NAME, EXPR")
                name, expr = [x.strip() for x in dargs.split(",", 1)]
                val = eval_expr(expr, sym)
                define(name, val, lineno)
                items.append(LineItem(kind="dir", addr=pc, words=0, text=line, lineno=lineno, dir_name="equ", dir_args=dargs))
                continue

            if dmn == ".org":
                if not dargs:
                    die(f"{src_path}:{lineno}: .org expects an address")
                new_pc = eval_expr(dargs, sym)
                if new_pc < 0:
                    die(f"{src_path}:{lineno}: .org must be >= 0")
                items.append(LineItem(kind="dir", addr=pc, words=0, text=line, lineno=lineno, dir_name="org", dir_args=dargs))
                pc = int(new_pc)
                continue

            if dmn == ".word":
                if not dargs:
                    die(f"{src_path}:{lineno}: .word expects an expression")
                items.append(LineItem(kind="dir", addr=pc, words=1, text=line, lineno=lineno, dir_name="word", dir_args=dargs))
                pc += 1
                continue

            if dmn == ".fill":
                if "," not in dargs:
                    die(f"{src_path}:{lineno}: .fill expects: .fill COUNT, EXPR")
                count_expr, _ = [x.strip() for x in dargs.split(",", 1)]
                count = eval_expr(count_expr, sym)
                if count < 0:
                    die(f"{src_path}:{lineno}: .fill count must be >= 0")
                items.append(LineItem(kind="dir", addr=pc, words=int(count), text=line, lineno=lineno, dir_name="fill", dir_args=dargs))
                pc += int(count)
                continue

            die(f"{src_path}:{lineno}: unknown directive: {dmn}")

        mn, ops = split_mnemonic(rest)
        if not mn:
            continue
        w = insn_words(mn)
        items.append(LineItem(kind="insn", addr=pc, words=w, text=line, lineno=lineno, mnemonic=mn, operands=ops))
        pc += w

    # Pass 2
    max_addr = 0
    mem: Dict[int, int] = {}
    listing: List[str] = []

    def emit(addr: int, word: int, src: str) -> None:
        nonlocal max_addr
        if addr in mem:
            die(f"{src_path}: duplicate emission at address {addr} (did you overlap .org regions?)")
        mem[addr] = u16(word)
        max_addr = max(max_addr, addr)
        listing.append(f"{addr:04X}: {u16(word):04X}    {src}")

    for it in items:
        if it.kind == "dir":
            if it.dir_name == "equ" or it.dir_name == "org":
                continue
            if it.dir_name == "word":
                val = eval_expr(it.dir_args or "0", sym)
                emit(it.addr, val, it.text)
                continue
            if it.dir_name == "fill":
                assert it.dir_args is not None
                count_expr, val_expr = [x.strip() for x in it.dir_args.split(",", 1)]
                count = eval_expr(count_expr, sym)
                val = eval_expr(val_expr, sym)
                for k in range(int(count)):
                    emit(it.addr + k, val, it.text if k == 0 else "")
                continue
            die(f"{src_path}:{it.lineno}: internal: unhandled directive {it.dir_name}")

        assert it.mnemonic is not None
        mn = it.mnemonic.upper()
        ops = (it.operands or "").strip()

        if mn == "NOP":
            op = isa.op_by_family.get("NOP")
            if op is None:
                die("ISA missing NOP family")
            emit(it.addr, enc_word(op, 0, 0), it.text)
            continue

        if mn == "LIT":
            if not ops:
                die(f"{src_path}:{it.lineno}: LIT expects an immediate")
            imm = eval_expr(ops, sym)
            if not (0 <= imm <= 0xFFF):
                die(f"{src_path}:{it.lineno}: LIT immediate out of range (0..0xFFF): {imm}")
            op = isa.op_by_family.get("LIT")
            if op is None:
                die("ISA missing LIT family")
            a = (imm >> 8) & 0xF
            b = imm & 0xFF
            emit(it.addr, enc_word(op, a, b), it.text)
            continue

        if mn == "LIT16":
            if not ops:
                die(f"{src_path}:{it.lineno}: LIT16 expects an immediate")
            imm = eval_expr(ops, sym)
            if not (0 <= imm <= 0xFFFF):
                die(f"{src_path}:{it.lineno}: LIT16 immediate out of range (0..0xFFFF): {imm}")
            op = isa.op_by_family.get("LIT16")
            if op is None:
                die("ISA missing LIT16 family")
            emit(it.addr, enc_word(op, 0, 0), it.text)
            emit(it.addr + 1, imm, "")
            continue

        if mn == "INVOKE":
            if not ops:
                die(f"{src_path}:{it.lineno}: INVOKE expects a fid (0..0xFFFF)")
            fid = eval_expr(ops, sym)
            if not (0 <= fid <= 0xFFFF):
                die(f"{src_path}:{it.lineno}: INVOKE fid out of range (0..0xFFFF): {fid}")
            op = isa.op_by_family.get("INVOKE")
            if op is None:
                die("ISA missing INVOKE family")
            a = (fid >> 8) & 0xF
            b = fid & 0xFF
            emit(it.addr, enc_word(op, a, b), it.text)
            continue

        if mn in (isa.subop_a_by_family_tag.get("SYS", {}) or {}):
            op = isa.op_by_family.get("SYS")
            if op is None:
                die("ISA missing SYS family")
            a = isa.subop_a_by_family_tag["SYS"][mn]
            b = 0
            if mn == "TRAP":
                if not ops:
                    die(f"{src_path}:{it.lineno}: TRAP expects aux8")
                b = eval_expr(ops, sym)
            else:
                if ops:
                    die(f"{src_path}:{it.lineno}: {mn} takes no operands")
            if not (0 <= b <= 0xFF):
                die(f"{src_path}:{it.lineno}: SYS aux out of range (0..255): {b}")
            emit(it.addr, enc_word(op, a, b), it.text)
            continue

        if mn in (isa.subop_a_by_family_tag.get("CTRL", {}) or {}):
            if not ops:
                die(f"{src_path}:{it.lineno}: {mn} expects a target label/expression")
            op = isa.op_by_family.get("CTRL")
            if op is None:
                die("ISA missing CTRL family")
            a = isa.subop_a_by_family_tag["CTRL"][mn]
            target = eval_expr(ops, sym)
            offset = target - (it.addr + 1)
            if not (0 <= offset <= 127):
                die(
                    f"{src_path}:{it.lineno}: {mn} target out of range. "
                    f"Need 0..127 words forward; got offset={offset} to target=0x{target:X}"
                )
            emit(it.addr, enc_word(op, a, offset), it.text)
            continue

        if mn in (isa.subop_a_by_family_tag.get("MEM", {}) or {}):
            op = isa.op_by_family.get("MEM")
            if op is None:
                die("ISA missing MEM family")
            a = isa.subop_a_by_family_tag["MEM"][mn]
            b = 0
            if mn in ("LD", "ST"):
                if not ops:
                    die(f"{src_path}:{it.lineno}: {mn} expects addr8")
                b = eval_expr(ops, sym)
                if not (0 <= b <= 0xFF):
                    die(f"{src_path}:{it.lineno}: {mn} addr out of range (0..255): {b}")
            else:
                if ops:
                    die(f"{src_path}:{it.lineno}: {mn} takes no operands")
            emit(it.addr, enc_word(op, a, b), it.text)
            continue

        if mn in (isa.subop_a_by_family_tag.get("STACK", {}) or {}):
            op = isa.op_by_family.get("STACK")
            if op is None:
                die("ISA missing STACK family")
            a = isa.subop_a_by_family_tag["STACK"][mn]
            if ops:
                die(f"{src_path}:{it.lineno}: {mn} takes no operands")
            emit(it.addr, enc_word(op, a, 0), it.text)
            continue

        if mn in (isa.subop_a_by_family_tag.get("ALU", {}) or {}):
            op = isa.op_by_family.get("ALU")
            if op is None:
                die("ISA missing ALU family")
            a = isa.subop_a_by_family_tag["ALU"][mn]
            b = 0
            if ops:
                b = eval_expr(ops, sym)
                if not (0 <= b <= 0xFF):
                    die(f"{src_path}:{it.lineno}: {mn} B operand out of range (0..255): {b}")
            emit(it.addr, enc_word(op, a, b), it.text)
            continue

        die(f"{src_path}:{it.lineno}: unknown instruction: {mn}")

    if not mem:
        die("program emitted no words")

    words = [0] * (max_addr + 1)
    for addr, w in mem.items():
        words[addr] = w

    if require_halt:
        sys_op = isa.op_by_family.get("SYS")
        halt_a = (isa.subop_a_by_family_tag.get("SYS") or {}).get("HALT")
        if sys_op is None or halt_a is None:
            die("ISA missing SYS/HALT")
        if words[-1] != enc_word(sys_op, halt_a, 0):
            die("program must end with SYS HALT (F000). Add 'HALT' as the final instruction.")

    return words, sym, listing


def write_hex(path: str, words: List[int]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for w in words:
            f.write(f"{w & 0xFFFF:04X}\n")


def write_sym(path: str, sym: Dict[str, int]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for k in sorted(sym.keys()):
            f.write(f"{k} = 0x{sym[k]:X}\n")


def write_lst(path: str, listing: List[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in listing:
            f.write(line + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="J16 v2 assembler")
    ap.add_argument("--isa", required=True, help="Path to docs/isa_v2.json")
    ap.add_argument("--symbols", default="", help="Optional build/symbols_aliases.json to expand CALL <SYMBOL>")
    ap.add_argument("--require-certified-symbols", action="store_true", help="Fail assembly if any CALL <SYM> refers to an uncertified/unbudgeted symbol entry (recommended for shipping banks).")
    ap.add_argument("--in", dest="in_path", required=True, help="Input .s file")
    ap.add_argument("--out", required=True, help="Output .hex file (16-bit words)")
    ap.add_argument("--sym", default="", help="Optional output .sym file")
    ap.add_argument("--lst", default="", help="Optional output .lst file")
    ap.add_argument("--no-require-halt", action="store_true", help="Do not require final HALT")
    args = ap.parse_args()

    try:
        isa = load_isa(args.isa)
        src_text = open(args.in_path, "r", encoding="utf-8").read()
        symbols = load_symbols_aliases(args.symbols)
        if symbols:
            src_text = preprocess_call_symbols(args.in_path, src_text, symbols, require_certified=bool(args.require_certified_symbols))
        words, sym, listing = assemble(
            isa=isa,
            src_path=args.in_path,
            src_text=src_text,
            require_halt=not args.no_require_halt,
        )
        write_hex(args.out, words)
        if args.sym:
            write_sym(args.sym, sym)
        if args.lst:
            write_lst(args.lst, listing)
        return 0
    except AsmError as e:
        print(f"j16asm: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
