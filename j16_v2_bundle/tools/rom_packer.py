#!/usr/bin/env python3
"""rom_packer.py (J16 v2)

Goal: produce prog.hex (readmemh-compatible) WITHOUT mnemonics and WITHOUT C.

Input formats:
1) JSON array of objects, each either:
   - {"op": <0..15>, "a": <0..15>, "b": <0..255>}
   - {"word": <0..65535>}  (explicit word)
   Values may be int or hex strings ("0xB006", "B006", etc).

2) Plain text (.ops): one instruction per line, either:
   - "op a b" as hex/decimal tokens (e.g. "B 0 06", "11 4 255")
   - a single 16-bit word token (e.g. "B006")

Optional:
- --isa <path> : load docs/isa_v2.json and validate encodings under the manifest.

Output:
- prog.hex: one 16-bit word per line, 4 hex digits uppercase.

v2 Note (LIT16):
If a word encodes OP_LIT16 (0x6, A=0, B=0), the *next* word is treated as raw
literal data and is NOT validated as an instruction encoding.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def parse_int(tok: Any) -> int:
    tok = str(tok).strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    # bare hex like "B006" or "ff"
    if re.fullmatch(r"[0-9a-fA-F]+", tok) and any(c.isalpha() for c in tok):
        return int(tok, 16)
    return int(tok, 0)


def pack_word(op: int, a: int, b: int) -> int:
    if not (0 <= op <= 15):
        raise ValueError("op out of range")
    if not (0 <= a <= 15):
        raise ValueError("a out of range")
    if not (0 <= b <= 255):
        raise ValueError("b out of range")
    return (op << 12) | (a << 8) | b


def decode_word(w: int) -> Tuple[int, int, int]:
    return ((w >> 12) & 0xF, (w >> 8) & 0xF, w & 0xFF)


class IsaManifest:
    def __init__(self, d: Dict[str, Any]):
        self.d = d
        self.allowed_ops = set()
        self.allowed_a: Dict[int, set] = {}
        self._build_tables()

        # v2: protected ranges for program-immediate MEM ops
        pr = d.get("memory_map", {}).get("protected_ranges_program_memops", [])
        self.protected_ranges: List[Tuple[int, int]] = []
        for r in pr:
            s = parse_int(r["start"])
            e = parse_int(r["end"])
            self.protected_ranges.append((s, e))

    def _build_tables(self) -> None:
        for ins in self.d.get("instructions", []):
            op = parse_int(ins["op"]) if isinstance(ins.get("op"), str) else int(ins["op"])
            self.allowed_ops.add(op)
            if "subops" in ins:
                aset = set(parse_int(s["a"]) for s in ins["subops"])
                self.allowed_a[op] = aset

    def is_protected_addr(self, addr8: int) -> bool:
        for s, e in self.protected_ranges:
            if s <= addr8 <= e:
                return True
        return False

    def validate_word(self, w: int, *, where: str = "") -> None:
        if not (0 <= w <= 0xFFFF):
            raise ValueError(f"{where}word out of range")

        op, a, b = decode_word(w)

        if op not in self.allowed_ops:
            raise ValueError(f"{where}illegal OP=0x{op:X}")
        if op in self.allowed_a and a not in self.allowed_a[op]:
            raise ValueError(f"{where}illegal A=0x{a:X} for OP=0x{op:X}")

        # v2: CTRL is forward-only. Negative rel8 is always illegal.
        if op == 0x4 and a in (0x0, 0x1, 0x2):
            if (b & 0x80) != 0:
                raise ValueError(f"{where}CTRL forbids negative rel8 (A=0x{a:X} B=0x{b:02X})")

        # v2: program MEM ops (immediate addressing) cannot target protected addresses.
        # Note: LDI/STI protected addr depends on runtime stack value; packer can't prove legality.
        if op == 0x3 and a in (0x0, 0x1):
            if self.is_protected_addr(b):
                raise ValueError(f"{where}MEM immediate access to protected addr B=0x{b:02X}")


def find_default_manifest() -> Optional[str]:
    here = os.path.abspath(os.path.dirname(__file__))
    cand = os.path.normpath(os.path.join(here, "..", "docs", "isa_v2.json"))
    return cand if os.path.exists(cand) else None


def load_manifest(path: str) -> IsaManifest:
    d = json.load(open(path, "r", encoding="utf-8"))
    if not isinstance(d, dict) or d.get("manifest", {}).get("kind") != "isa_manifest":
        raise ValueError("invalid ISA manifest")
    if d.get("manifest", {}).get("name") not in ("J16-ISA", "J16"):
        # don't be overly strict; just require kind.
        pass
    return IsaManifest(d)


def _load_program_tokens(path: str) -> List[Dict[str, Any]]:
    data = json.load(open(path, "r", encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON input must be an array")
    return data


def load_json(path: str) -> List[int]:
    out: List[int] = []
    data = _load_program_tokens(path)
    for i, ins in enumerate(data):
        where = f"entry {i}: "
        if not isinstance(ins, dict):
            raise ValueError(where + "must be object")
        if "word" in ins:
            w = parse_int(ins["word"]) & 0xFFFF
            out.append(w)
        else:
            op = parse_int(ins.get("op"))
            a = parse_int(ins.get("a"))
            b = parse_int(ins.get("b"))
            out.append(pack_word(op, a, b) & 0xFFFF)
    return out


def load_ops(path: str) -> List[int]:
    out: List[int] = []
    for ln, line in enumerate(open(path, "r", encoding="utf-8"), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        toks = re.split(r"\s+", line)
        where = f"line {ln}: "
        if len(toks) == 1:
            out.append(parse_int(toks[0]) & 0xFFFF)
        elif len(toks) == 3:
            op = parse_int(toks[0])
            a = parse_int(toks[1])
            b = parse_int(toks[2])
            out.append(pack_word(op, a, b) & 0xFFFF)
        else:
            raise ValueError(where + "expected 1 token (word) or 3 tokens (op a b)")
    return out


def validate_program_v2(words: List[int], isa: IsaManifest) -> None:
    OP_LIT16 = 0x6
    pending_lit16 = False

    for i, w in enumerate(words):
        if pending_lit16:
            pending_lit16 = False
            continue

        op, a, b = decode_word(w)
        where = f"word[{i}]: "
        isa.validate_word(w, where=where)

        if op == OP_LIT16:
            # encoding must be exact (A=0, B=0) per manifest.
            if a != 0 or b != 0:
                raise ValueError(f"{where}illegal LIT16 encoding")
            if i + 1 >= len(words):
                raise ValueError(f"{where}LIT16 missing following data word")
            pending_lit16 = True


def write_hex(words: List[int], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for w in words:
            f.write(f"{w & 0xFFFF:04X}\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="program.json or program.ops")
    ap.add_argument("-o", "--out", default="prog.hex")
    ap.add_argument("--isa", default=None, help="path to docs/isa_v2.json")
    args = ap.parse_args()

    isa_path = args.isa or find_default_manifest()
    isa = load_manifest(isa_path) if isa_path else None

    if args.input.lower().endswith(".json"):
        words = load_json(args.input)
    else:
        words = load_ops(args.input)

    if isa:
        validate_program_v2(words, isa)

    write_hex(words, args.out)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
