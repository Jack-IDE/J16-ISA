#!/usr/bin/env python3
"""primtab_pack.py — generate a simulator-safe primtab.hex for J16 v2.

Why this exists:
- $readmemh for wide words (128-bit) is easy to *silently* get wrong across simulators
  if you rely on comments, prefixes, underscores, or non-canonical formatting.
- This tool emits a canonical format: **one 32-hex-digit token per line**.

Input JSON:
- Either a top-level list of entries, or a dict with key "entries" or "primitives".
- Each entry must specify either:
  - "fid" (0..4095 recommended), or
  - "bank" (0..15) and "idx" (0..255)  => fid = (bank<<8)|idx

Fields (all optional unless noted):
  fid/bank/idx, model, unit, max_units, base_cycles, per_cycles,
  cap_id, pops, pushes, deterministic

The generated file is designed to be consumed by:
- rtl/j16_core.sv (primtab_raw -> prim_by_id)
- rtl/j16_prim_registry.sv

"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


def _parse_int(x: Any, field: str) -> int:
    if isinstance(x, bool):
        raise ValueError(f"{field}: expected int, got bool")
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip().lower()
        base = 16 if s.startswith("0x") else 10
        return int(s, base)
    raise ValueError(f"{field}: expected int or str, got {type(x)}")


def _require_range(v: int, lo: int, hi: int, field: str) -> int:
    if not (lo <= v <= hi):
        raise ValueError(f"{field}: {v} out of range [{lo}, {hi}]")
    return v


@dataclass(frozen=True)
class PrimEntry:
    fid: int
    model: int = 0
    unit: int = 0
    max_units: int = 0
    base_cycles: int = 0
    per_cycles: int = 0
    cap_id: int = 0
    pops: int = 0
    pushes: int = 0
    deterministic: int = 1

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "PrimEntry":
        if "fid" in obj:
            fid = _parse_int(obj["fid"], "fid")
        else:
            bank = _parse_int(obj.get("bank", 0), "bank")
            idx = _parse_int(obj.get("idx", 0), "idx")
            _require_range(bank, 0, 15, "bank")
            _require_range(idx, 0, 255, "idx")
            fid = (bank << 8) | idx

        fid = _require_range(fid, 0, 0xFFFF, "fid")

        model = _require_range(_parse_int(obj.get("model", 0), "model"), 0, 15, "model")
        unit = _require_range(_parse_int(obj.get("unit", 0), "unit"), 0, 15, "unit")

        max_units = _require_range(_parse_int(obj.get("max_units", 0), "max_units"), 0, 0xFFFF, "max_units")
        base_cycles = _require_range(_parse_int(obj.get("base_cycles", 0), "base_cycles"), 0, 0xFFFF, "base_cycles")
        per_cycles = _require_range(_parse_int(obj.get("per_cycles", 0), "per_cycles"), 0, 0xFFFF, "per_cycles")

        cap_id = _require_range(_parse_int(obj.get("cap_id", 0), "cap_id"), 0, 0xFF, "cap_id")
        pops = _require_range(_parse_int(obj.get("pops", 0), "pops"), 0, 0xFF, "pops")
        pushes = _require_range(_parse_int(obj.get("pushes", 0), "pushes"), 0, 0xFF, "pushes")

        det_raw = obj.get("deterministic", True)
        deterministic = 1 if bool(det_raw) else 0

        return PrimEntry(
            fid=fid,
            model=model,
            unit=unit,
            max_units=max_units,
            base_cycles=base_cycles,
            per_cycles=per_cycles,
            cap_id=cap_id,
            pops=pops,
            pushes=pushes,
            deterministic=deterministic,
        )

    def pack_u128(self) -> int:
        # Bit layout matches docs/primtab_format.md and rtl/j16_core.sv
        v = 0
        v |= (self.fid & 0xFFFF) << 112
        v |= (self.model & 0xF) << 108
        v |= (self.unit & 0xF) << 104
        v |= (self.max_units & 0xFFFF) << 88
        v |= (self.base_cycles & 0xFFFF) << 72
        v |= (self.per_cycles & 0xFFFF) << 56
        v |= (self.cap_id & 0xFF) << 48
        v |= (self.pops & 0xFF) << 40
        v |= (self.pushes & 0xFF) << 32
        v |= (self.deterministic & 0x1) << 31
        # [30:0] reserved = 0
        return v

    def annotate(self) -> str:
        return (
            f"fid=0x{self.fid:04x} model={self.model} unit={self.unit} "
            f"max_units={self.max_units} base_cycles={self.base_cycles} per_cycles={self.per_cycles} "
            f"cap_id=0x{self.cap_id:02x} pops={self.pops} pushes={self.pushes} det={self.deterministic}"
        )


def _load_entries(path: str) -> List[PrimEntry]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        raw_entries = data
    elif isinstance(data, dict):
        raw_entries = data.get("entries") or data.get("primitives") or []
    else:
        raise ValueError("JSON must be a list or an object with 'entries'/'primitives'.")

    if not isinstance(raw_entries, list):
        raise ValueError("entries/primitives must be a list")

    entries: List[PrimEntry] = []
    for i, obj in enumerate(raw_entries):
        if not isinstance(obj, dict):
            raise ValueError(f"entry[{i}] must be an object")
        entries.append(PrimEntry.from_json(obj))
    return entries


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a canonical J16 primtab.hex from JSON.")
    ap.add_argument("--json", required=True, help="Input JSON (entries or primitives list)")
    ap.add_argument("--out", required=True, help="Output primtab.hex path")
    ap.add_argument("--words", type=int, default=256, help="Number of 128-bit rows to emit (default: 256)")
    ap.add_argument("--sparse", action="store_true", help="Emit only nonzero rows (no padding)")
    ap.add_argument("--annotated-out", default=None, help="Optional human-readable companion file")
    args = ap.parse_args()

    entries = _load_entries(args.json)

    # De-dup by fid (last one wins)
    by_fid: Dict[int, PrimEntry] = {}
    for e in entries:
        by_fid[e.fid] = e

    # Stable ordering for diff-friendliness
    ordered = [by_fid[k] for k in sorted(by_fid.keys())]

    if not args.sparse and len(ordered) > args.words:
        raise SystemExit(f"Too many entries ({len(ordered)}) for --words={args.words}.")

    rows: List[int] = []
    for e in ordered:
        rows.append(e.pack_u128())

    if not args.sparse:
        while len(rows) < args.words:
            rows.append(0)

    # Write canonical primtab.hex: 32 hex digits per line
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for v in rows:
            f.write(f"{v:032x}\n")

    if args.annotated_out:
        with open(args.annotated_out, "w", encoding="utf-8", newline="\n") as f:
            for e in ordered:
                f.write(f"{e.pack_u128():032x}  // {e.annotate()}\n")


if __name__ == "__main__":
    main()
