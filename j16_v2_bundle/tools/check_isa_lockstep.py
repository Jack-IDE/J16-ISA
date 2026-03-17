#!/usr/bin/env python3
"""
check_isa_lockstep.py  —  J16 v2 ISA drift checker.

Verifies that j16_isa.svh (and rtl/j16_isa.svh) matches the canonical
isa_v2.json manifest. Fails with a nonzero exit code if any constant
in the JSON does not appear correctly in the SVH, or if any v1 remnants
(CALL, RET, PROFILE_T, ST_J16T_VIOL, RSTACK) are present.

Usage:
  python3 check_isa_lockstep.py \
    --json docs/isa_v2.json \
    --svh  j16_isa.svh \
    --svh-rtl rtl/j16_isa.svh
"""
import argparse
import json
import re
import sys


FORBIDDEN_V1_REMNANTS = [
    "CTRL_CALL",
    "CTRL_RET",
    "PROFILE_T",
    "ST_J16T_VIOL",
    "ST_RSTACK_UF",
    "ST_RSTACK_OF",
    "RSTACK",
]

def load_svh_constants(path):
    """Extract all localparam name=value pairs from a SystemVerilog package."""
    constants = {}
    with open(path) as f:
        text = f.read()
    # Match: localparam [optional-type-including-brackets] NAME = VALUE;
    # Type can be: logic [N:0], int unsigned, bit, etc.
    # Strategy: skip everything between 'localparam' and the last identifier before '='
    pattern = re.compile(
        r'localparam\b[^;]*?\b([A-Z_][A-Z_0-9]*)\s*=\s*([^;]+);',
        re.MULTILINE
    )
    for m in pattern.finditer(text):
        name  = m.group(1).strip()
        value = m.group(2).strip()
        # Normalise SV literals: 4'h0 -> 0, 16'hABCD -> 43981, 4'b1011 -> 11
        value = re.sub(r"\d+'h([0-9a-fA-F]+)", lambda mm: str(int(mm.group(1), 16)), value)
        value = re.sub(r"\d+'b([01]+)",          lambda mm: str(int(mm.group(1), 2)),  value)
        # Strip comments
        value = re.sub(r'//.*', '', value).strip()
        constants[name] = value
    return constants


def check_constant(svh_consts, name, expected_hex, errors, svh_path):
    """Verify a named constant exists and has the expected hex value."""
    if name not in svh_consts:
        errors.append(f"{svh_path}: MISSING constant '{name}' (expected 0x{expected_hex:04X})")
        return
    actual = svh_consts[name].strip()
    try:
        if actual.startswith("0x") or actual.startswith("0X"):
            actual_int = int(actual, 16)
        elif actual.lstrip('-').isdigit():
            actual_int = int(actual)
        else:
            actual_int = int(actual, 0)
    except ValueError:
        errors.append(f"{svh_path}: constant '{name}' has non-numeric value '{actual}'")
        return
    if actual_int != expected_hex:
        errors.append(
            f"{svh_path}: '{name}' = 0x{actual_int:04X}, expected 0x{expected_hex:04X}"
        )


def check_forbidden(svh_consts, svh_path, errors):
    """Fail if any v1 remnants appear in the SVH."""
    for name in FORBIDDEN_V1_REMNANTS:
        if name in svh_consts:
            errors.append(
                f"{svh_path}: FORBIDDEN v1 remnant '{name}' found — must not exist in J16 v2"
            )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json",    required=True)
    ap.add_argument("--svh",     required=True)
    ap.add_argument("--svh-rtl", required=False, default=None)
    args = ap.parse_args()

    with open(args.json) as f:
        spec = json.load(f)

    errors = []

    # Build expected constant table from JSON
    expected = {}

    # ------------------------------------------------------------------
    # Encoding geometry (spec-lock)
    # ------------------------------------------------------------------
    enc = spec.get("encoding", {}) or {}
    try:
        expected["J16_WORD_BITS"] = int(enc.get("word_bits", 0))
    except Exception:
        errors.append("JSON: encoding.word_bits missing or invalid")

    layout = enc.get("layout", {}) or {}
    for field_name, sv_name in (
        ("op", "J16_OP_BITS"),
        ("a",  "J16_A_BITS"),
        ("b",  "J16_B_BITS"),
    ):
        try:
            bits = (layout.get(field_name, {}) or {}).get("bits", None)
            if not (isinstance(bits, list) and len(bits) == 2):
                raise ValueError("bits must be [hi, lo]")
            hi, lo = int(bits[0]), int(bits[1])
            if hi < lo:
                raise ValueError("hi < lo")
            expected[sv_name] = (hi - lo + 1)
        except Exception:
            errors.append(f"JSON: encoding.layout.{field_name}.bits missing/invalid")

    # Opcodes
    op_names = {
        "NOP":    0x0, "ALU":   0x1, "LIT":    0x2, "MEM":    0x3,
        "CTRL":   0x4, "STACK": 0x5, "LIT16":  0x6, "INVOKE": 0xB,
        "SYS":    0xF,
    }
    for tag, val in op_names.items():
        expected[f"OP_{tag}"] = val

    # Instruction subops (ALU/MEM/STACK/CTRL/SYS)
    # The JSON is canonical; SVH must mirror it exactly.
    subop_prefix = {
        "0x1": "ALU_",
        "0x3": "MEM_",
        "0x4": "CTRL_",
        "0x5": "STACK_",
        "0xF": "SYS_",
    }

    def find_insn(op_hex: str):
        for insn in spec.get("instructions", []):
            if insn.get("op") == op_hex:
                return insn
        return None

    # ALU mask computed from the manifest (spec-lock)
    alu_mask = 0

    for op_hex, prefix in subop_prefix.items():
        insn = find_insn(op_hex)
        if not insn:
            errors.append(f"JSON: missing instruction entry for op={op_hex}")
            continue
        for so in insn.get("subops", []) or []:
            tag = str(so.get("tag", "")).strip()
            a_hex = so.get("a", None)
            if not tag or a_hex is None:
                errors.append(f"JSON: malformed subop for op={op_hex}: {so}")
                continue
            name = f"{prefix}{tag.upper()}"
            try:
                aval = int(str(a_hex), 16)
            except Exception:
                errors.append(f"JSON: bad subop 'a' value for {name}: {a_hex}")
                continue
            expected[name] = aval
            if op_hex == "0x1" and 0 <= aval < 16:
                alu_mask |= (1 << aval)

    # ALU_VALID_MASK must match the derived bitmask
    expected["ALU_VALID_MASK"] = alu_mask

    # INVOKE ABI dimensions (max args/rets)
    inv = find_insn("0xB")
    if inv and isinstance(inv.get("abi"), dict):
        abi = inv["abi"]
        if "max_args" in abi:
            expected["ABI_MAX_ARGS"] = int(abi["max_args"])
        if "max_rets" in abi:
            expected["ABI_MAX_RETS"] = int(abi["max_rets"])
        # Optional: consistency check between ABI bases and memory map constants
        mm = spec.get("memory_map", {}).get("constants", {})
        for abi_k, mm_k in (
            ("arg_base", "ARG_BASE"),
            ("res_base", "RES_BASE"),
            ("status_addr", "STATUS_ADDR"),
            ("aux_addr", "AUX_ADDR"),
        ):
            if abi_k in abi and mm_k in mm:
                try:
                    a = int(str(abi[abi_k]), 16)
                    m = int(str(mm[mm_k]), 16)
                    if a != m:
                        errors.append(f"JSON: INVOKE abi.{abi_k} ({a:#x}) != memory_map.{mm_k} ({m:#x})")
                except Exception:
                    pass
    else:
        errors.append("JSON: missing INVOKE instruction entry (op=0xB) or missing abi")

    # Primitive registry schema constants (bit positions)
    pr = spec.get("primitive_registry", {})
    if pr:
        try:
            expected["PRIM_ROW_BITS"] = int(pr.get("row_bits", 0))
        except Exception:
            errors.append("JSON: primitive_registry.row_bits missing or invalid")
        for field in pr.get("fields", []) or []:
            fname = str(field.get("name", "")).strip()
            bits = field.get("bits", None)
            if not fname or not (isinstance(bits, list) and len(bits) == 2):
                errors.append(f"JSON: malformed primitive_registry field: {field}")
                continue
            hi, lo = int(bits[0]), int(bits[1])
            key = re.sub(r"[^A-Za-z0-9]", "_", fname).upper()
            expected[f"PRIM_{key}_HI"] = hi
            expected[f"PRIM_{key}_LO"] = lo

    # Status codes
    for sc in spec.get("status_codes", []):
        name  = sc["name"]
        value = int(sc["value"], 16)
        expected[name] = value

    # Memory map constants
    mm = spec.get("memory_map", {}).get("constants", {})
    addr_map = {
        "ARG_BASE":      "ARG_BASE",
        "RES_BASE":      "RES_BASE",
        "USER_START":    "USER_START",
        "USER_END":      "USER_END",
        "AUX_ADDR":      "AUX_ADDR",
        "STATUS_ADDR":   "STATUS_ADDR",
        "PROT_LO_END":   "PROT_LO_END",
        "PROT_HI_START": "PROT_HI_START",
    }
    for json_key, svh_key in addr_map.items():
        if json_key in mm:
            expected[svh_key] = int(mm[json_key], 16)

    # Check each SVH file
    svh_files = [args.svh]
    if args.svh_rtl:
        svh_files.append(args.svh_rtl)

    for svh_path in svh_files:
        try:
            consts = load_svh_constants(svh_path)
        except FileNotFoundError:
            errors.append(f"File not found: {svh_path}")
            continue

        for name, val in expected.items():
            check_constant(consts, name, val, errors, svh_path)

        check_forbidden(consts, svh_path, errors)

        # Extra: verify CALL/RET are absent as constants
        for forbidden in ("CTRL_CALL", "CTRL_RET"):
            if forbidden in consts:
                errors.append(
                    f"{svh_path}: '{forbidden}' must not exist in J16 v2 ISA package"
                )

    if errors:
        print("ISA LOCKSTEP FAILED:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print(f"ISA lockstep OK — {len(expected)} constants verified across {len(svh_files)} SVH file(s)")
        sys.exit(0)


if __name__ == "__main__":
    main()
