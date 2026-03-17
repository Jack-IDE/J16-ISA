#!/usr/bin/env python3
"""
gen_j16_isa_svh.py — Generate j16_isa.svh from docs/isa_v2.json

Usage:
  python3 gen_j16_isa_svh.py \
    --json docs/isa_v2.json \
    --out  j16_isa.svh \
    --out-rtl rtl/j16_isa.svh
"""
import argparse
import json
import hashlib
import datetime
import sys

HEADER = """\
// Auto-generated from {json_path} ({name}, {version})
// DO NOT EDIT BY HAND. Run: make gen-isa
// JSON sha256: {sha256}
// Generated: {date}
//
// Design intent: Non-Turing-complete ISA. Security properties are structural.
// CALL/RET do not exist. Backward branches are illegal encodings.
// No return stack. No profile mode switch.

`ifndef J16_ISA_SVH
`define J16_ISA_SVH

package j16_isa_pkg;

  // === Encoding constants ===
  localparam int unsigned J16_WORD_BITS = 16;
  localparam int unsigned J16_OP_BITS   = 4;
  localparam int unsigned J16_A_BITS    = 4;
  localparam int unsigned J16_B_BITS    = 8;

  // === Primary opcodes (OP field [15:12]) ===
  localparam logic [3:0] OP_NOP    = 4'h0;
  localparam logic [3:0] OP_ALU    = 4'h1;
  localparam logic [3:0] OP_LIT    = 4'h2;
  localparam logic [3:0] OP_MEM    = 4'h3;
  localparam logic [3:0] OP_CTRL   = 4'h4;
  localparam logic [3:0] OP_STACK  = 4'h5;
  localparam logic [3:0] OP_LIT16  = 4'h6;
  localparam logic [3:0] OP_INVOKE = 4'hB;
  localparam logic [3:0] OP_SYS    = 4'hF;

  // === ALU subops ===
  localparam logic [3:0] ALU_XOR  = 4'h0;
  localparam logic [3:0] ALU_AND  = 4'h1;
  localparam logic [3:0] ALU_OR   = 4'h2;
  localparam logic [3:0] ALU_NOT  = 4'h3;
  localparam logic [3:0] ALU_ADD  = 4'h4;
  localparam logic [3:0] ALU_SUB  = 4'h5;
  localparam logic [3:0] ALU_SHL  = 4'h6;
  localparam logic [3:0] ALU_SHR  = 4'h7;
  localparam logic [3:0] ALU_ROTL = 4'h8;
  localparam logic [3:0] ALU_ROTR = 4'h9;
  localparam logic [3:0] ALU_EQ   = 4'hA;
  localparam logic [3:0] ALU_LT   = 4'hB;
  localparam logic [3:0] ALU_NEQ  = 4'hC;
  localparam logic [15:0] ALU_VALID_MASK = 16'h{alu_valid_mask};  // bit[a]=1 iff ALU subop A is legal

  // === MEM subops ===
  localparam logic [3:0] MEM_LD  = 4'h0;
  localparam logic [3:0] MEM_ST  = 4'h1;
  localparam logic [3:0] MEM_LDI = 4'h2;
  localparam logic [3:0] MEM_STI = 4'h3;

  // === STACK subops ===
  localparam logic [3:0] STACK_DUP  = 4'h0;
  localparam logic [3:0] STACK_DROP = 4'h1;
  localparam logic [3:0] STACK_SWAP = 4'h2;
  localparam logic [3:0] STACK_OVER = 4'h3;

  // === CTRL subops (A < 0x3 only; A >= 0x3 is ST_ILLEGAL_ENC) ===
  // NOTE: CTRL_CALL and CTRL_RET DO NOT EXIST in J16 v2.
  localparam logic [3:0] CTRL_JMP = 4'h0;
  localparam logic [3:0] CTRL_JZ  = 4'h1;
  localparam logic [3:0] CTRL_JNZ = 4'h2;

  // === SYS subops ===
  localparam logic [3:0] SYS_HALT = 4'h0;
  localparam logic [3:0] SYS_TRAP = 4'h1;

"""

MEMORY_MAP = """\
  // === Memory map (frozen) ===
{consts}

  // ABI dimensions
  localparam int unsigned ABI_MAX_ARGS = 64;
  localparam int unsigned ABI_MAX_RETS = 64;

"""

STATUS_CODES = """\
  // === Status codes (frozen) ===
{codes}

"""

HELPERS = """\
  // === Semantic helper functions ===

  function automatic logic signed [31:0] sext8(input logic [7:0] b);
    sext8 = $signed({{24{{b[7]}}, b}});
  endfunction

  function automatic logic [31:0] ctrl_target(input logic [31:0] pc_before, input logic [7:0] b);
    ctrl_target = pc_before + 32'd1 + logic'(sext8(b));
  endfunction

  function automatic logic [3:0] shamt4(input logic [7:0] b);
    shamt4 = b[3:0];
  endfunction

  function automatic logic mem_protected(input logic [7:0] addr);
    mem_protected = ((addr <= PROT_LO_END) || (addr >= PROT_HI_START));
  endfunction

  function automatic logic ctrl_b_legal(input logic [7:0] b);
    ctrl_b_legal = (b[7] == 1'b0);
  endfunction

"""

PRIM_SCHEMA = """\
  // === Primitive registry field constants (128-bit row) ===
  localparam int unsigned PRIM_ROW_BITS         = 128;
  localparam int unsigned PRIM_FULL_ID_HI        = 127;
  localparam int unsigned PRIM_FULL_ID_LO        = 112;
  localparam int unsigned PRIM_MODEL_HI          = 111;
  localparam int unsigned PRIM_MODEL_LO          = 108;
  localparam int unsigned PRIM_UNIT_HI           = 107;
  localparam int unsigned PRIM_UNIT_LO           = 104;
  localparam int unsigned PRIM_MAX_UNITS_HI      = 103;
  localparam int unsigned PRIM_MAX_UNITS_LO      = 88;
  localparam int unsigned PRIM_BASE_CYCLES_HI    = 87;
  localparam int unsigned PRIM_BASE_CYCLES_LO    = 72;
  localparam int unsigned PRIM_PER_CYCLES_HI     = 71;
  localparam int unsigned PRIM_PER_CYCLES_LO     = 56;
  localparam int unsigned PRIM_CAP_ID_HI         = 55;
  localparam int unsigned PRIM_CAP_ID_LO         = 48;
  localparam int unsigned PRIM_POPS_HI           = 47;
  localparam int unsigned PRIM_POPS_LO           = 40;
  localparam int unsigned PRIM_PUSHES_HI         = 39;
  localparam int unsigned PRIM_PUSHES_LO         = 32;
  localparam int unsigned PRIM_DETERMINISTIC_HI  = 31;
  localparam int unsigned PRIM_DETERMINISTIC_LO  = 31;

endpackage

`endif // J16_ISA_SVH
"""


def format_const(bits, name, value_hex, comment=""):
    w = bits
    digits = (w + 3) // 4
    if w <= 4:
        type_str = f"logic [{w-1}:0]"
        val_str  = f"{w}'h{value_hex:01X}"
    else:
        type_str = f"logic [{w-1}:0]"
        val_str  = f"{w}'h{value_hex:0{digits}X}"
    c = f"  // {comment}" if comment else ""
    return f"  localparam {type_str} {name} = {val_str};{c}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json",    required=True)
    ap.add_argument("--out",     required=True)
    ap.add_argument("--out-rtl", required=False, default=None)
    args = ap.parse_args()

    with open(args.json, "rb") as f:
        raw = f.read()
    sha = hashlib.sha256(raw).hexdigest()[:12]
    spec = json.loads(raw)

    name    = spec["manifest"]["name"]
    version = spec["manifest"]["version"]
    today   = datetime.date.today().isoformat()

    # ALU valid mask derived from isa_v2.json (spec-lock)
    alu_mask = 0
    for insn in spec.get("instructions", []):
        if insn.get("family") == "ALU" or insn.get("op") == "0x1":
            for so in insn.get("subops", []):
                try:
                    a = int(so.get("a", "0x0"), 16)
                except Exception:
                    continue
                if 0 <= a < 16:
                    alu_mask |= (1 << a)
            break
    alu_valid_mask = f"{alu_mask:04X}"


    # Memory map constants
    mm_consts = spec["memory_map"]["constants"]
    mm_lines = []
    for k, v in mm_consts.items():
        val = int(v, 16)
        mm_lines.append(f"  localparam logic [7:0]  {k:<20} = 8'h{val:02X};")

    # Status codes
    sc_lines = []
    for sc in spec["status_codes"]:
        val  = int(sc["value"], 16)
        note = sc.get("note", sc.get("aux", ""))
        comment = f"  // aux: {note}" if note else ""
        sc_lines.append(f"  localparam logic [15:0] {sc['name']:<22} = 16'h{val:04X};{comment}")

    output = (
        HEADER.format(json_path=args.json, name=name, version=version,
                      sha256=sha, date=today, alu_valid_mask=alu_valid_mask) +
        MEMORY_MAP.format(consts="\n".join(mm_lines)) +
        STATUS_CODES.format(codes="\n".join(sc_lines)) +
        HELPERS +
        PRIM_SCHEMA
    )

    for path in [args.out] + ([args.out_rtl] if args.out_rtl else []):
        with open(path, "w") as f:
            f.write(output)
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
