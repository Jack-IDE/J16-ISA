# J16 v2 — Non-Turing-Complete Secure Execution Substrate

## What This Is

J16 v2 is a 16-bit stack-based CPU ISA designed from the ground up for **structural security**.

The core design principle: **Turing completeness is the attack surface.** Rather than trying to
contain it, J16 v2 eliminates it at the encoding level.

Every J16 v2 program is statically certifiable to:
- Terminate within a computable cycle bound
- Never overflow or underflow its data stack
- Never access protected memory regions
- Never execute undefined behavior

These are not runtime guarantees enforced by a mode flag. They are **structural properties**
of the ISA encoding. You cannot synthesize an insecure J16 v2 core by misconfiguring a parameter.

---

## Key Differences From v1

| Property | v1 | v2 |
|---|---|---|
| CALL/RET | Present (blocked by PROFILE_T) | **Removed from encoding entirely** |
| Return stack | Present | **Gone** |
| Backward branches | Blocked by PROFILE_T | **ST_ILLEGAL_ENC at encoding level** |
| Profile mode switch | `PROFILE_T` parameter | **No switch. Always secure.** |
| Violation fault | ST_J16T_VIOL (implies a mode) | ST_MEM_PROT (describes what happened) |
| LIT range | 12-bit | 12-bit (LIT) + **16-bit (LIT16, new)** |
| ALU ops | 11 | 13 (added LT, NEQ) |
| Stack proof | Simulation-based | **Static per-instruction depth certificate** |


## Simulate (Icarus)

### Basic certification + run
```bash
iverilog -g2012 -o sim \
  j16_ref_pkg.sv j16_certifier.sv \
  tb_cert.sv
vvp sim
```

### RTL equivalence check
```bash
iverilog -g2012 -o sim \
  rtl/j16_core.sv rtl/j16_imem.sv rtl/j16_prim_registry.sv \
  rtl/j16_invoke_stub.sv rtl/j16_soc_min.sv \
  j16_ref_pkg.sv j16_certifier.sv \
  tb/tb_j16_rtl_equiv.sv
vvp sim
```

---

## Assemble

```bash
make asm ASM_SRC=asm/prog_equiv.s ASM_OUT=build/prog_equiv.hex
```

The assembler reads `docs/isa_v2.json` for encodings, so it stays spec-locked.

---

## Memory Map

| Region    | Range       | Program Access |
|-----------|-------------|----------------|
| ARG       | 0x00..0x3F  | INVOKE only    |
| RES       | 0x40..0x7F  | INVOKE only    |
| USER      | 0x80..0xFD  | Read/Write     |
| AUX       | 0xFE        | Read via INVOKE only |
| STATUS    | 0xFF        | Read via INVOKE only |

---

## Primitive Registry (`primtab.hex`)

Each entry is a 128-bit row (32 hex digits per line):

```
[127:112] full_id        = (bank<<8)|idx
[111:108] model          = 0 (const), 1 (linear)
[107:104] unit           = reserved
[103:88]  max_units      = max problem size
[87:72]   base_cycles    = base budget
[71:56]   per_cycles     = per-unit budget
[55:48]   cap_id         = capability class (gated by ALLOW_CAPS)
[47:40]   pops           = args popped from data stack
[39:32]   pushes         = results pushed to data stack
[31]      deterministic  = MUST BE 1 (J16 v2 rejects non-deterministic primitives)
[30:0]    reserved
```

All registered primitives **must** be deterministic and have a declared cycle budget.
Non-deterministic primitives are rejected by the certifier and the runtime.

---

## Lock-Step ISA Manifest

`docs/isa_v2.json` is the canonical spec. `j16_isa.svh` is auto-generated from it.
They must never drift.

```bash
make gen-isa    # Regenerate j16_isa.svh from isa_v2.json
make check-isa  # Verify they match (runs in CI on every push)
```

---

## Why Non-Turing-Complete Is Enough

The functions you need for specialized hardware processes — data transformation,
state machine execution, bounded cryptographic kernels, protocol parsing, inference
pre/post-processing — are all **primitive recursive**. None of them require unbounded loops.

What you lose is the ability to write an interpreter or implement arbitrary algorithms.
That is precisely what you want to prevent.

For capabilities beyond the core ISA, use the INVOKE system: registered, capability-gated,
cycle-bounded hardware primitives. They extend what programs can do without giving programs
Turing-complete escape.


## Capability-typed banks (v0)

Banks and symbols declare capability sets. Primitive rows in `primtab.hex` carry a `cap_id` which is mapped to a capability name via `docs/isa_v2.json`.

`tools/j16sym.py cert` enforces:

- `symbol.caps ⊆ bank.caps`
- symbol dependencies are monotonic: callers may only depend on symbols/primitives whose caps are a subset of the caller's caps
- bank policy: primitive caps must be allowed by `bank.allow_prim_caps`

See `docs/symbols_cert.md`.


---

## Soundness gates

The repo includes explicit pass/fail gates that turn “sound to concept” into something you can run:

- **Gate A (end-to-end conservativeness)**: `make sim-gate-a GATE_HEXFILE=prog_equiv.hex`
  - Runs RTL to HALT and asserts actual cycles/icount stay within the static certificate bounds.
- **Gate B (ABI contract enforcement)**: `tools/j16sym.py cert` performs a CFG stack analysis and
  rejects any symbol whose *actual* stack effect differs from its declared `(pops, pushes)` ABI.
  It also rejects CTRL targets that escape the symbol object.
- **Assembler hardening**: `tools/j16asm.py --require-certified-symbols` prevents assembling programs
  that CALL symbols lacking ABI/budget metadata (i.e., “assembled but never certified”).

See `docs/soundness_gates.md` for details.
