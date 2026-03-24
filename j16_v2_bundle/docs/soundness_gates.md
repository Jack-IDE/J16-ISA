# Soundness gates (J16 v2)

This repo is designed to keep the ISA/toolchain **sound to concept** by turning the biggest
“trust me” assumptions into **pass/fail gates** you can run locally and in CI.

## Gate A — Certifier conservativeness (end-to-end)

Goal: prove the static certificate bounds are **never optimistic** relative to real RTL execution.

**Bench:** `tb/tb_soundness_gate_a.sv`

What it checks (for a given `*.hex` program image):
- `RTL actual_cycles <= cert.max_cycles` (strict)
- `RTL actual_icount <= cert.max_icount`
- RTL must reach `HALT` without `FAULT`

Run it:
```sh
make sim-gate-a GATE_HEXFILE=prog_equiv.hex
```

Cycle-counting convention (strict):
- Cycle 0 is the first posedge after reset deassertion (`rst=0`).
- Count every subsequent posedge until `HALT`/`FAULT` is observed.

This matches the certifier's cycle model (`CORE_CYCLES_PER_INSN = FETCH+EXEC`).

## Gate B — ABI contract enforcement (no silent mismatch)

Goal: ensure a “certified symbol” cannot violate its declared stack contract.

Enforced by `tools/j16sym.py cert`:
- It statically analyzes the **symbol object** control-flow graph.
- It verifies **all paths** have the same exit stack depth.
- It requires: `exit_depth == abi.pushes` when starting from `abi.pops`.
- It enforces **boundary-only** CTRL targets and **forward-only** CTRL (J16 rule).
- It rejects any CTRL that jumps outside the symbol object (e.g. into harness prologue/HALT).

Assembler rule:
- `CALL <SYM>` must resolve to a symbol entry with certified ABI/budget/hash data.
  This is part of the frozen banked-symbol toolchain model and prevents the "assembled but never certified" footgun.

## Gate C — Worst-case bound safety (baseline_subtract + branches)

Baseline-subtract certification relies on subtracting a constant prologue/epilogue budget from a
harnessed cert run. The risky case is letting internal branches “escape” into the harness, which can
violate the model and (in the worst case) compromise bounds.

This repo enforces:
- Symbols must be straight-line (`CTRL` forbidden).
- Any internal `CTRL` is rejected for the frozen v0 rule set. Branching into the harness (including the final `HALT`) is rejected.

## Gate D — Semantic coverage suites

The static gates above are necessary, but you still want good coverage of “edge semantics.”
Recommended suites to keep expanding:
- Control target calculation and forward-branch legality
- Protected memory region behavior
- INVOKE allow-list / capability behavior (bank containment)
