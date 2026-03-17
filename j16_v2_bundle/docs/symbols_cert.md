# J16 Symbols v0 — certification (j16sym cert)

This bundle supports **Path A (CALL-based symbols)**: `CALL <SYM>` is a toolchain macro that expands the symbol inline during assembly.

`j16sym cert` makes your "symbol = atomic process" idea *mechanically enforceable* by producing:

- a **locked object hash** of the expanded symbol words
- a **worst-case instruction/cycle budget** for the symbol (derived from the existing SV certifier)

Nothing here changes the ISA.

## What gets certified

For each symbol, `j16sym cert` generates two harness programs:

1) **Baseline harness** (for the symbol's ABI `pops`):

- push `pops` dummy arguments (`LIT16`)
- `HALT`

2) **Symbol harness**:

- push `pops` dummy arguments (`LIT16`)
- `CALL <SYM>`  (expands inline)
- `HALT`

It runs the existing **SystemVerilog certifier** on both harnesses, then computes:

```
max_cycles(symbol) = max_cycles(symbol_harness) - max_cycles(baseline_harness)
max_icount(symbol) = max_icount(symbol_harness) - max_icount(baseline_harness)
```

This isolates the symbol's cost from the harness prologue/terminator.

The object hash is computed from the **expanded symbol words** extracted from the harness hex by stripping:

- `pops * 2` words of prologue (`LIT16` is a 2-word instruction)
- the final `HALT` word

## Running it

From the bundle root:

```bash
make sym-cert
```

Or directly:

```bash
python3 tools/j16sym.py cert \
  --in symbols/symbols_v0.json \
  --out build/symbols_v0_certified.json \
  --build build
```

### Requirements

- `iverilog` + `vvp` (Icarus Verilog)

If you want to generate harnesses + hashes without running Icarus:

```bash
python3 tools/j16sym.py cert --in symbols/symbols_v0.json --out build/symbols_v0_certified.json --no-run
```

## Registry fields written back

Each symbol receives:

- `hash.obj_hash` — sha256 over canonical 4-hex word lines of the expanded object
- `budget.max_cycles` / `budget.max_icount` — symbol-only budgets
- `cert.*` — method + baseline/raw values used to compute the budgets

These are the pieces you need to treat symbols as **first-class, bank-addressable, versioned artifacts**.
## ABI and control-flow constraints (v0)

During `j16sym cert`, each symbol is assembled into a harness:

```
LIT16 <dummy>   ; repeated abi.pops times
CALL  <SYMBOL>  ; expands inline
HALT
```

The cert tool now enforces:

- **ABI match**: all possible harness paths must end with **exactly** `abi.pushes` words on the data stack (starting from empty).
- **No SYS inside symbols**: `HALT` / `TRAP` inside a symbol object is forbidden (it would halt the caller).
- **(Default) no CTRL inside symbols**: v0 certification uses a harness-based budget strategy (`baseline_subtract`), which assumes straight-line symbol bodies.
  You may override with `--allow-branches`, but this is not recommended until the budgeting method is upgraded.

`j16sym cert` also records direct dependencies:

- `cert_info.deps.invoke_fids` — the set of `INVOKE` fids referenced by the symbol body.

## Closure hash

`j16sym cert` computes an additional tamper-evident hash:

- `hash.obj_hash` — SHA-256 of the inlined object words (symbol body)
- `hash.closure_hash` — SHA-256 over `obj_hash` plus the hashes of all **direct INVOKE dependencies**
  (symbol deps use their own `closure_hash`; external primitive deps use a leaf hash of the primtab row).

This makes symbol bundles tamper-evident across bank boundaries where dependencies are invoked, not inlined.

## Bank-descending constraint (v0 strict)

In addition to the ABI/control-flow checks, `j16sym cert` enforces a **layered bank rule**:

- A symbol in bank **B** may only `CALL` / `INVOKE` symbols in banks **< B**.

This is the strongest form of "no cyclic dependencies":

- it forbids cycles structurally (all edges point down),
- it makes bank placement deterministic,
- and it keeps the system non-recursive without adding ISA features.

Override for experiments: `--allow-non-descending` (not v0-compliant).


## Capability enforcement (v0)

Each bank declares:

- `caps`: the maximum capability set allowed for symbols in that bank
- `allow_prim_caps`: the capability names allowed for primitive INVOKE targets from that bank

Each symbol declares:

- `caps`: the capability set for that symbol

Certification rules:

1) `symbol.caps ⊆ bank.caps`
2) For every symbol dependency (CALL/INVOKE to a symbol), `callee_symbol.caps ⊆ caller_symbol.caps`
3) For every primitive INVOKE dependency, the primitive's capability (from `primtab.cap_id` mapped via `docs/isa_v2.json` certification.capabilities) must be in `bank.allow_prim_caps` and in `caller_symbol.caps`

This turns the symbol graph into a *policy-checked DAG* and keeps privilege monotonic across dependencies.
