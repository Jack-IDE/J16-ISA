# J16 Symbols (v0)

J16 v2 intentionally has **no CALL/RET** instruction in the ISA. To enable your "process becomes a symbol" workflow *without changing the ISA*, the toolchain treats:

- `CALL <SYMBOL>` as a **spec-locked symbol invocation**
- which **expands inline at assembly time** (macro expansion)

This makes symbols first-class artifacts that can be:

- **banked**: (bank, index) → fid = (bank<<8)|index
- **hash-locked**: source hash and (later) object hash
- **budgeted**: certified `max_cycles`
- **capability-typed**: banks and symbols declare capability sets; certification enforces that a symbol only depends on symbols/primitives whose capabilities are a subset of its declared caps.


Later, the backend can be swapped so `CALL <SYMBOL>` emits `INVOKE fid` and is handled by a ROM primitive dispatcher—without changing source syntax.

## Files

- `symbols/symbols_v0.json` — canonical symbol registry
- `build/symbols_aliases.json` — generated aliases for the assembler
- `sym/**.s` — symbol implementations (assembly snippets)

## Registry schema (minimal)

Each symbol has:

- `bank` + `index` (fid = bank<<8 | index)
- `name`
- `src` (path to symbol assembly)
- `abi.pops`, `abi.pushes`
- `caps` (capabilities)
- `budget.max_cycles` (may be filled by a future `j16sym cert`)

See `docs/symbols_cert.md` for the spec-locked certification workflow.

### Primitive capability allowlist key

The canonical bank field for primitive capability allowlisting is `allow_prim_caps`.
Some external or authoring tools may accept `allow_effect_caps` as an alias, but the bundle format and `j16sym` use `allow_prim_caps`.

## Assembler usage

Generate aliases:

```sh
make sym-aliases
```

Assemble with symbol expansion enabled:

```sh
python3 tools/j16asm.py --isa docs/isa_v2.json --symbols build/symbols_aliases.json \
  --in your_prog.s --out build/your_prog.hex
```

Write symbol calls as:

```asm
LIT16  3
LIT16  4
CALL   ADD16
HALT
```
## ABI enforcement, dependencies, and closure hashing

`j16sym cert` now writes additional verified metadata back into the registry:

- `hash.obj_hash` — SHA-256 over the symbol object words (after `CALL` expansion)
- `hash.closure_hash` — tamper-evident SHA-256 committing to the full dependency closure
- `cert_info.abi_check` — stack-depth verification result (cert fails on mismatch)
- `cert_info.deps.invoke_fids` — direct `INVOKE` dependencies (fids)

### Branches in v0 symbols

By default, v0 symbol certification rejects `CTRL` inside symbol bodies. This keeps budgeting and ABI analysis simple and deterministic.
If you explicitly want branches inside symbols, pass `--allow-branches` to `j16sym cert` and ensure your budgeting strategy remains sound.

### Bank-descending rule (v0 strict)

To finish the "banked symbols" safety story, v0 additionally enforces:

- A symbol in bank **B** may only `CALL` / `INVOKE` symbols in banks **< B**.

This means the symbol dependency graph is a DAG by construction, which supports:

- deterministic bank placement
- closure hashing without fixed-point tricks
- no recursion-by-indirection through `INVOKE`

For experiments you may relax this with `j16sym cert --allow-non-descending`, but it is not v0-compliant.


### CBM `INVOKE_THEN` lowering note

`INVOKE_THEN` is a CBM authoring construct, not a native J16 instruction.
At the strict/v0 lowering boundary it maps to:

```
INVK <rd>, <callee>
BNZ  <rd>, <ok_target>
J    <fail_target>
```

So any workflow that allows `INVOKE_THEN` inside a lowered symbol must also allow the resulting `CTRL` words in that lowered artifact, or treat the branch as part of an out-of-band lowering contract.
