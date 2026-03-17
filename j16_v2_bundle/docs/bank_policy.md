# Bank allocation policy (v0)

This document locks down the **bank** / **layer** scheme for J16 v2 symbol libraries.

## Definitions

- `fid` (full id) is a 12-bit identifier encoded in `INVOKE`:
  - `fid = (bank << 8) | index`
  - `bank` is 4 bits (0..15)
  - `index` is 8 bits (0..255)

## Reserved bank ranges

- **Bank 0** (`bank=0x0`) is reserved for **platform primitives** (hardware/ROM services).
  - The canonical definition is `primtab.hex` (one 128-bit row per primitive).
  - Primitive contracts are immutable once a platform target is frozen.

- **Banks 1..15** (`bank=0x1..0xF`) are reserved for **banked symbols** (certified code objects).

## Layer numbering (spec-locked)

To avoid ambiguity, v0 defines:

- **Layer N uses bank N** (for N=1..15).

That is: `layer == bank`.

This gives a trivially verifiable mapping and eliminates hidden hierarchy rules.
If a future version needs multiple banks per layer, it must introduce an explicit `layers.json` manifest and a new cert rule.

## Bank-descending dependency rule (v0 strict)

To make the banked-symbol system **structurally acyclic** (and therefore tamper-evident + placeable),
v0 enforces a single rule during `j16sym cert`:

- A symbol in **bank B** may only `CALL` / `INVOKE` symbols in **banks < B**.

Notes:

- This is stronger than a generic "no cycles" rule; it makes cycles **impossible** by construction.
- It also makes bank placement deterministic: every edge points "down."
- Primitives live in bank 0, so any symbol may `INVOKE` primitives.

You can override this for experiments with `j16sym cert --allow-non-descending`, but that is not v0-compliant.
