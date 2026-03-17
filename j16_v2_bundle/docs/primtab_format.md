# primtab.hex format (J16 v2)

`primtab.hex` is a simulation-time primitive metadata table consumed by:

- `rtl/j16_core.sv` (builds `prim_by_id[]` + `prim_valid[]` at init)
- `rtl/j16_prim_registry.sv` (standalone lookup module)

To avoid silent misloads when switching simulators, this doc specifies a **canonical, simulator-safe** `$readmemh` encoding.

---

## 1) File-level rules (portable across Icarus + Verilator)

For maximum portability:

- **One primitive row per line**
- **Exactly 32 hex digits per line** (128 bits), **no `0x` prefix**
- No spaces, underscores, or commas inside the hex token
- Prefer **no comments** in `primtab.hex` (some flows accept `//`, others are pickier)
- End lines with `\n` (LF). Avoid CRLF if you are seeing tool issues.

Notes:
- Your RTL pre-initializes `primtab_raw[]` to zero before calling `$readmemh`, so the file may contain fewer than 256 lines.  
  If you want the file itself to be self-contained and deterministic, emit all 256 lines (zeros for unused rows).

---

## 2) Per-row layout (128-bit packed word)

Each line is parsed as a 128-bit word `primtab_raw[i]` with the following fixed bit layout
(see `rtl/j16_core.sv` and `rtl/j16_prim_registry.sv`):

```
bits [127:112]  fid           (16)  // full_id = (bank<<8)|idx, currently must be < 4096
bits [111:108]  model         (4)
bits [107:104]  unit          (4)   // accounting / unit class (currently 0 in the stub)
bits [103:88]   max_units     (16)
bits [87:72]    base_cycles   (16)
bits [71:56]    per_cycles    (16)
bits [55:48]    cap_id        (8)
bits [47:40]    pops          (8)
bits [39:32]    pushes        (8)
bit  [31]       deterministic (1)
bits [30:0]     reserved      (31)  // must be 0
```

A row of all zeros (`000...000`) is treated as **unused** by `j16_core.sv`.

### Hex digit ordering

The 32 hex digits represent the 128-bit word in the usual Verilog way:

- **leftmost** hex digit is bits `[127:124]` (MS nibble)
- **rightmost** hex digit is bits `[3:0]` (LS nibble)

There is no “byte ordering” beyond that — it is a pure bit-vector load.

---

## 3) Example

This is a valid row for primitive fid `0x0001` with:

- `model=0`, `unit=0`
- `base_cycles=12`
- `pops=2`, `pushes=1`
- `deterministic=1`
- everything else 0

```
0001000000000c000000020180000000
```

---

## 4) Generator script

Use `tools/primtab_pack.py` to generate a canonical `primtab.hex` from JSON:

```
python3 tools/primtab_pack.py \
  --json docs/primtab_example.json \
  --out primtab.hex \
  --words 256
```

The script can also write an annotated companion file for humans:

```
python3 tools/primtab_pack.py \
  --json docs/primtab_example.json \
  --out primtab.hex \
  --annotated-out primtab_annotated.txt
```


### cap_id → capability name

`cap_id` is a numeric capability tag attached to each primitive. Tooling maps it to a capability name using `docs/isa_v2.json` under `certification.capabilities.cap_id_to_name`.

Symbol certification can then enforce bank/symbol capability policies (see `docs/symbols_cert.md`).
