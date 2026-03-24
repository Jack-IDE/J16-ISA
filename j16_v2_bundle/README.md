# J16 v2 — 32/32 ABI Checkpoint

This repository is a public checkpoint of the **J16 v2** execution substrate and its surrounding toolchain.

It includes:
- the canonical ISA manifest
- generated ISA headers
- a SystemVerilog reference model
- a static certifier
- a synthesizable RTL core and testbenches
- a manifest-driven assembler and symbol tooling
- a standalone Python reference simulator and Python certifier
- the offline browser-based **CBM-SAE** authoring and certification workbench

This should be presented as a **serious integrated checkpoint**, not as a final closed research endpoint. The core spec, ABI, and verification stack are present together and can be exercised directly from this repo.

---

## Checkpoint status

### Stable in this checkpoint

- **J16 v2 32/32 ABI layout**
- canonical ISA manifest in `docs/isa_v2.json`
- generated-header lockstep discipline via `j16_isa.svh` and `rtl/j16_isa.svh`
- SystemVerilog reference execution model
- static certification flow
- synthesizable RTL core and equivalence-oriented testbenches
- manifest-driven assembler and symbol tooling
- standalone Python simulator and Python certifier
- integrated CBM-SAE workbench with J16 lowering support

### Still evolving

- higher-level symbol ecosystem and larger primitive library growth
- CBM-SAE authoring ergonomics and documentation polish
- broader example programs and packaged demonstrations
- future platform profiles above the current strict checkpoint

---

## ABI and memory map

This checkpoint uses the **32 ARG / 32 RES** layout.

| Region | Range | Notes |
|---|---|---|
| ARG | `0x00..0x1F` | INVOKE argument window |
| RES | `0x20..0x3F` | INVOKE result window |
| USER | `0x40..0xFD` | general read/write program memory |
| AUX | `0xFE` | reserved / INVOKE-side access |
| STATUS | `0xFF` | reserved / INVOKE-side access |

That means ordinary program-visible mutable space begins at **`0x40`**.

For the current J16-L0 profile, `INVOKE_THEN` success codes are expected to be **non-zero**.

---

## Repository layout

### Core spec and verification

- `docs/J16_ISA_v2.md` — human-readable ISA specification
- `docs/isa_v2.json` — canonical machine-readable ISA manifest
- `j16_isa.svh` — generated ISA header
- `rtl/j16_isa.svh` — generated RTL-side ISA header
- `j16_ref_pkg.sv` — SystemVerilog reference model
- `j16_certifier.sv` — SystemVerilog static certifier
- `rtl/` — synthesizable RTL core and support modules
- `tb/` — equivalence and gate testbenches

### Tools

- `tools/j16asm.py` — manifest-driven assembler
- `tools/j16sym.py` — symbol tooling and certification support
- `tools/j16cert.py` — Python certifier mirroring the SV certifier
- `tools/j16sim.py` — standalone Python reference simulator
- `tools/check_isa_lockstep.py` — verifies JSON ↔ generated-header lockstep
- `tools/gen_j16_isa_svh.py` — regenerates ISA headers from the manifest
- `tools/rom_packer.py` — ROM word packer
- `tools/primtab_pack.py` — primitive-table packer

### CBM-SAE

- `tools/cbm_sae/index.html` — offline CBM authoring, certification, simulation, and J16-lowering workbench
- `tools/cbm_sae/README.md` — short CBM-SAE overview

### Example sources and artifacts

- `asm/` — example assembly sources
- `sym/corelib/` — example symbol source
- `symbols/symbols_v0.json` — example / authoring symbol registry
- `build/` — generated example outputs and certification artifacts
- `prog.hex`, `prog_equiv.hex`, `prog_equiv_timing.hex`, `prog_equiv_invoke_fault.hex` — example program images
- `primtab.hex`, `allow_prims.hex` — primitive registry / allowlist examples

---

## Requirements

Minimum useful setup:
- Python 3

Optional but recommended for the full flow:
- `make`
- `iverilog` and `vvp` for SystemVerilog certification and RTL testbenches

CBM-SAE runs fully offline in a browser.

---

## Quick start

### 1. Verify the ISA manifest/header lockstep

```bash
make check-isa
```

To regenerate the headers first:

```bash
make gen-isa
make check-isa
```

### 2. Run the Python simulator

Basic run:

```bash
python3 tools/j16sim.py --hex prog.hex
```

Trace execution:

```bash
python3 tools/j16sim.py --hex prog.hex --trace
```

Dump memory after execution:

```bash
python3 tools/j16sim.py --hex prog.hex --dump-mem
```

### 3. Assemble example code

```bash
make asm ASM_SRC=asm/prog_equiv.s ASM_OUT=build/prog_equiv.hex
```

This uses the canonical manifest in `docs/isa_v2.json`, so encoding remains tied to the frozen spec.

### 4. Generate symbol aliases and run symbol-aware flows

Generate aliases:

```bash
make sym-aliases
```

Run symbol certification:

```bash
make sym-cert
```

Assemble the symbol-aware example using generated aliases:

```bash
make asm-sym
```

### 5. Run SystemVerilog certification / equivalence flows

Static certifier testbench:

```bash
make sim-cert
```

RTL equivalence runs:

```bash
make sim-rtl-equiv-all
```

Gate A conservativeness check:

```bash
make sim-gate-a
```

### 6. Open CBM-SAE

Open this file in a browser:

```text
tools/cbm_sae/index.html
```

CBM-SAE is the offline graph editor, semantic checker, simulator, and J16-lowering workbench included with this checkpoint.

---

## Important notes

### Symbol-aware assembly

`asm/prog_symbols_demo.s` is **not** a plain-assembler-only example.

It references symbol aliases such as `CALL ADD16`, so it should be assembled through the symbol-aware flow after generating aliases, not by running bare `j16asm.py` alone with no symbol metadata.

Use:

```bash
make sym-aliases
make asm-sym
```

or invoke `j16asm.py` with `--symbols build/symbols_aliases.json`.

### Symbol registry status

`symbols/symbols_v0.json` should be treated as an **authoring/example registry**.

Certified symbol metadata should come from the certification flow, for example:

```text
build/symbols_v0_certified.json
```

See:
- `docs/symbols.md`
- `docs/symbols_cert.md`
- `docs/bank_policy.md`

### Python certifier fallback

`tools/j16sym.py cert` supports two backends:
- Icarus Verilog using the SystemVerilog certifier
- the bundled Python certifier in `tools/j16cert.py`

If `iverilog` is unavailable and `tools/j16cert.py` is present, the symbol certification flow can fall back to the Python certifier.

---

## Primitive registry

`primtab.hex` stores primitive registry rows. Registered primitives are expected to be deterministic and to carry a declared cycle budget.

Relevant documentation:
- `docs/primtab_format.md`
- `docs/primtab_example.json`

---

## What this checkpoint demonstrates

This repo brings the major layers together in one place:

1. a spec-locked ISA definition
2. generated-header lockstep discipline
3. a reference execution model
4. static certification
5. synthesizable RTL
6. assembly and symbol tooling
7. a standalone Python simulator and Python certifier
8. an offline CBM authoring and lowering environment

That combination is the point of the release: it is a reproducible **J16 v2 integrated checkpoint** with the core spec, runtime model, verification, and authoring stack aligned around the current ABI.

---

## Recommended public framing

> **J16 v2 — 32/32 ABI Checkpoint**
>
> A bundled milestone containing the J16 v2 ISA/spec/toolchain/reference stack, the synthesizable RTL and certifier flows, standalone Python reference tooling, and the offline CBM-SAE authoring/certification frontend.
