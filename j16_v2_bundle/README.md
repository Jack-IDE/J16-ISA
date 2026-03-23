# J16 / CBM Integrated Checkpoint

This bundle is an integrated checkpoint of the **J16 v2** execution substrate together with:

- the **SystemVerilog reference model**
- the **static certifier**
- the **manifest-driven assembler and symbol tools**
- the **synthesizable RTL core and testbenches**
- a standalone **Python reference simulator**
- the browser-based **CBM-SAE** authoring and certification environment

It should be presented as a **serious checkpoint release** rather than a final research closure. The main layers of the system are present together and can be run directly from this bundle.

---

## What is in this bundle

### Core J16 v2

- `docs/J16_ISA_v2.md` — human-readable ISA specification
- `docs/isa_v2.json` — canonical machine-readable ISA manifest
- `j16_ref_pkg.sv` — SystemVerilog reference model
- `j16_certifier.sv` — static certifier
- `rtl/` — synthesizable RTL core and support modules
- `tb/` — equivalence / gate testbenches

### Tools

- `tools/j16asm.py` — manifest-driven assembler
- `tools/j16sym.py` — symbol tooling and certification support
- `tools/j16sim.py` — standalone Python reference simulator
- `tools/check_isa_lockstep.py` — manifest / generated-header lockstep check
- `tools/gen_j16_isa_svh.py` — regenerate `j16_isa.svh` from `docs/isa_v2.json`
- `tools/rom_packer.py` — ROM word packer
- `tools/primtab_pack.py` — primitive-table packer

### CBM-SAE

- `tools/cbm_sae/index.html` — offline CBM authoring, certification, simulation, and J16-lowering workbench
- `tools/cbm_sae/README.md` — short CBM-SAE usage overview

### Example artifacts

- `asm/` — example assembly sources
- `build/` — example assembled outputs
- `prog.hex`, `prog_equiv.hex`, `prog_equiv_timing.hex`, `prog_equiv_invoke_fault.hex` — example program images
- `primtab.hex`, `allow_prims.hex` — primitive registry / allowlist examples
- `symbols/symbols_v0.json` — example or authoring registry for symbol metadata
- `sym/corelib/` — example symbol source

---

## What this checkpoint demonstrates

This checkpoint brings the major layers together in one place:

1. **Spec-locked ISA definition** via `docs/isa_v2.json`
2. **Generated ISA header discipline** via `j16_isa.svh` and lockstep checks
3. **Reference execution model** via `j16_ref_pkg.sv`
4. **Static certification** via `j16_certifier.sv`
5. **Synthesizable RTL** via `rtl/`
6. **Assembly and symbol tooling** via `tools/j16asm.py` and `tools/j16sym.py`
7. **Standalone runnable reference simulator** via `tools/j16sim.py`
8. **CBM authoring and lowering integration** via `tools/cbm_sae/index.html`

The intended framing is:

> **J16 / CBM Integrated Checkpoint**
>
> A reproducible milestone containing the J16 v2 spec/toolchain/reference stack, a standalone Python simulator, and the CBM-SAE authoring and certification frontend.

---

## Quick start

### 1. Run the Python simulator

Basic run:

```bash
python3 tools/j16sim.py --hex prog.hex
```

Trace execution:

```bash
python3 tools/j16sim.py --hex prog_equiv.hex --trace
```

Run with primitive table loaded:

```bash
python3 tools/j16sim.py --hex prog_equiv.hex --primtab primtab.hex --trace
```

Dump memory after execution:

```bash
python3 tools/j16sim.py --hex prog.hex --dump-mem
```

### 2. Assemble example code

```bash
make asm ASM_SRC=asm/prog_equiv.s ASM_OUT=build/prog_equiv.hex
```

The assembler is manifest-driven and reads `docs/isa_v2.json`, so the encoding layer stays tied to the canonical spec.

### 3. Check ISA manifest lockstep

```bash
make gen-isa
make check-isa
```

This regenerates `j16_isa.svh` from `docs/isa_v2.json` and verifies the generated header has not drifted.

### 4. Run certification / simulation with Icarus

Basic certification flow:

```bash
iverilog -g2012 -o sim \
  j16_ref_pkg.sv j16_certifier.sv \
  tb_cert.sv
vvp sim
```

RTL equivalence flow:

```bash
iverilog -g2012 -o sim \
  rtl/j16_core.sv rtl/j16_imem.sv rtl/j16_prim_registry.sv \
  rtl/j16_invoke_stub.sv rtl/j16_soc_min.sv \
  j16_ref_pkg.sv j16_certifier.sv \
  tb/tb_j16_rtl_equiv.sv
vvp sim
```

### 5. Open CBM-SAE

Open this file in a browser:

```text
tools/cbm_sae/index.html
```

CBM-SAE is the browser-based authoring and semantic-analysis frontend. It supports graph editing, JSON/schema inspection, certification, simulation, and an embedded J16-lowering workbench.

---

## The role of `j16sim.py`

`tools/j16sim.py` is not just a convenience script. It belongs in the bundle as the **Python reference simulator**.

Use it for:

- quick CLI inspection of `.hex` programs
- readable execution traces
- easier reproduction without a Verilog simulator
- cross-checking behaviour against the SystemVerilog reference model

For repo organization, the clean public placement is:

```text
tools/j16sim.py
```

---

## Symbol and certification notes

The shipped `symbols/symbols_v0.json` should be understood as an **example / authoring registry**, not automatically as fully certified production metadata.

That file is useful as a starting point for authoring and policy structure. Certified symbol metadata should come from the symbol certification flow and include the expected certification-derived fields such as budgets and hashes.

See:

- `docs/symbols.md`
- `docs/symbols_cert.md`
- `docs/bank_policy.md`

---

## Memory map

| Region | Range | Program access |
|---|---|---|
| ARG | `0x00..0x3F` | INVOKE only |
| RES | `0x40..0x7F` | INVOKE only |
| USER | `0x80..0xFD` | Read / write |
| AUX | `0xFE` | Read via INVOKE only |
| STATUS | `0xFF` | Read via INVOKE only |

---

## Primitive registry

`primtab.hex` stores primitive registry rows. Registered primitives are expected to be deterministic and to carry a declared cycle budget.

Relevant documentation:

- `docs/primtab_format.md`
- `docs/primtab_example.json`

---

## Current checkpoint status

### What is solid in this bundle

- canonical ISA manifest present
- generated-header lockstep tooling present
- SystemVerilog reference model present
- static certifier present
- RTL core and testbenches present
- assembler and symbol tooling present
- Python simulator present
- CBM-SAE integrated into the same checkpoint

### What this bundle should not claim yet

This bundle should be described as a **complete integrated checkpoint**, not as the final closure of the entire broader research program.

That framing is stronger and more accurate than overselling it as “final.”

## Final positioning

The clean public description is:

> **J16 / CBM Integrated Checkpoint**
>
> A bundled milestone containing the J16 v2 ISA/spec/toolchain/reference stack, a standalone Python reference simulator, and the CBM-SAE authoring / certification frontend.

That is strong, accurate, and matches what is actually present in this ZIP.
