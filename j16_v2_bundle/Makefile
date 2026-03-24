# J16 v2 — Build, lock-step, and simulation targets

.PHONY: all gen-isa check-isa asm sim-cert sim-rtl-equiv sim-rtl-equiv-timing sim-rtl-equiv-invoke-fault sim-rtl-equiv-all clean sim-gate-a

all: check-isa

# Regenerate j16_isa.svh (and rtl/j16_isa.svh) from the canonical JSON manifest.
gen-isa:
	python3 tools/gen_j16_isa_svh.py \
	  --json docs/isa_v2.json \
	  --out  j16_isa.svh \
	  --out-rtl rtl/j16_isa.svh

# Verify j16_isa.svh matches isa_v2.json — fails if they have drifted.
# This is the CI gate run on every push/PR.
check-isa:
	python3 tools/check_isa_lockstep.py \
	  --json    docs/isa_v2.json \
	  --svh     j16_isa.svh \
	  --svh-rtl rtl/j16_isa.svh

# Assemble a .s file into a $readmemh-compatible .hex
ASM_SRC ?= asm/prog_equiv.s
ASM_OUT ?= build/out.hex

asm:
	mkdir -p build
	python3 tools/j16asm.py --isa docs/isa_v2.json --in $(ASM_SRC) --out $(ASM_OUT) --lst $(ASM_OUT:.hex=.lst) --sym $(ASM_OUT:.hex=.sym)

# Run certification testbench (Icarus)
sim-cert:
	iverilog -g2012 -o sim_cert \
	  j16_ref_pkg.sv \
	  j16_certifier.sv \
	  tb_cert.sv
	vvp sim_cert

# Run RTL equivalence testbench (Icarus)
# Run RTL equivalence testbench (Icarus)
SIM_RTL_SRCS = \
	rtl/j16_core.sv \
	rtl/j16_imem.sv \
	rtl/j16_prim_registry.sv \
	rtl/j16_invoke_stub.sv \
	rtl/j16_soc_min.sv \
	j16_ref_pkg.sv \
	j16_certifier.sv \
	tb/tb_j16_rtl_equiv.sv

sim-rtl-equiv:
	iverilog -g2012 -o sim_rtl $(SIM_RTL_SRCS) -DPROG_HEXFILE=\"prog_equiv.hex\"
	vvp sim_rtl



# Gate A: certifier conservativeness check (RTL runtime <= cert bounds)
GATE_HEXFILE ?= prog_equiv.hex
SIM_GATE_A_SRCS = \
	rtl/j16_core.sv \
	rtl/j16_imem.sv \
	rtl/j16_prim_registry.sv \
	rtl/j16_invoke_stub.sv \
	rtl/j16_soc_min.sv \
	j16_ref_pkg.sv \
	j16_certifier.sv \
	tb/tb_soundness_gate_a.sv

sim-gate-a:
	iverilog -g2012 -o sim_gate_a $(SIM_GATE_A_SRCS) -DPROG_HEXFILE=\"$(GATE_HEXFILE)\"
	vvp sim_gate_a

sim-rtl-equiv-timing:
	iverilog -g2012 -o sim_rtl $(SIM_RTL_SRCS) -DPROG_HEXFILE=\"prog_equiv_timing.hex\" -DEXPECT_TIMING
	vvp sim_rtl

sim-rtl-equiv-invoke-fault:
	iverilog -g2012 -o sim_rtl $(SIM_RTL_SRCS) -DPROG_HEXFILE=\"prog_equiv_invoke_fault.hex\" -DEXPECT_FAULT
	vvp sim_rtl

sim-rtl-equiv-all: sim-rtl-equiv sim-rtl-equiv-timing sim-rtl-equiv-invoke-fault

# Generate primtab.hex from a JSON description (portable $readmemh formatting)
primtab-gen-sparse:
	python3 tools/primtab_pack.py --json docs/primtab_example.json --out primtab.hex --sparse

primtab-gen-full:
	python3 tools/primtab_pack.py --json docs/primtab_example.json --out primtab.hex --words 256

clean:
	rm -f sim_cert sim_rtl


# ---- Symbols (v0) -----------------------------------------------------
SYMBOLS_REG ?= symbols/symbols_v0.json
SYMBOLS_ALIASES ?= build/symbols_aliases.json

.PHONY: sym-aliases
sym-aliases:
	python3 tools/j16sym.py aliases --in $(SYMBOLS_REG) --out $(SYMBOLS_ALIASES)

.PHONY: sym-cert
sym-cert: sym-aliases
	# Uses Icarus when available; otherwise auto-falls back to tools/j16cert.py if present.
	python3 tools/j16sym.py cert --in $(SYMBOLS_REG) --out build/symbols_v0_certified.json --build build

.PHONY: asm-sym
asm-sym: sym-aliases
	python3 tools/j16asm.py --isa docs/isa_v2.json --symbols $(SYMBOLS_ALIASES) --in asm/prog_equiv.s --out build/prog_equiv_fromasm.hex --sym build/prog_equiv_fromasm.sym --lst build/prog_equiv_fromasm.lst
