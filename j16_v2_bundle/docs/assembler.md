# J16 Assembler (j16asm.py)

This bundle includes a **manifest-driven** assembler:

- `tools/j16asm.py`
- It **reads `docs/isa_v2.json`** for op/subop encodings (spec-lock friendly).
- It outputs a simulator-safe **16-bit `$readmemh`** hex file (**one 16-bit word per line**).

## Quick start

```bash
mkdir -p build
python3 tools/j16asm.py \
  --isa docs/isa_v2.json \
  --in asm/prog_equiv.s \
  --out build/prog_equiv.hex \
  --lst build/prog_equiv.lst \
  --sym build/prog_equiv.sym
```

The assembler defaults to **requiring a final `HALT`** (the same spec-lock discipline as the certifier). Use `--no-require-halt` only for experiments.

## Syntax

### Comments

- `; comment`
- `// comment`
- `# comment`

### Labels

```asm
start:
  NOP
```

### Expressions

Expressions are safe-evaluated and support:

- integers: `123`, `0x7B`, `0b1111011`
- symbols: `start`
- operators: `+ - * // % << >> & | ^ ~` and parentheses

### Directives

- `.equ NAME, EXPR` — define a constant
- `.org ADDR` — set the assembly address (must be >= 0)
- `.word EXPR` — emit one raw 16-bit word
- `.fill COUNT, EXPR` — emit COUNT copies of a 16-bit word

### Instructions

The assembler supports the J16 instruction families present in `docs/isa_v2.json`:

- `NOP`
- `LIT imm12`
- `LIT16 imm16` (emits two words)
- ALU tags from the manifest (e.g. `ADD`, `SUB`, `XOR`, `EQ`, `LT`, `NEQ`, `SHL 3`, `SHR 1`, …)
- STACK tags (e.g. `DUP`, `DROP`, `SWAP`, `OVER`)
- MEM tags (e.g. `LD 0x80`, `ST 0x80`, `LDI`, `STI`)
- CTRL tags (e.g. `JMP label`, `JZ label`, `JNZ label`) — **forward-only rel8** encoding
- SYS tags (`HALT`, `TRAP 1`)
- `INVOKE fid16` (e.g. `INVOKE 0x0005`)

## Makefile helper

The Makefile exposes a convenience target:

```bash
make asm ASM_SRC=asm/prog_equiv.s ASM_OUT=build/prog_equiv.hex
```
