# J16 ISA v2 — Normative Specification

**Version:** v2.0
**Word size:** 16-bit fixed-width
**Instruction layout:** `IR[15:12]=OP`, `IR[11:8]=A`, `IR[7:0]=B`

---

## Design Intent

J16 v2 is a **non-Turing-complete instruction set architecture.**

This is not a limitation — it is the goal. Turing completeness is the attack surface.
By removing it at the encoding level, the following properties become unconditional:

- Every program provably terminates.
- Every execution is bounded by a computable cycle count.
- No buffer overflow via stack manipulation is possible.
- No program can escape into unintended memory regions.
- No dynamic dispatch, no self-modification, no recursion.

These properties hold **structurally** — they do not depend on a runtime mode flag, a
profile parameter, or correct tool configuration. There is no `PROFILE_T=1` to forget
to set. The secure behavior is the only behavior.

---

## 1. What Was Removed From v1 (and Why)

### CALL and RET — Permanently Removed

`CALL` and `RET` do not exist in J16 v2. Their encoding slots (`OP=0x4, A>=0x3`)
are `ST_ILLEGAL_ENC`, treated identically to any other undefined opcode.

This eliminates:
- Recursion (the primary mechanism for unbounded stack growth)
- Indirect control flow via return address manipulation
- Return-oriented programming (ROP) as an attack class
- The entire return stack and its associated underflow/overflow state

### Return Stack — Permanently Removed

With no CALL/RET, there is no return stack. The `RSP`, `RSTACK`, `ST_RSTACK_UF`,
and `ST_RSTACK_OF` architectural state and status codes are gone. The architecture
is simpler and the attack surface is smaller.

### PROFILE_T Parameter — Removed

There is no mode switch. The security rules are the ISA. A synthesized J16 v2 core
always enforces all constraints. There is no configuration option that produces an
insecure core.

### ST_J16T_VIOL — Replaced by ST_MEM_PROT

The name "J16T violation" implied a mode that could be disabled. The new status code
`ST_MEM_PROT` (value `0x0007`) describes what actually happened: a program attempted
to access a protected memory region.

---

## 2. Architectural State

- **PC** — 32-bit word address, resets to 0
- **DSTACK[256]** — 16-bit words; DSP is a count (0..256); TOS = DSTACK[DSP-1]
- **RAM[256]** — 16-bit word-addressed flat memory, partitioned by region (see §4)
- **ROM** — Instruction memory, read-only; separate from RAM

No return stack. No heap. No pointers outside the defined memory map.

---

## 3. Instruction Set

### OP = 0x0 — NOP

`A=0x0, B=0x00` only. Any other encoding is `ST_ILLEGAL_ENC`.

### OP = 0x2 — LIT (push 12-bit immediate)

Pushes `(A<<8)|B` zero-extended to 16 bits.

### OP = 0x6 — LIT16 (push 16-bit immediate)

Two-word instruction. `A=0x0, B=0x00` required. The next ROM word (`PC+1`) is the
literal value. PC advances by 2. This is the only way to push a full 16-bit constant.

To push `0xBEEF`:
```
0x6000    ; LIT16
0xBEEF    ; literal data word
```

The data word at `PC+1` is **not** an instruction. The certifier marks it `is_data=1`
and never attempts to decode it.

### OP = 0x5 — STACK

| A | Tag  | Effect           |
|---|------|------------------|
| 0 | DUP  | `x → x x`        |
| 1 | DROP | `x →`             |
| 2 | SWAP | `a b → b a`      |
| 3 | OVER | `a b → a b a`    |

Other A values: `ST_ILLEGAL_ENC`.

### OP = 0x1 — ALU

| A | Tag  | Effect (u16, wrapping) |
|---|------|------------------------|
| 0 | XOR  | `a b → a^b`           |
| 1 | AND  | `a b → a&b`           |
| 2 | OR   | `a b → a\|b`          |
| 3 | NOT  | `a → ~a`              |
| 4 | ADD  | `a b → a+b`           |
| 5 | SUB  | `a b → a-b` (nos-tos) |
| 6 | SHL  | `a → a<<(B&0xF)`      |
| 7 | SHR  | `a → a>>(B&0xF)` (logical) |
| 8 | ROTL | `a → rotl16(a,B&0xF)` |
| 9 | ROTR | `a → rotr16(a,B&0xF)` |
| A | EQ   | `a b → (a==b?1:0)`    |
| B | LT   | `a b → (a<b?1:0)` (unsigned) |
| C | NEQ  | `a b → (a!=b?1:0)`    |

LT and NEQ are new in v2. Other A values: `ST_ILLEGAL_ENC`.

### OP = 0x3 — MEM

Program RAM access. All accesses to protected regions fault `ST_MEM_PROT`.

| A | Tag | Effect |
|---|-----|--------|
| 0 | LD  | `→ RAM[B]`                  (B must be in user region) |
| 1 | ST  | `x →` `RAM[B]=x`           (B must be in user region) |
| 2 | LDI | `addr → RAM[addr[7:0]]`    (addr must be in user region) |
| 3 | STI | `x addr →` `RAM[addr[7:0]]=x` (addr must be in user region) |

Note: `LD[B]` and `ST[B]` with B in `0x00..0x7F` or `0xFE..0xFF` are **encoding-level**
violations caught by the certifier. At runtime, they fault `ST_MEM_PROT`.

### OP = 0x4 — CTRL

**Forward-only branches.** `B[7]=1` is `ST_ILLEGAL_ENC` — a hard encoding error,
not a runtime mode check. The certifier rejects programs containing any such instruction.

| A | Tag | Effect |
|---|-----|--------|
| 0 | JMP | `PC := (PC+1) + B` (unconditional) |
| 1 | JZ  | `cond →` if cond==0: jump |
| 2 | JNZ | `cond →` if cond!=0: jump |

`A >= 0x3`: permanently `ST_ILLEGAL_ENC`. CALL and RET do not exist.

**Why forward-only is an encoding rule, not a runtime check:**
A backward branch could create a loop. A loop means unbounded execution.
Unbounded execution means the program cannot be certified. The certifier
rejects programs with backward branches before they ever run. The runtime
enforcement is a defense-in-depth backstop.

### OP = 0xB — INVOKE

Calls a registered, bounded, deterministic hardware primitive.

Encoding: `full_id = (A<<8)|B`

The primitive is looked up in the primitive registry (`primtab.hex`). If unknown,
or non-deterministic, or capability-gated: `ST_UNKNOWN_INVOKE`.

**ABI (frozen):**
1. Pop `pops` args from data stack; arg0 is original TOS
2. Store to `RAM[0x00..0x3F]` (ARG region)
3. Assert `inv_valid`; stall core while primitive runs
4. Primitive may access `RAM[0x00..0x7F]` via `inv_mem_*` bus **only**. Accessing
   outside this range produces `ST_MEM_PROT` immediately.
5. On `inv_done`: write STATUS/AUX, push `pushes` results from `RAM[0x40..0x7F]`

Pre-flight check: if `DSP - pops + pushes > 256`, fault `ST_DSTACK_OF` before execution.

### OP = 0xF — SYS

| A | Tag  | Effect |
|---|------|--------|
| 0 | HALT | Clean termination. `halted=1, faulted=0`. |
| 1 | TRAP | Fault termination. `STATUS=ST_TRAP, AUX=B`. |

---

## 4. Memory Map (Frozen)

| Range       | Name    | Program Access | Notes |
|-------------|---------|----------------|-------|
| `0x00..0x3F`| ARG     | None (fault)   | INVOKE argument marshalling |
| `0x40..0x7F`| RES     | None (fault)   | INVOKE result marshalling |
| `0x80..0xFD`| USER    | Read/Write     | 126 words of program RAM |
| `0xFE`      | AUX     | None (fault)   | Fault auxiliary; read via SYS_STATUS_AUX INVOKE only |
| `0xFF`      | STATUS  | None (fault)   | Fault status; same |

Programs have **126 words** of writable RAM. This is intentionally constrained.
For larger working sets, use INVOKE primitives with dedicated hardware buffers.

---

## 5. Status Codes (Frozen)

| Code   | Value  | Meaning |
|--------|--------|---------|
| ST_OK             | 0x0000 | Normal operation |
| ST_UNKNOWN_INVOKE | 0x0001 | INVOKE target not in registry, non-deterministic, or capability denied |
| ST_DSTACK_UF      | 0x0002 | Data stack underflow |
| ST_DSTACK_OF      | 0x0003 | Data stack overflow |
| ST_PC_OOB         | 0x0004 | PC outside program ROM |
| ST_ILLEGAL_ENC    | 0x0005 | Illegal instruction encoding |
| ST_TRAP           | 0x0006 | SYS TRAP executed |
| ST_MEM_PROT       | 0x0007 | Protected memory region accessed |
| ST_INVOKE_TIMEOUT | 0x0008 | Primitive exceeded declared cycle budget |

---

## 6. Certification Rules

A program is **J16 v2 certifiable** if and only if all of the following hold:

**Program image length (`prog_len`)**: Certification treats the program image as a contiguous ROM from word 0 up to (and including) a terminating `SYS HALT` instruction (`0xF000`). The certifier requires that the final word at `prog_len-1` is `SYS HALT`. In `AUTO_LEN` mode, `prog_len` is computed as `last SYS HALT + 1` and any **non-zero** words after that terminator are rejected (so padding can’t silently truncate analysis). For production builds, prefer an explicit `PROG_LEN` and always place `SYS HALT` at the end of the image.

1. All instructions at reachable PCs have legal encodings.
2. No CTRL instruction has `B[7]=1`.
3. No CTRL instruction has `A >= 0x3` (no CALL/RET encoding anywhere).
4. All CTRL targets are within `[0, prog_len)` and point at instruction words (not LIT16 data words).
5. All INVOKE full_ids exist in `primtab.hex`, have `deterministic=1`, and have allowed `cap_id`.
6. All direct-address MEM ops (`LD[B]`, `ST[B]`) have B in the user region.
7. Stack depth is provably consistent at every instruction: the certifier computes a unique
   `dsp_at[pc]` for each reachable instruction; inconsistency (branch target with conflicting
   depths from two predecessors) is a certification failure.
8. Stack depth never underflows or overflows on any path.
9. Every reachable execution path reaches `SYS HALT`.
10. The program has a finite computable worst-case cycle count.

The certifier outputs a JSON certificate containing `prog_len`, `max_icount`, `max_cycles`,
and the per-instruction `dsp_at` array. Any tool can independently verify the certificate
in a single O(n) pass.

---

## Appendix: Non-Turing Completeness Argument

J16 v2 programs cannot express:

- **Unbounded loops:** All CTRL targets must be forward (`B[7]=0`). Combined with
  finite `prog_len`, every execution visits each PC at most once.
- **Recursion:** CALL/RET do not exist. The data stack depth at every instruction is
  statically known.
- **Unbounded primitive work:** Every INVOKE primitive must declare a finite cycle
  budget. The certifier sums budgets across all reachable INVOKE sites.

The class of functions computable by J16 v2 programs is a proper subset of the
**primitive recursive functions** — specifically, those with a statically bounded
call depth and iteration count. This is more than sufficient for data transformation,
protocol state machines, bounded cryptographic operations, and specialized inference
kernels.
