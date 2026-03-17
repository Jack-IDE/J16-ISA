`include "j16_isa.svh"
// j16_certifier.sv — J16 v2 Static Certifier
//
// This module performs a single-pass static analysis of a J16 v2 program and:
//   1. Verifies all encoding constraints (no backward branches, no CALL/RET, etc.)
//   2. Verifies all INVOKE targets exist, are deterministic, and have allowed capabilities.
//   3. Proves stack safety: every instruction has a unique, consistent stack depth from
//      all possible predecessors. A branch target whose predecessor depths disagree FAILS.
//   4. Proves termination: every reachable execution path reaches HALT.
//   5. Computes a worst-case instruction count and cycle budget.
//   6. Outputs a JSON certificate to stdout.
//
// Key design decisions vs. v1 certifier:
//   - No PROFILE_T parameter. These checks are always active.
//   - Stack depth is a PROOF, not a simulation. A per-instruction depth array is
//     computed by linear forward sweep. Branch targets must match their computed depth.
//   - The certificate is the per-instruction depth array; any verifier can check it
//     in O(n) without re-running the program.
//   - LIT16 data words (PC+1 of each LIT16) are marked as data, not instructions.
//     The certifier skips them during instruction iteration.

module j16_certifier #(
  parameter int unsigned PROG_WORDS    = 1024,
  parameter string       HEXFILE       = "prog.hex",
  parameter int unsigned PROG_LEN      = 0,
  parameter bit          AUTO_LEN      = 1'b1,
  parameter string       PRIMTABFILE   = "primtab.hex",
  parameter int unsigned PRIMTAB_WORDS = 256,
  parameter bit          ALLOW_ALL_INVOKE = 1'b0,
  parameter string       ALLOWFILE     = "",
  parameter int unsigned ALLOW_WORDS   = 256,
  parameter logic [255:0] ALLOW_CAPS   = {256{1'b1}},
  parameter int unsigned CORE_CYCLES_PER_INSN = 2,  // FETCH+EXEC = 2 cycles
  parameter bit          EMIT_CERT_JSON = 1'b1        // Print certificate to $display
)(
  output logic        ok,
  output logic [15:0] fail_status,
  output logic [15:0] fail_word,
  output int unsigned fail_pc,
  output int unsigned prog_len,
  output int unsigned max_icount,
  output int unsigned max_cycles
);

  import j16_isa_pkg::*;

  // === Certifier-only status codes (tooling) ===
  // These are NOT architectural runtime statuses; they indicate certification-time structural failures.
  localparam logic [15:0] ST_CERT_NO_HALT_TERM = 16'hF101;
  localparam logic [15:0] ST_CERT_TAIL_NONZERO = 16'hF102;

  // Canonical HALT word encoding
  localparam logic [15:0] HALT_WORD = {OP_SYS, SYS_HALT, 8'h00};


  // Program ROM
  logic [15:0] rom [0:PROG_WORDS-1];

  // Primitive registry
  typedef struct {
    bit          valid;
    logic [3:0]  model;
    logic [15:0] max_units;
    logic [15:0] base_cycles;
    logic [15:0] per_cycles;
    logic [7:0]  cap_id;
    logic [7:0]  pops;
    logic [7:0]  pushes;
    logic        deterministic;
  } prim_meta_t;
  prim_meta_t primtab [0:4095];

  // Allowlist
  bit allow_set [int];

  // Per-instruction analysis arrays
  // dsp_at[i] = proven stack depth at instruction i (-1 = unreachable or unset)
  int signed  dsp_at     [0:PROG_WORDS-1];
  bit         is_data    [0:PROG_WORDS-1];  // 1 = LIT16 data word, not instruction
  bit         reach      [0:PROG_WORDS-1];
  bit         can_halt   [0:PROG_WORDS-1];
  int unsigned icount_at [0:PROG_WORDS-1];
  int unsigned cycles_at [0:PROG_WORDS-1];

  // Termination in the certification proof means *clean HALT* only.
  // SYS_TRAP is a diagnostic fault termination and must be unreachable in certified programs.
  function automatic bit is_term(input logic [15:0] w);
    return (w[15:12] == OP_SYS) && (w[11:8] == SYS_HALT);
  endfunction

  // Encoding legality check (encoding-level only, no runtime state required)
  function automatic bit is_legal_enc(input logic [15:0] w);
    logic [3:0] op = w[15:12];
    logic [3:0] A  = w[11:8];
    logic [7:0] B  = w[7:0];
    case (op)
      OP_NOP:    return (A == 4'h0 && B == 8'h00);
      OP_ALU:    return (ALU_VALID_MASK[A]);
      OP_LIT:    return 1'b1;
      OP_MEM:    begin
        if (A > MEM_STI) return 0;
        // Direct-address MEM ops: check for protected region accesses
        if ((A == MEM_LD || A == MEM_ST) &&
            ((B <= PROT_LO_END) || (B >= PROT_HI_START)))
          return 0;
        return 1;
      end
      OP_CTRL:   begin
        // Canonical CTRL semantics live in j16_isa_pkg helpers.
        // Backward branches are illegal encodings (structural rule, not a runtime mode).
        if (!ctrl_b_legal(B)) return 0;
        // CALL/RET: permanently removed
        if (A >= 4'h3)    return 0;
        return 1;
      end
      OP_STACK:  return (A <= STACK_OVER);
      OP_LIT16:  return (A == 4'h0 && B == 8'h00);
      OP_INVOKE: return 1'b1;   // existence/determinism checked separately
      OP_SYS:    return (A == SYS_HALT || A == SYS_TRAP);
      default:   return 0;
    endcase
  endfunction

  // Stack effect of an instruction (pops, pushes).
  // For INVOKE, returned via the primitive table.
  function automatic void stack_effect(
    input  logic [15:0] w,
    input  prim_meta_t  prim,   // only used if INVOKE
    output int signed   net,    // net stack change
    output int          need    // minimum depth required before instruction
  );
    logic [3:0] op = w[15:12];
    logic [3:0] A  = w[11:8];
    case (op)
      OP_NOP:    begin net =  0; need = 0; end
      OP_LIT:    begin net =  1; need = 0; end
      OP_LIT16:  begin net =  1; need = 0; end
      OP_STACK: case (A)
        STACK_DUP:  begin net =  1; need = 1; end
        STACK_DROP: begin net = -1; need = 1; end
        STACK_SWAP: begin net =  0; need = 2; end
        STACK_OVER: begin net =  1; need = 2; end
        default:    begin net =  0; need = 0; end
      endcase
      OP_ALU: case (A)
        ALU_NOT, ALU_SHL, ALU_SHR, ALU_ROTL, ALU_ROTR:
                    begin net =  0; need = 1; end
        default:    begin net = -1; need = 2; end  // binary ops
      endcase
      OP_MEM: case (A)
        MEM_LD:     begin net =  1; need = 0; end
        MEM_ST:     begin net = -1; need = 1; end
        MEM_LDI:    begin net =  0; need = 1; end  // pop addr, push value
        MEM_STI:    begin net = -2; need = 2; end
        default:    begin net =  0; need = 0; end
      endcase
      OP_CTRL: case (A)
        CTRL_JMP:   begin net =  0; need = 0; end
        CTRL_JZ,
        CTRL_JNZ:   begin net = -1; need = 1; end
        default:    begin net =  0; need = 0; end
      endcase
      OP_INVOKE: begin
        net  = int'(prim.pushes) - int'(prim.pops);
        need = int'(prim.pops);
      end
      OP_SYS:    begin net =  0; need = 0; end
      default:   begin net =  0; need = 0; end
    endcase
  endfunction

  task automatic do_fail(
    input logic [15:0] status,
    input int unsigned pc_i,
    input logic [15:0] w
  );
    ok          = 1'b0;
    fail_status = status;
    fail_pc     = pc_i;
    fail_word   = w;
  endtask

  initial begin : CERTIFY
    int i;
    int unsigned len;
    logic [15:0] allow_rom [0:ALLOW_WORDS-1];

    // Init outputs
    ok          = 1'b1;
    fail_status = ST_OK;
    fail_pc     = 0;
    fail_word   = 16'h0;
    max_icount  = 0;
    max_cycles  = 0;
    prog_len    = 0;

    for (i = 0; i < PROG_WORDS; i++) rom[i] = 16'h0;
    for (i = 0; i < 4096; i++) primtab[i] = '{ valid:0, default:0 };
    for (i = 0; i < PROG_WORDS; i++) begin
      dsp_at[i]     = -1;
      is_data[i]    = 0;
      reach[i]      = 0;
      can_halt[i]   = 0;
      icount_at[i]  = 0;
      cycles_at[i]  = 0;
    end

    // --- Load program ---
    $readmemh(HEXFILE, rom);

    if (PROG_LEN != 0) begin
      len = (PROG_LEN > PROG_WORDS) ? PROG_WORDS : PROG_LEN;
    end else if (AUTO_LEN) begin
      int halt_idx;
      halt_idx = -1;

      // AUTO_LEN is HALT-terminated: length = last SYS HALT + 1.
      // This prevents NOP/zero padding from truncating certification analysis.
      for (i = PROG_WORDS-1; i >= 0; i--) begin
        if (rom[i] === HALT_WORD) begin halt_idx = i; break; end
      end
      if (halt_idx < 0) begin
        ok          = 1'b0;
        fail_status = ST_CERT_NO_HALT_TERM;
        fail_pc     = 0;
        fail_word   = 16'h0000;
        $display("CERT FAIL: AUTO_LEN requires a terminating SYS HALT (%h) within ROM.", HALT_WORD);
        disable CERTIFY;
      end

      // Reject any nonzero tail after the terminator (prevents silent truncation).
      for (i = halt_idx+1; i < PROG_WORDS; i++) begin
        if (rom[i] !== 16'h0000) begin
          ok          = 1'b0;
          fail_status = ST_CERT_TAIL_NONZERO;
          fail_pc     = halt_idx+1;
          fail_word   = rom[i];
          $display("CERT FAIL: nonzero ROM word after terminating SYS HALT at word[%0d]: word[%0d]=%h", halt_idx, i, rom[i]);
          disable CERTIFY;
        end
      end

      len = halt_idx + 1;
    end else begin
      len = PROG_WORDS;
    end

    // Certification requires a HALT terminator at the end of the certified image.
    if (len == 0) len = 1;
    if (rom[len-1] !== HALT_WORD) begin
      ok          = 1'b0;
      fail_status = ST_CERT_NO_HALT_TERM;
      fail_pc     = (len-1);
      fail_word   = rom[len-1];
      $display("CERT FAIL: program must end with SYS HALT (%h). word[%0d]=%h", HALT_WORD, len-1, rom[len-1]);
      disable CERTIFY;
    end

    prog_len = len;
    // --- Load primitive table ---
    // Use 128-bit version
    begin
      logic [127:0] ptab128 [0:255];
      $readmemh(PRIMTABFILE, ptab128);
      for (i = 0; i < 256; i++) begin
        if (ptab128[i] !== 128'h0) begin
          logic [15:0] fid = ptab128[i][127:112];
          if (int'(fid) < 4096) begin
            primtab[int'(fid)].valid         = 1;
            primtab[int'(fid)].model         = ptab128[i][111:108];
            primtab[int'(fid)].max_units     = ptab128[i][103:88];
            primtab[int'(fid)].base_cycles   = ptab128[i][87:72];
            primtab[int'(fid)].per_cycles    = ptab128[i][71:56];
            primtab[int'(fid)].cap_id        = ptab128[i][55:48];
            primtab[int'(fid)].pops          = ptab128[i][47:40];
            primtab[int'(fid)].pushes        = ptab128[i][39:32];
            primtab[int'(fid)].deterministic = ptab128[i][31];
          end
        end
      end
    end

    // --- Build allowlist ---
    allow_set.delete();
    if (!ALLOW_ALL_INVOKE) begin
      if (ALLOWFILE != "") begin
        for (i = 0; i < ALLOW_WORDS; i++) allow_rom[i] = 16'h0;
        $readmemh(ALLOWFILE, allow_rom);
        for (i = 0; i < ALLOW_WORDS; i++) allow_set[int'(allow_rom[i])] = 1;
      end else begin
        for (i = 0; i < 32; i++) allow_set[(0<<8)|i] = 1;
      end
    end

    // -----------------------------------------------------------------------
    // PASS 1: Mark LIT16 data words, verify encoding legality, INVOKE metadata
    // -----------------------------------------------------------------------
    for (i = 0; i < int'(len); i++) begin
      if (!ok) break;
      if (is_data[i]) continue;  // skip data word

      logic [15:0] w = rom[i];
      logic [3:0]  op = w[15:12];
      logic [3:0]  A  = w[11:8];
      logic [7:0]  B  = w[7:0];

      if (!is_legal_enc(w)) begin
        do_fail(ST_ILLEGAL_ENC, i, w);
        break;
      end

      // LIT16: mark next word as data
      if (op == OP_LIT16) begin
        if (i + 1 >= int'(len)) begin
          do_fail(ST_PC_OOB, i, w);
          break;
        end
        is_data[i+1] = 1;
      end

      // INVOKE checks
      if (op == OP_INVOKE) begin
        logic [15:0] fid = {A, B};
        int fid_i = int'(fid);

        if (!ALLOW_ALL_INVOKE && !allow_set.exists(fid_i)) begin
          do_fail(ST_UNKNOWN_INVOKE, i, w);
          break;
        end
        if (!primtab[fid_i].valid) begin
          do_fail(ST_UNKNOWN_INVOKE, i, w);
          break;
        end
        if (!primtab[fid_i].deterministic) begin
          do_fail(ST_ILLEGAL_ENC, i, w);
          break;
        end
        if (!ALLOW_CAPS[int'(primtab[fid_i].cap_id)]) begin
          do_fail(ST_UNKNOWN_INVOKE, i, w);
          break;
        end


// Budget must be non-zero; otherwise INVOKE would timeout immediately.
begin
  logic [31:0] bud;
  if (primtab[fid_i].model == 4'h0)
    bud = 32'(primtab[fid_i].base_cycles);
  else
    bud = 32'(primtab[fid_i].base_cycles) + 32'(primtab[fid_i].per_cycles) * 32'(primtab[fid_i].max_units);
  if (bud == 32'h0) begin
    do_fail(ST_ILLEGAL_ENC, i, w);
    break;
  end
end
        end
      end

      // CTRL target range check (for all CTRL instructions)
      if (op == OP_CTRL) begin
        int signed  tgt = int'(ctrl_target(32'(i), B));
        if (tgt < 0 || tgt >= int'(len) || is_data[tgt]) begin
          do_fail(ST_ILLEGAL_ENC, i, w);
          break;
        end
      end
    end

    if (!ok) disable CERTIFY;

    // -----------------------------------------------------------------------
    // PASS 2: Forward stack-depth propagation (single pass, DAG guaranteed)
    // Prove stack depth is consistent at every instruction and branch target.
    // -----------------------------------------------------------------------
    dsp_at[0] = 0;
    reach[0]  = 1;

    for (i = 0; i < int'(len); i++) begin
      if (!ok) break;
      if (is_data[i] || !reach[i]) continue;
      if (dsp_at[i] < 0) begin
        // Reached but depth unknown — internal error in the analysis
        do_fail(ST_ILLEGAL_ENC, i, rom[i]);
        break;
      end

      logic [15:0]  w    = rom[i];
      logic [3:0]   op   = w[15:12];
      logic [3:0]   A    = w[11:8];
      logic [7:0]   B    = w[7:0];
      int signed    cur  = dsp_at[i];
      int signed    net;
      int           need;
      prim_meta_t   meta = '{ valid:0, default:0 };

      if (op == OP_INVOKE) meta = primtab[int'({A,B})];

      stack_effect(w, meta, net, need);

      // Stack underflow check
      if (cur < need) begin
        do_fail(ST_DSTACK_UF, i, w);
        break;
      end
      // Stack overflow check (pre-INVOKE overflow caught here too)
      if (cur + net > 256) begin
        do_fail(ST_DSTACK_OF, i, w);
        break;
      end

      int signed after = cur + net;

      if (is_term(w)) continue;

      // Advance PC: LIT16 is a 2-word instruction
      int unsigned pc_next = (op == OP_LIT16) ? i + 2 : i + 1;

      if (op == OP_CTRL) begin
        int unsigned tgt = int'(ctrl_target(32'(i), B));
        if (A == CTRL_JMP) begin
          // Unconditional: only tgt is reachable
          if (!reach[tgt]) begin
            reach[tgt]  = 1;
            dsp_at[tgt] = after;
          end else if (dsp_at[tgt] != after) begin
            // Inconsistent stack depth at branch target — proof fails
            $display("CERT FAIL: branch target %0d has conflicting stack depths %0d vs %0d",
                     tgt, dsp_at[tgt], after);
            do_fail(ST_DSTACK_UF, i, w);
            break;
          end
        end else begin
          // Conditional (JZ/JNZ): both fall-through and target reachable
          for (int j = 0; j < 2; j++) begin
            int unsigned dst = (j == 0) ? pc_next : tgt;
            if (!reach[dst]) begin
              reach[dst]  = 1;
              dsp_at[dst] = after;
            end else if (dsp_at[dst] != after) begin
              $display("CERT FAIL: branch target %0d has conflicting stack depths %0d vs %0d",
                       dst, dsp_at[dst], after);
              do_fail(ST_DSTACK_UF, i, w);
              break;
            end
          end
          if (!ok) break;
        end
      end else begin
        // Sequential instruction
        if (!reach[pc_next]) begin
          reach[pc_next]  = 1;
          dsp_at[pc_next] = after;
        end else if (dsp_at[pc_next] != after) begin
          do_fail(ST_DSTACK_OF, i, w);
          break;
        end
      end
    end

    if (!ok) disable CERTIFY;

    // -----------------------------------------------------------------------
    // PASS 3: Reverse DP — can_halt + worst-case instruction/cycle count
    // -----------------------------------------------------------------------
    for (i = int'(len)-1; i >= 0; i--) begin
      if (is_data[i] || !reach[i]) begin
        can_halt[i]  = 0;
        icount_at[i] = 0;
        cycles_at[i] = 0;
        continue;
      end

      logic [15:0] w  = rom[i];
      logic [3:0]  op = w[15:12];
      logic [3:0]  A  = w[11:8];
      logic [7:0]  B  = w[7:0];

      // Own cycle cost
      int unsigned own_cycles;
      if (op == OP_INVOKE) begin
        prim_meta_t m = primtab[int'({A,B})];
        if (m.model == 4'h0)
          own_cycles = int'(m.base_cycles) + int'(m.pops) + int'(m.pushes) + CORE_CYCLES_PER_INSN + 2; // +2 drain cycles: S_INV_ARG exit + S_INV_RES exit
        else
          own_cycles = int'(m.base_cycles) + int'(m.per_cycles)*int'(m.max_units) + int'(m.pops) + int'(m.pushes) + CORE_CYCLES_PER_INSN + 2; // +2 drain cycles: S_INV_ARG exit + S_INV_RES exit
      end else begin
        own_cycles = (op == OP_LIT16) ? CORE_CYCLES_PER_INSN + 2 : CORE_CYCLES_PER_INSN;
      end

      if (is_term(w)) begin
        can_halt[i]  = 1;
        icount_at[i] = 1;
        cycles_at[i] = own_cycles;
      end else if (op == OP_CTRL) begin
        int unsigned pc_next = i + 1;
        int unsigned tgt     = int'(ctrl_target(32'(i), B));
        if (A == CTRL_JMP) begin
          can_halt[i]  = can_halt[tgt];
          icount_at[i] = can_halt[tgt] ? 1 + icount_at[tgt] : 0;
          cycles_at[i] = can_halt[tgt] ? own_cycles + cycles_at[tgt] : 0;
        end else begin
          bit ok1 = can_halt[pc_next];
          bit ok2 = can_halt[tgt];
          can_halt[i] = ok1 & ok2;
          if (can_halt[i]) begin
            int unsigned mi = (icount_at[pc_next]>icount_at[tgt]) ? icount_at[pc_next] : icount_at[tgt];
            int unsigned mc = (cycles_at[pc_next]>cycles_at[tgt])  ? cycles_at[pc_next]  : cycles_at[tgt];
            icount_at[i] = 1 + mi;
            cycles_at[i] = own_cycles + mc;
          end
        end
      end else begin
        int unsigned pc_next = (op == OP_LIT16) ? i + 2 : i + 1;
        can_halt[i]  = can_halt[pc_next];
        icount_at[i] = can_halt[pc_next] ? 1 + icount_at[pc_next] : 0;
        cycles_at[i] = can_halt[pc_next] ? own_cycles + cycles_at[pc_next] : 0;
      end
    end

    // Every reachable instruction must have a path to HALT
    for (i = 0; i < int'(len); i++) begin
      if (!ok) break;
      if (is_data[i] || !reach[i]) continue;
      if (!can_halt[i]) begin
        do_fail(ST_ILLEGAL_ENC, i, rom[i]);
        break;
      end
    end

    if (!ok) disable CERTIFY;

    max_icount = icount_at[0];
    max_cycles = cycles_at[0];

    // -----------------------------------------------------------------------
    // Certificate output (JSON)
    // -----------------------------------------------------------------------
    if (EMIT_CERT_JSON) begin
      $display("{");
      $display("  \"schema\": \"j16_cert_v2\",");
      $display("  \"ok\": true,");
      $display("  \"prog_len\": %0d,", prog_len);
      $display("  \"max_icount\": %0d,", max_icount);
      $display("  \"max_cycles\": %0d,", max_cycles);
      $display("  \"dsp_at\": [");
      for (i = 0; i < int'(len); i++) begin
        if (is_data[i])
          $display("    %0d%s  /* data word */", -2, (i==int'(len)-1)?"":",");
        else
          $display("    %0d%s", dsp_at[i], (i==int'(len)-1)?"":",");
      end
      $display("  ],");
      $display("  \"is_data\": [");
      for (i = 0; i < int'(len); i++) begin
        $display("    %0d%s", is_data[i], (i==int'(len)-1)?"":",");
      end
      $display("  ]");
      $display("}");
    end

  end // CERTIFY

endmodule
