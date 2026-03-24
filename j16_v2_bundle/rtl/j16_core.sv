`include "j16_isa.svh"
// j16_core.sv — J16 v2 RTL Core (synthesizable)
//
// Security properties are structural (not a runtime mode):
//   - No return stack. No CALL. No RET.
//   - Backward branches (B[7]=1) fault ST_ILLEGAL_ENC, not a "profile violation."
//     There is no profile to violate. This is just an illegal instruction.
//   - OP=0x4 A>=0x3: permanently ST_ILLEGAL_ENC.
//   - MEM to 0x00..0x3F or 0xFE..0xFF: ST_MEM_PROT.
//   - INVOKE primitive mem-bus: restricted to 0x00..0x3F only.
//   - LIT16 (OP=0x6): two-cycle fetch of next ROM word as 16-bit literal.
//   - Pre-INVOKE stack overflow check before any execution.
//
// Pipeline: 2-phase FETCH/EXEC for normal instructions.
// INVOKE: multi-cycle stall with ARG marshal -> handshake -> RES push.
// LIT16: stall for second ROM fetch.
//
// No PROFILE_T parameter. No behavioral mode switches.

module j16_core #(
  parameter int unsigned PROG_WORDS  = 1024,
  parameter int unsigned PROG_LEN    = 0,      // 0 => PROG_WORDS

  // Primitive registry (compile-time ROM, not runtime-mutable)
  parameter int unsigned PRIMTAB_WORDS = 256,
  parameter string       PRIMTABFILE   = "primtab.hex",
  parameter bit          ENFORCE_PRIM_META = 1'b1,

  // Capability allowlist: bitmask over cap_id[7:0].
  // Bit N=1 means primitives with cap_id=N are allowed.
  // Default: all 256 capability IDs allowed. Narrow this per deployment.
  parameter logic [255:0] ALLOW_CAPS = {256{1'b1}},

  // ABI constants (frozen — do not override)
  parameter logic [7:0]  ARG_BASE     = j16_isa_pkg::ARG_BASE,
  parameter logic [7:0]  RES_BASE     = j16_isa_pkg::RES_BASE,
  parameter int unsigned ABI_MAX_ARGS = j16_isa_pkg::ABI_MAX_ARGS,
  parameter int unsigned ABI_MAX_RETS = j16_isa_pkg::ABI_MAX_RETS
)(
  input  logic clk,
  input  logic rst,

  // Instruction memory interface (ROM)
  output logic [$clog2(PROG_WORDS)-1:0] imem_addr,
  input  logic [15:0]                   imem_rdata,

  // INVOKE primitive handshake
  output logic        inv_valid,
  output logic [3:0]  inv_bank,
  output logic [7:0]  inv_idx,
  input  logic        inv_ready,

  input  logic        inv_done,
  input  logic [15:0] inv_status,
  input  logic [15:0] inv_aux,

  // Primitive-to-core memory bus (ARG/RES region ONLY: 0x00..0x3F)
  // Primitive attempting to access outside this range will be blocked; core asserts inv_mem_prot.
  input  logic        inv_mem_valid,
  input  logic        inv_mem_we,
  input  logic [7:0]  inv_mem_addr,
  input  logic [15:0] inv_mem_wdata,
  output logic [15:0] inv_mem_rdata,
  output logic        inv_mem_prot,   // 1 = primitive violated its memory restriction

  // Debug/trace output (pulses on architectural commit)
  output logic        dbg_commit,
  output logic [31:0] dbg_pc,
  output logic [31:0] dbg_pc_after,
  output logic [15:0] dbg_ir,
  output logic [8:0]  dbg_dsp,
  output logic [15:0] dbg_tos,
  output logic [15:0] dbg_status,
  output logic [15:0] dbg_aux,
  output logic        dbg_halted,
  output logic        dbg_faulted,

  // Optional pre/post snapshots (stable when dbg_commit=1)
  output logic [8:0]  dbg_dsp_before,
  output logic [15:0] dbg_tos_before,
  output logic [15:0] dbg_status_before,
  output logic [15:0] dbg_aux_before,
  output logic        dbg_halted_before,
  output logic        dbg_faulted_before,

  output logic [8:0]  dbg_dsp_after,
  output logic [15:0] dbg_tos_after,
  output logic [15:0] dbg_status_after,
  output logic [15:0] dbg_aux_after,
  output logic        dbg_halted_after,
  output logic        dbg_faulted_after
);

  import j16_isa_pkg::*;

  // =========================================================================
  // Primitive registry (loaded from PRIMTABFILE at elaboration)
  // =========================================================================
  typedef struct packed {
    logic [3:0]  model;
    logic [3:0]  unit;
    logic [15:0] max_units;
    logic [15:0] base_cycles;
    logic [15:0] per_cycles;
    logic [7:0]  cap_id;
    logic [7:0]  pops;
    logic [7:0]  pushes;
    logic        deterministic;
  } prim_meta_t;

  logic [127:0]  primtab_raw  [0:PRIMTAB_WORDS-1];
  prim_meta_t    primtab      [0:PRIMTAB_WORDS-1];
  // Fast lookup: index by full_id[7:0] (idx field) within bank
  // For simplicity, use a 4096-entry flat array indexed by full_id[11:0].
  // full_id = (bank<<8)|idx, max 4096 entries.
  prim_meta_t    prim_by_id   [0:4095];
  bit            prim_valid   [0:4095];

  initial begin
    for (int i = 0; i < 4096; i++) prim_valid[i] = 0;
    for (int i = 0; i < PRIMTAB_WORDS; i++) primtab_raw[i] = 128'h0;
    `ifndef J16_NO_READMEMH
    $readmemh(PRIMTABFILE, primtab_raw);
`else
    for (int i = 0; i < PRIMTAB_WORDS; i++) primtab_raw[i] = 128'h0;
`endif
    for (int i = 0; i < PRIMTAB_WORDS; i++) begin
      if (primtab_raw[i] !== 128'h0) begin
        logic [15:0] fid = primtab_raw[i][127:112];
        prim_meta_t  m;
        m.model         = primtab_raw[i][111:108];
        m.unit          = primtab_raw[i][107:104];
        m.max_units     = primtab_raw[i][103:88];
        m.base_cycles   = primtab_raw[i][87:72];
        m.per_cycles    = primtab_raw[i][71:56];
        m.cap_id        = primtab_raw[i][55:48];
        m.pops          = primtab_raw[i][47:40];
        m.pushes        = primtab_raw[i][39:32];
        m.deterministic = primtab_raw[i][31];
        if (int'(fid) < 4096) begin
          prim_by_id[int'(fid)] = m;
          prim_valid[int'(fid)] = 1;
        end
      end
    end
  end

  // =========================================================================
  // Architectural state
  // =========================================================================
  logic [31:0]  arch_pc;
  logic [15:0]  dstack  [0:255];
  logic [8:0]   dsp;               // 0..256

  logic [15:0]  ram     [0:255];   // data memory

  logic         halted;
  logic         faulted;

  // =========================================================================
  // Pipeline state machine
  // =========================================================================
  typedef enum logic [3:0] {
    S_FETCH        = 4'h0,   // Issuing instruction fetch
    S_EXEC         = 4'h1,   // Executing fetched instruction
    S_LIT16_FETCH  = 4'h2,   // Second fetch for LIT16 data word
    S_LIT16_PUSH   = 4'h3,   // Push the fetched literal
    S_INV_ARG      = 4'h4,   // Marshalling arguments to mem[ARG_BASE..]
    S_INV_WAIT     = 4'h5,   // Waiting for inv_ready + inv_done
    S_INV_RES      = 4'h6,   // Pushing results from mem[RES_BASE..]
    S_FAULT        = 4'hE,   // Fault/halt, draining
    S_HALT         = 4'hF    // Clean halt
  } state_t;

  state_t state;

  logic [15:0]  ir_reg;             // Latched instruction
  logic [3:0]   ir_op, ir_a;
  logic [7:0]   ir_b;

  // Identity of the in-flight instruction (for multi-cycle commit)
  logic [31:0]  insn_pc;
  logic [15:0]  insn_ir;

  // Snapshot of architectural state at instruction ISSUE (used for multi-cycle commit/fault tracing)
  logic [8:0]   insn_dsp0;
  logic [15:0]  insn_tos0;
  logic [15:0]  insn_status0;
  logic [15:0]  insn_aux0;
  logic         insn_halted0;
  logic         insn_faulted0;

  // Snapshot of architectural state BEFORE the committed instruction (stable on dbg_commit)
  logic [8:0]   dbg_dsp_before_r;
  logic [15:0]  dbg_tos_before_r;
  logic [15:0]  dbg_status_before_r;
  logic [15:0]  dbg_aux_before_r;
  logic         dbg_halted_before_r;
  logic         dbg_faulted_before_r;


  // Commit/trace registers (pulse on architectural commit)
  logic         dbg_commit_r;
  logic [31:0]  dbg_pc_r;
  logic [15:0]  dbg_ir_r;
  logic [8:0]   inv_arg_idx;        // Current arg being marshalled
  logic [8:0]   inv_res_idx;        // Current result being pushed
  prim_meta_t   inv_meta_latch;     // Primitive metadata for current INVOKE

  // Budget watchdog for INVOKE
  logic [31:0]  inv_budget;
  logic [31:0]  inv_timer;

  // =========================================================================
  // Instruction memory
  // =========================================================================
  localparam int unsigned PWORDS = (PROG_LEN != 0) ? PROG_LEN : PROG_WORDS;
  // Gate the instruction memory address when PC is out-of-bounds.
  // This avoids spurious reads at a truncated address on the same cycle an OOB fault is raised.
  assign imem_addr = (arch_pc < 32'(PWORDS)) ? arch_pc[$clog2(PROG_WORDS)-1:0] : '0;

  // =========================================================================
  // Primitive memory bus — restricted to ARG/RES region (0x00..0x3F)
  // =========================================================================
  always_comb begin
    inv_mem_rdata = 16'h0;
    inv_mem_prot  = 1'b0;
    if (inv_mem_valid) begin
      if (inv_mem_addr > PROT_LO_END) begin
        // Primitive attempting to access outside its allowed region
        inv_mem_prot = 1'b1;
      end else begin
        inv_mem_rdata = ram[inv_mem_addr];
      end
    end
  end

  // =========================================================================
  // Fault helpers
  // =========================================================================
  task automatic trace_commit(input logic [31:0] pc_before, input logic [15:0] ir_word);
    // Commit identifier
    dbg_commit_r <= 1'b1;
    dbg_pc_r     <= pc_before;
    dbg_ir_r     <= ir_word;

    // BEFORE snapshot (current architectural state; correct for single-cycle commits)
    dbg_dsp_before_r     <= dsp;
    dbg_tos_before_r     <= (dsp > 0) ? dstack[dsp-1] : 16'h0;
    dbg_status_before_r  <= ram[STATUS_ADDR];
    dbg_aux_before_r     <= ram[AUX_ADDR];
    dbg_halted_before_r  <= halted;
    dbg_faulted_before_r <= faulted;
  endtask

  task automatic trace_commit_pre(input logic [31:0] pc_before, input logic [15:0] ir_word);
    // Commit identifier
    dbg_commit_r <= 1'b1;
    dbg_pc_r     <= pc_before;
    dbg_ir_r     <= ir_word;

    // BEFORE snapshot (latched at instruction ISSUE; required for multi-cycle commits)
    dbg_dsp_before_r     <= insn_dsp0;
    dbg_tos_before_r     <= insn_tos0;
    dbg_status_before_r  <= insn_status0;
    dbg_aux_before_r     <= insn_aux0;
    dbg_halted_before_r  <= insn_halted0;
    dbg_faulted_before_r <= insn_faulted0;
  endtask

  task automatic do_fault_here(
    input logic [31:0] pc_before,
    input logic [15:0] ir_word,
    input logic [15:0] status,
    input logic [15:0] aux_val
  );
    // Capture BEFORE snapshot prior to mutating STATUS/AUX/HALT.
    trace_commit(pc_before, ir_word);

    // Fault becomes the committed architectural outcome.
    ram[STATUS_ADDR] <= status;
    ram[AUX_ADDR]    <= aux_val;
    halted  <= 1'b1;
    faulted <= 1'b1;
    state   <= S_FAULT;
  endtask

  task automatic do_fault_current(input logic [15:0] status, input logic [15:0] aux_val);
    // Attribute fault to the in-flight instruction (insn_pc/insn_ir) and
    // use the ISSUE snapshot for BEFORE tracing (important for multi-cycle ops).
    ram[STATUS_ADDR] <= status;
    ram[AUX_ADDR]    <= aux_val;
    halted  <= 1'b1;
    faulted <= 1'b1;
    state   <= S_FAULT;
    trace_commit_pre(insn_pc, insn_ir);
  endtask

  // =========================================================================
  // Stack helpers
  // =========================================================================
  // These are inline in the always_ff block; helpers shown here for clarity.

  function automatic logic [15:0] tos_v();
    return (dsp > 0) ? dstack[dsp-1] : 16'h0;
  endfunction

  // =========================================================================
  // Debug outputs
  // =========================================================================
  // Commit/trace interface:
  //  - dbg_commit pulses for 1 cycle when an instruction commits.
  //  - dbg_pc/dbg_ir identify the instruction that committed (pc_before, ir).
  //  - dbg_pc_after and other dbg_* reflect architectural state after commit.
  assign dbg_commit  = dbg_commit_r;
  assign dbg_pc      = dbg_pc_r;
  assign dbg_pc_after= arch_pc;
  assign dbg_ir      = dbg_ir_r;
  assign dbg_dsp     = dsp;
  assign dbg_tos     = tos_v();
  assign dbg_status  = ram[STATUS_ADDR];
  assign dbg_aux     = ram[AUX_ADDR];
  assign dbg_halted  = halted;
  assign dbg_faulted = faulted;

  assign dbg_dsp_before     = dbg_dsp_before_r;
  assign dbg_tos_before     = dbg_tos_before_r;
  assign dbg_status_before  = dbg_status_before_r;
  assign dbg_aux_before     = dbg_aux_before_r;
  assign dbg_halted_before  = dbg_halted_before_r;
  assign dbg_faulted_before = dbg_faulted_before_r;

  // AFTER snapshots are just aliases of the current architectural outputs.
  assign dbg_dsp_after     = dsp;
  assign dbg_tos_after     = tos_v();
  assign dbg_status_after  = ram[STATUS_ADDR];
  assign dbg_aux_after     = ram[AUX_ADDR];
  assign dbg_halted_after  = halted;
  assign dbg_faulted_after = faulted;

  // =========================================================================
  // INVOKE outputs
  // =========================================================================
  assign inv_valid = (state == S_INV_WAIT);
  assign inv_bank  = ir_a;
  assign inv_idx   = ir_b;

  // =========================================================================
  // Reset and main pipeline
  // =========================================================================
  always_ff @(posedge clk or posedge rst) begin
    if (rst) begin
      state       <= S_FETCH;
      arch_pc     <= 32'h0;
      dsp         <= 9'h0;
      halted      <= 1'b0;
      faulted     <= 1'b0;
      ir_reg      <= 16'h0;
      insn_pc     <= 32'h0;
      insn_ir     <= 16'h0;
      insn_dsp0    <= 9'h0;
      insn_tos0    <= 16'h0;
      insn_status0 <= 16'h0;
      insn_aux0    <= 16'h0;
      insn_halted0 <= 1'b0;
      insn_faulted0<= 1'b0;

      dbg_dsp_before_r     <= 9'h0;
      dbg_tos_before_r     <= 16'h0;
      dbg_status_before_r  <= 16'h0;
      dbg_aux_before_r     <= 16'h0;
      dbg_halted_before_r  <= 1'b0;
      dbg_faulted_before_r <= 1'b0;
      dbg_commit_r<= 1'b0;
      dbg_pc_r    <= 32'h0;
      dbg_ir_r    <= 16'h0;
      inv_arg_idx <= 9'h0;
      inv_res_idx <= 9'h0;
      inv_timer   <= 32'h0;
      inv_budget  <= 32'h0;
      inv_meta_latch <= '0;
      for (int i = 0; i < 256; i++) ram[i] <= 16'h0;
      for (int i = 0; i < 256; i++) dstack[i] <= 16'h0;
    end else begin
      automatic bit mem_fault;

      // default: no commit this cycle
      dbg_commit_r <= 1'b0;
// Handle primitive mem-bus write (always live during INVOKE stall)
// IMPORTANT: if this triggers a fault, do not allow later state logic
// in the same cycle to overwrite state <= S_FAULT.
mem_fault = 1'b0;

if (inv_mem_valid && inv_mem_we && state == S_INV_WAIT) begin
  if (inv_mem_addr <= 8'h7F) begin
    ram[inv_mem_addr] <= inv_mem_wdata;
  end else begin
    // Primitive violated memory restriction: fault the in-flight INVOKE.
    do_fault_current(ST_MEM_PROT, {8'h00, inv_mem_addr});
    mem_fault = 1'b1;
  end
end

if (!mem_fault) begin
  case (state)

        // -----------------------------------------------------------------
        S_FETCH: begin
          if (arch_pc >= 32'(PWORDS)) begin
            // Fault-at-PC event (no instruction word committed at this PC).
            do_fault_here(arch_pc, 16'h0000, ST_PC_OOB, 16'(arch_pc));
          end else begin
            state <= S_EXEC;
          end
        end

        // -----------------------------------------------------------------
        S_EXEC: begin
          // Capture identity of the in-flight instruction (used for multi-cycle commit)
          insn_pc <= arch_pc;
          insn_ir <= imem_rdata;

          // Capture ISSUE snapshot (for multi-cycle instruction tracing)
          insn_dsp0     <= dsp;
          insn_tos0     <= tos_v();
          insn_status0  <= ram[STATUS_ADDR];
          insn_aux0     <= ram[AUX_ADDR];
          insn_halted0  <= halted;
          insn_faulted0 <= faulted;

          ir_reg <= imem_rdata;
          ir_op  <= imem_rdata[15:12];
          ir_a   <= imem_rdata[11:8];
          ir_b   <= imem_rdata[7:0];

          automatic logic [3:0]  op  = imem_rdata[15:12];
          automatic logic [3:0]  A   = imem_rdata[11:8];
          automatic logic [7:0]  B   = imem_rdata[7:0];
          automatic logic [15:0] tos = tos_v();
          automatic logic [15:0] nos = (dsp > 1) ? dstack[dsp-2] : 16'h0;
          automatic logic [15:0] result;
          automatic logic [7:0]  addr8;

          case (op)

            OP_NOP: begin
              if (A != 4'h0 || B != 8'h00) begin
                do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              end else begin
                arch_pc <= arch_pc + 1;
                state   <= S_FETCH;
	                trace_commit(arch_pc, imem_rdata);
              end
            end

            OP_LIT: begin
              if (dsp >= 256) begin
                do_fault_here(arch_pc, imem_rdata, ST_DSTACK_OF, imem_rdata);
              end else begin
                dstack[dsp] <= {A, B};
                dsp         <= dsp + 1;
                arch_pc     <= arch_pc + 1;
                state       <= S_FETCH;
	                trace_commit(arch_pc, imem_rdata);
              end
            end

            OP_LIT16: begin
              if (A != 4'h0 || B != 8'h00) begin
                do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              end else if (arch_pc + 1 >= 32'(PWORDS)) begin
                do_fault_here(arch_pc, imem_rdata, ST_PC_OOB, 16'(arch_pc + 1));
              end else begin
                arch_pc <= arch_pc + 1;   // point at data word
                state   <= S_LIT16_FETCH;
              end
            end

            OP_STACK: begin
              case (A)
                STACK_DUP: begin
                  if (dsp == 0)     do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else if (dsp >= 256) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_OF, imem_rdata);
                  else begin
                    dstack[dsp] <= dstack[dsp-1];
                    dsp         <= dsp + 1;
                    arch_pc     <= arch_pc + 1;
                    state       <= S_FETCH;
	                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                STACK_DROP: begin
                  if (dsp == 0) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    dsp     <= dsp - 1;
                    arch_pc <= arch_pc + 1;
                    state   <= S_FETCH;
	                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                STACK_SWAP: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    dstack[dsp-1] <= nos;
                    dstack[dsp-2] <= tos;
                    arch_pc <= arch_pc + 1;
                    state   <= S_FETCH;
	                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                STACK_OVER: begin
                  if (dsp < 2)     do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else if (dsp >= 256) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_OF, imem_rdata);
                  else begin
                    dstack[dsp] <= nos;
                    dsp         <= dsp + 1;
                    arch_pc     <= arch_pc + 1;
                    state       <= S_FETCH;
	                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              endcase
            end

            OP_ALU: begin
              case (A)
                ALU_XOR: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= tos ^ nos; dsp <= dsp-1; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_AND: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= tos & nos; dsp <= dsp-1; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_OR: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= tos | nos; dsp <= dsp-1; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_NOT: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-1] <= ~tos; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_ADD: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= tos + nos; dsp <= dsp-1; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_SUB: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= nos - tos; dsp <= dsp-1; arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_SHL: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-1] <= tos << shamt4(B); arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_SHR: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-1] <= tos >> shamt4(B); arch_pc <= arch_pc+1; state <= S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_ROTL: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    logic [3:0] sh = shamt4(B);
                    dstack[dsp-1] <= (tos << sh) | (tos >> (16-sh));
                    arch_pc <= arch_pc+1; state <= S_FETCH;
                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                ALU_ROTR: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    logic [3:0] sh = shamt4(B);
                    dstack[dsp-1] <= (tos >> sh) | (tos << (16-sh));
                    arch_pc <= arch_pc+1; state <= S_FETCH;
                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                ALU_EQ: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= (tos==nos)?16'h1:16'h0; dsp<=dsp-1; arch_pc<=arch_pc+1; state<=S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_LT: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= (nos<tos)?16'h1:16'h0; dsp<=dsp-1; arch_pc<=arch_pc+1; state<=S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                ALU_NEQ: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin dstack[dsp-2] <= (tos!=nos)?16'h1:16'h0; dsp<=dsp-1; arch_pc<=arch_pc+1; state<=S_FETCH; trace_commit(arch_pc, imem_rdata); end
                end
                default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              endcase
            end

            OP_MEM: begin
              case (A)
                MEM_LD: begin
                  if (mem_protected(B)) do_fault_here(arch_pc, imem_rdata, ST_MEM_PROT, {8'h00, B});
                  else if (dsp >= 256) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_OF, imem_rdata);
                  else begin
                    dstack[dsp] <= ram[B];
                    dsp     <= dsp + 1;
                    arch_pc <= arch_pc + 1;
                    state   <= S_FETCH;
                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                MEM_ST: begin
                  if (mem_protected(B)) do_fault_here(arch_pc, imem_rdata, ST_MEM_PROT, {8'h00, B});
                  else if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    ram[B]  <= dstack[dsp-1];
                    dsp     <= dsp - 1;
                    arch_pc <= arch_pc + 1;
                    state   <= S_FETCH;
                    trace_commit(arch_pc, imem_rdata);
                  end
                end
                MEM_LDI: begin
                  if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    addr8 = tos[7:0];
                    if (mem_protected(addr8)) do_fault_here(arch_pc, imem_rdata, ST_MEM_PROT, {8'h00, addr8});
                    else begin
                      dstack[dsp-1] <= ram[addr8];
                      arch_pc <= arch_pc + 1;
                      state   <= S_FETCH;
                      trace_commit(arch_pc, imem_rdata);
                    end
                  end
                end
                MEM_STI: begin
                  if (dsp < 2) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                  else begin
                    addr8 = tos[7:0];
                    if (mem_protected(addr8)) do_fault_here(arch_pc, imem_rdata, ST_MEM_PROT, {8'h00, addr8});
                    else begin
                      ram[addr8] <= nos;
                      dsp     <= dsp - 2;
                      arch_pc <= arch_pc + 1;
                      state   <= S_FETCH;
                      trace_commit(arch_pc, imem_rdata);
                    end
                  end
                end
                default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              endcase
            end

            OP_CTRL: begin
              // Canonical CTRL semantics live in j16_isa_pkg helpers.
              // Backward branches are illegal encodings (structural rule, not a runtime mode).
              if (!ctrl_b_legal(B)) begin
                do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              end else begin
                automatic logic [31:0] tgt = ctrl_target(arch_pc, B);
                case (A)
                  CTRL_JMP: begin
                    arch_pc <= tgt;
                    state   <= S_FETCH;
                    trace_commit(arch_pc, imem_rdata);
                  end
                  CTRL_JZ: begin
                    if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                    else begin
                      arch_pc <= (tos == 16'h0) ? tgt : arch_pc + 1;
                      dsp     <= dsp - 1;
                      state   <= S_FETCH;
                      trace_commit(arch_pc, imem_rdata);
                    end
                  end
                  CTRL_JNZ: begin
                    if (dsp < 1) do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, imem_rdata);
                    else begin
                      arch_pc <= (tos != 16'h0) ? tgt : arch_pc + 1;
                      dsp     <= dsp - 1;
                      state   <= S_FETCH;
                      trace_commit(arch_pc, imem_rdata);
                    end
                  end
                  default: begin
                    // A >= 0x3: CALL and RET — permanently removed from J16 v2
                    do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
                  end
                endcase
              end
            end

            OP_INVOKE: begin
              automatic logic [15:0] fid = {A, B};
              automatic int          fid_i = int'(fid);

              // Unknown primitive
              if (!ENFORCE_PRIM_META || !prim_valid[fid_i]) begin
                do_fault_here(arch_pc, imem_rdata, ST_UNKNOWN_INVOKE, fid);
              end else begin
                automatic prim_meta_t meta = prim_by_id[fid_i];

                // Capability check
                if (!ALLOW_CAPS[int'(meta.cap_id)]) begin
                  do_fault_here(arch_pc, imem_rdata, ST_UNKNOWN_INVOKE, fid);
                end
                // Determinism check (all primitives must be deterministic in J16 v2)
                else if (!meta.deterministic) begin
                  do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, fid);
                end
                // Pre-flight stack bounds check
                else if (int'(dsp) - int'(meta.pops) + int'(meta.pushes) > 256) begin
                  do_fault_here(arch_pc, imem_rdata, ST_DSTACK_OF, fid);
                end
                else if (dsp < {1'b0, meta.pops}) begin
                  do_fault_here(arch_pc, imem_rdata, ST_DSTACK_UF, fid);
                end
                else begin
                  // Latch metadata, begin argument marshalling
                  inv_meta_latch <= meta;
                  inv_arg_idx    <= 9'h0;
                  inv_res_idx    <= 9'h0;

                  // Compute budget for watchdog (clamp to >=1 to avoid immediate timeout)
automatic logic [31:0] bud;
if (meta.model == 4'h0)
  bud = 32'(meta.base_cycles);
else
  bud = 32'(meta.base_cycles) + 32'(meta.per_cycles) * 32'(meta.max_units);
if (bud == 32'h0) bud = 32'h1;
inv_budget <= bud;

                  inv_timer <= 32'h0;

                  state <= S_INV_ARG;
                end
              end
            end

            OP_SYS: begin
              case (A)
                SYS_HALT: begin
                  ram[STATUS_ADDR] <= ST_OK;
                  ram[AUX_ADDR]    <= 16'h0;
                  halted  <= 1'b1;
                  faulted <= 1'b0;
                  state   <= S_HALT;
                  trace_commit(arch_pc, imem_rdata);
                end
                SYS_TRAP: begin
                  do_fault_here(arch_pc, imem_rdata, ST_TRAP, {8'h00, B});
                end
                default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);
              endcase
            end

            default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, imem_rdata);

          endcase
        end // S_EXEC

        // -----------------------------------------------------------------
        S_LIT16_FETCH: begin
          // arch_pc now points at the data word; wait one cycle for imem_rdata
          state <= S_LIT16_PUSH;
        end

        S_LIT16_PUSH: begin
          // imem_rdata is the 16-bit literal
          if (dsp >= 256) begin
            // Fault is attributed to the original LIT16 instruction, not the data word.
            do_fault_current(ST_DSTACK_OF, 16'(insn_pc));
          end else begin
            dstack[dsp] <= imem_rdata;
            dsp         <= dsp + 1;
            arch_pc     <= arch_pc + 1;
            state       <= S_FETCH;
            trace_commit_pre(insn_pc, insn_ir);
          end
        end

        // -----------------------------------------------------------------
        S_INV_ARG: begin
          // Pop arguments from data stack, write to mem[ARG_BASE + inv_arg_idx]
          if (inv_arg_idx < {1'b0, inv_meta_latch.pops}) begin
            ram[ARG_BASE + inv_arg_idx[7:0]] <= dstack[dsp-1];
            dsp         <= dsp - 1;
            inv_arg_idx <= inv_arg_idx + 1;
          end else begin
            // All args marshalled; start INVOKE handshake
            inv_timer <= 32'h0;
            state     <= S_INV_WAIT;
          end
        end

        // -----------------------------------------------------------------
        S_INV_WAIT: begin
          // Waiting for primitive to complete
          // Budget watchdog
          inv_timer <= inv_timer + 1;
          if (inv_timer >= inv_budget) begin
	          do_fault_current(ST_INVOKE_TIMEOUT, {ir_a, ir_b});
          end else if (inv_done) begin
            // Primitive completed
            ram[STATUS_ADDR] <= inv_status;
            ram[AUX_ADDR]    <= inv_aux;
            if (inv_status != ST_OK) begin
              halted  <= 1'b1;
              faulted <= 1'b1;
              state   <= S_FAULT;
	            trace_commit_pre(insn_pc, insn_ir);
            end else begin
              inv_res_idx <= 9'h0;
              state       <= S_INV_RES;
            end
          end
        end

        // -----------------------------------------------------------------
        S_INV_RES: begin
          // Push results from mem[RES_BASE + inv_res_idx] onto data stack
          if (inv_res_idx < {1'b0, inv_meta_latch.pushes}) begin
            dstack[dsp]  <= ram[RES_BASE + inv_res_idx[7:0]];
            dsp          <= dsp + 1;
            inv_res_idx  <= inv_res_idx + 1;
          end else begin
            arch_pc <= arch_pc + 1;
            state   <= S_FETCH;
            trace_commit_pre(insn_pc, insn_ir);
          end
        end

        // -----------------------------------------------------------------
        S_FAULT, S_HALT: begin
          // Stable terminal states. Wait for reset.
        end

        default: do_fault_here(arch_pc, imem_rdata, ST_ILLEGAL_ENC, 16'hDEAD);

      endcase
      end
    end
  end

endmodule
