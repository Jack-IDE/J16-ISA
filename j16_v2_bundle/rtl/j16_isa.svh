// Auto-generated from docs/isa_v2.json (J16 ISA v2, v2.0)
// DO NOT EDIT BY HAND. Run: make gen-isa
// JSON sha256: a32a5f8cb1e4
// Generated: 2026-03-23
//
// Design intent: Non-Turing-complete ISA. Security properties are structural.
// CALL/RET do not exist. Backward branches are illegal encodings.
// No return stack. No profile mode switch.

`ifndef J16_ISA_SVH
`define J16_ISA_SVH

package j16_isa_pkg;

  // === Encoding constants ===
  localparam int unsigned J16_WORD_BITS = 16;
  localparam int unsigned J16_OP_BITS   = 4;
  localparam int unsigned J16_A_BITS    = 4;
  localparam int unsigned J16_B_BITS    = 8;

  // === Primary opcodes (OP field [15:12]) ===
  localparam logic [3:0] OP_NOP    = 4'h0;
  localparam logic [3:0] OP_ALU    = 4'h1;
  localparam logic [3:0] OP_LIT    = 4'h2;
  localparam logic [3:0] OP_MEM    = 4'h3;
  localparam logic [3:0] OP_CTRL   = 4'h4;
  localparam logic [3:0] OP_STACK  = 4'h5;
  localparam logic [3:0] OP_LIT16  = 4'h6;
  localparam logic [3:0] OP_INVOKE = 4'hB;
  localparam logic [3:0] OP_SYS    = 4'hF;

  // === ALU subops ===
  localparam logic [3:0] ALU_XOR  = 4'h0;
  localparam logic [3:0] ALU_AND  = 4'h1;
  localparam logic [3:0] ALU_OR   = 4'h2;
  localparam logic [3:0] ALU_NOT  = 4'h3;
  localparam logic [3:0] ALU_ADD  = 4'h4;
  localparam logic [3:0] ALU_SUB  = 4'h5;
  localparam logic [3:0] ALU_SHL  = 4'h6;
  localparam logic [3:0] ALU_SHR  = 4'h7;
  localparam logic [3:0] ALU_ROTL = 4'h8;
  localparam logic [3:0] ALU_ROTR = 4'h9;
  localparam logic [3:0] ALU_EQ   = 4'hA;
  localparam logic [3:0] ALU_LT   = 4'hB;
  localparam logic [3:0] ALU_NEQ  = 4'hC;
  localparam logic [15:0] ALU_VALID_MASK = 16'h1FFF;  // bit[a]=1 iff ALU subop A is legal

  // === MEM subops ===
  localparam logic [3:0] MEM_LD  = 4'h0;
  localparam logic [3:0] MEM_ST  = 4'h1;
  localparam logic [3:0] MEM_LDI = 4'h2;
  localparam logic [3:0] MEM_STI = 4'h3;

  // === STACK subops ===
  localparam logic [3:0] STACK_DUP  = 4'h0;
  localparam logic [3:0] STACK_DROP = 4'h1;
  localparam logic [3:0] STACK_SWAP = 4'h2;
  localparam logic [3:0] STACK_OVER = 4'h3;

  // === CTRL subops (A < 0x3 only; A >= 0x3 is ST_ILLEGAL_ENC) ===
  // NOTE: CTRL_CALL and CTRL_RET DO NOT EXIST in J16 v2.
  localparam logic [3:0] CTRL_JMP = 4'h0;
  localparam logic [3:0] CTRL_JZ  = 4'h1;
  localparam logic [3:0] CTRL_JNZ = 4'h2;

  // === SYS subops ===
  localparam logic [3:0] SYS_HALT = 4'h0;
  localparam logic [3:0] SYS_TRAP = 4'h1;

  // === Memory map (frozen) ===
  localparam logic [7:0]  ARG_BASE             = 8'h00;
  localparam logic [7:0]  RES_BASE             = 8'h20;
  localparam logic [7:0]  USER_START           = 8'h40;
  localparam logic [7:0]  USER_END             = 8'hFD;
  localparam logic [7:0]  AUX_ADDR             = 8'hFE;
  localparam logic [7:0]  STATUS_ADDR          = 8'hFF;
  localparam logic [7:0]  PROT_LO_END          = 8'h3F;
  localparam logic [7:0]  PROT_HI_START        = 8'hFE;

  // ABI dimensions
  localparam int unsigned ABI_MAX_ARGS = 32;
  localparam int unsigned ABI_MAX_RETS = 32;

  // === Status codes (frozen) ===
  localparam logic [15:0] ST_OK                  = 16'h0000;
  localparam logic [15:0] ST_UNKNOWN_INVOKE      = 16'h0001;  // aux: full_id
  localparam logic [15:0] ST_DSTACK_UF           = 16'h0002;
  localparam logic [15:0] ST_DSTACK_OF           = 16'h0003;
  localparam logic [15:0] ST_PC_OOB              = 16'h0004;  // aux: pc_low16
  localparam logic [15:0] ST_ILLEGAL_ENC         = 16'h0005;  // aux: ir_word
  localparam logic [15:0] ST_TRAP                = 16'h0006;  // aux: trap_code
  localparam logic [15:0] ST_MEM_PROT            = 16'h0007;  // aux: Replaces ST_J16T_VIOL. Covers program MEM to protected region AND invoke membus outside ARG/RES.
  localparam logic [15:0] ST_INVOKE_TIMEOUT      = 16'h0008;  // aux: Primitive exceeded declared cycle budget.

  // === Semantic helper functions ===

  function automatic logic signed [31:0] sext8(input logic [7:0] b);
    sext8 = $signed({{24{{b[7]}}, b}});
  endfunction

  function automatic logic [31:0] ctrl_target(input logic [31:0] pc_before, input logic [7:0] b);
    ctrl_target = pc_before + 32'd1 + logic'(sext8(b));
  endfunction

  function automatic logic [3:0] shamt4(input logic [7:0] b);
    shamt4 = b[3:0];
  endfunction

  function automatic logic mem_protected(input logic [7:0] addr);
    mem_protected = ((addr <= PROT_LO_END) || (addr >= PROT_HI_START));
  endfunction

  function automatic logic ctrl_b_legal(input logic [7:0] b);
    ctrl_b_legal = (b[7] == 1'b0);
  endfunction

  // === Primitive registry field constants (128-bit row) ===
  localparam int unsigned PRIM_ROW_BITS         = 128;
  localparam int unsigned PRIM_FULL_ID_HI        = 127;
  localparam int unsigned PRIM_FULL_ID_LO        = 112;
  localparam int unsigned PRIM_MODEL_HI          = 111;
  localparam int unsigned PRIM_MODEL_LO          = 108;
  localparam int unsigned PRIM_UNIT_HI           = 107;
  localparam int unsigned PRIM_UNIT_LO           = 104;
  localparam int unsigned PRIM_MAX_UNITS_HI      = 103;
  localparam int unsigned PRIM_MAX_UNITS_LO      = 88;
  localparam int unsigned PRIM_BASE_CYCLES_HI    = 87;
  localparam int unsigned PRIM_BASE_CYCLES_LO    = 72;
  localparam int unsigned PRIM_PER_CYCLES_HI     = 71;
  localparam int unsigned PRIM_PER_CYCLES_LO     = 56;
  localparam int unsigned PRIM_CAP_ID_HI         = 55;
  localparam int unsigned PRIM_CAP_ID_LO         = 48;
  localparam int unsigned PRIM_POPS_HI           = 47;
  localparam int unsigned PRIM_POPS_LO           = 40;
  localparam int unsigned PRIM_PUSHES_HI         = 39;
  localparam int unsigned PRIM_PUSHES_LO         = 32;
  localparam int unsigned PRIM_DETERMINISTIC_HI  = 31;
  localparam int unsigned PRIM_DETERMINISTIC_LO  = 31;

endpackage

`endif // J16_ISA_SVH
