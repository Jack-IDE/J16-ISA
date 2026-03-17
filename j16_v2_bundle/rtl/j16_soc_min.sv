// j16_soc_min.sv
// Minimal SoC wrapper: core + imem + invoke stub.

module j16_soc_min #(
  parameter int unsigned PROG_WORDS = 1024,
  parameter string       HEXFILE    = "prog.hex",
  parameter string       PRIMTABFILE = "primtab.hex"
)(
  input  logic clk,
  input  logic rst,

  // Debug/trace passthrough
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

  logic [$clog2(PROG_WORDS)-1:0] imem_addr;
  logic [15:0]                   imem_rdata;

  logic        inv_valid;
  logic [3:0]  inv_bank;
  logic [7:0]  inv_idx;
  logic        inv_ready;
  logic        inv_done;
  logic [15:0] inv_status;
  logic [15:0] inv_aux;

  logic        inv_mem_valid;
  logic        inv_mem_we;
  logic [7:0]  inv_mem_addr;
  logic [15:0] inv_mem_wdata;
  logic [15:0] inv_mem_rdata;
  logic        inv_mem_prot;

  j16_imem #(
    .PROG_WORDS(PROG_WORDS),
    .HEXFILE(HEXFILE)
  ) u_imem(
    .clk(clk),
    .addr(imem_addr),
    .rdata(imem_rdata)
  );

  j16_core #(
    .PROG_WORDS(PROG_WORDS),
    .PROG_LEN(0),
    .PRIMTAB_WORDS(256),
    .PRIMTABFILE(PRIMTABFILE),
    .ENFORCE_PRIM_META(1'b1)
  ) u_core(
    .clk(clk),
    .rst(rst),

    .imem_addr(imem_addr),
    .imem_rdata(imem_rdata),

    .inv_valid(inv_valid),
    .inv_bank(inv_bank),
    .inv_idx(inv_idx),
    .inv_ready(inv_ready),

    .inv_done(inv_done),
    .inv_status(inv_status),
    .inv_aux(inv_aux),

    .inv_mem_valid(inv_mem_valid),
    .inv_mem_we(inv_mem_we),
    .inv_mem_addr(inv_mem_addr),
    .inv_mem_wdata(inv_mem_wdata),
    .inv_mem_rdata(inv_mem_rdata),
    .inv_mem_prot(inv_mem_prot),

    .dbg_commit(dbg_commit),
    .dbg_pc(dbg_pc),
    .dbg_pc_after(dbg_pc_after),
    .dbg_ir(dbg_ir),
    .dbg_dsp(dbg_dsp),
    .dbg_tos(dbg_tos),
    .dbg_status(dbg_status),
    .dbg_aux(dbg_aux),
    .dbg_halted(dbg_halted),
    .dbg_faulted(dbg_faulted),

    .dbg_dsp_before(dbg_dsp_before),
    .dbg_tos_before(dbg_tos_before),
    .dbg_status_before(dbg_status_before),
    .dbg_aux_before(dbg_aux_before),
    .dbg_halted_before(dbg_halted_before),
    .dbg_faulted_before(dbg_faulted_before),

    .dbg_dsp_after(dbg_dsp_after),
    .dbg_tos_after(dbg_tos_after),
    .dbg_status_after(dbg_status_after),
    .dbg_aux_after(dbg_aux_after),
    .dbg_halted_after(dbg_halted_after),
    .dbg_faulted_after(dbg_faulted_after)
  );

  j16_invoke_stub u_invoke(
    .clk(clk),
    .rst(rst),

    .inv_valid(inv_valid),
    .inv_bank(inv_bank),
    .inv_idx(inv_idx),
    .inv_ready(inv_ready),

    .inv_done(inv_done),
    .inv_status(inv_status),
    .inv_aux(inv_aux),

    .inv_mem_valid(inv_mem_valid),
    .inv_mem_we(inv_mem_we),
    .inv_mem_addr(inv_mem_addr),
    .inv_mem_wdata(inv_mem_wdata),
    .inv_mem_rdata(inv_mem_rdata),
    .inv_mem_prot(inv_mem_prot)
  );

endmodule
