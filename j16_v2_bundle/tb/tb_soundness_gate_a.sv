`timescale 1ns/1ps
// tb_soundness_gate_a.sv
// Gate A: certifier conservativeness check (runtime cycles/icount vs certificate bounds).
//
// Usage:
//   make sim-gate-a GATE_HEXFILE=prog_equiv.hex
//
// This bench:
//   - Runs j16_certifier on the same hex image to get max_cycles/max_icount.
//   - Runs the RTL core (via j16_soc_min) until HALT/FAULT.
//   - Asserts actual_cycles <= max_cycles (strict) and actual_icount <= max_icount.
//
// Cycle-counting convention (STRICT):
//   - Cycle 0 is the first posedge *after* reset deassertion (rst=0).
//   - We count every subsequent posedge until HALT/FAULT is observed.
//
// This aligns with the certifier's cycle model (CORE_CYCLES_PER_INSN = FETCH+EXEC).

module tb_soundness_gate_a;
  localparam int unsigned PWORDS = 1024;

`ifdef PROG_HEXFILE
  localparam string PROG_HEXFILE    = `PROG_HEXFILE;
`else
  localparam string PROG_HEXFILE    = "prog.hex";
`endif
  localparam string PRIMTAB_HEXFILE = "primtab.hex";
  localparam string ALLOW_HEXFILE   = "allow_prims.hex";

  // --- Certifier outputs
  logic ok;
  logic [15:0] fail_status;
  logic [15:0] fail_word;
  int unsigned fail_pc;
  int unsigned prog_len;
  int unsigned max_icount;
  int unsigned max_cycles;

  j16_certifier #(
    .PROG_WORDS(PWORDS),
    .HEXFILE(PROG_HEXFILE),
    .PRIMTABFILE(PRIMTAB_HEXFILE),
    .ALLOWFILE(ALLOW_HEXFILE),
    .AUTO_LEN(1'b1),
    .EMIT_CERT_JSON(1'b0)
  ) u_cert (
    .ok(ok),
    .fail_status(fail_status),
    .fail_word(fail_word),
    .fail_pc(fail_pc),
    .prog_len(prog_len),
    .max_icount(max_icount),
    .max_cycles(max_cycles)
  );

  // --- RTL SoC
  logic clk;
  logic rst;

  logic        dbg_commit;
  logic [31:0] dbg_pc;
  logic [31:0] dbg_pc_after;
  logic [15:0] dbg_ir;
  logic [8:0]  dbg_dsp;
  logic [15:0] dbg_tos;
  logic [15:0] dbg_status;
  logic [15:0] dbg_aux;
  logic        dbg_halted;
  logic        dbg_faulted;

  logic [8:0]  dbg_dsp_before;
  logic [15:0] dbg_tos_before;
  logic [15:0] dbg_status_before;
  logic [15:0] dbg_aux_before;
  logic        dbg_halted_before;
  logic        dbg_faulted_before;

  logic [8:0]  dbg_dsp_after;
  logic [15:0] dbg_tos_after;
  logic [15:0] dbg_status_after;
  logic [15:0] dbg_aux_after;
  logic        dbg_halted_after;
  logic        dbg_faulted_after;

  j16_soc_min #(
    .PROG_WORDS(PWORDS),
    .HEXFILE(PROG_HEXFILE),
    .PRIMTABFILE(PRIMTAB_HEXFILE)
  ) u_soc (
    .clk(clk),
    .rst(rst),
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

  // Clock
  initial clk = 1'b0;
  always #5 clk = ~clk;

  // Counters
  int unsigned cycles;
  int unsigned icount;
  int unsigned max_dsp_obs;

  initial begin
    cycles = 0;
    icount = 0;
    max_dsp_obs = 0;

    // Give combinational certifier time to settle.
    #1;
    if (!ok) begin
      $fatal(1, "GATE_A_FAIL: certifier failed status=0x%04x pc=%0d word=0x%04x", fail_status, fail_pc, fail_word);
    end

    // Reset
    rst = 1'b1;
    repeat (4) @(posedge clk);
    rst = 1'b0;

    // Run until HALT/FAULT, but never beyond certified max.
    while (1) begin
      @(posedge clk);
      cycles++;
      if (dbg_commit) begin
        icount++;
        if (dbg_dsp > max_dsp_obs) max_dsp_obs = dbg_dsp;
      end
      if (dbg_halted || dbg_faulted) begin
        break;
      end
      if (cycles > max_cycles) begin
        $fatal(1, "GATE_A_FAIL: runtime exceeded cert bound cycles=%0d > max_cycles=%0d", cycles, max_cycles);
      end
    end

    if (dbg_faulted) begin
      $fatal(1, "GATE_A_FAIL: RTL faulted before HALT (pc=%0d ir=0x%04x status=0x%04x)", dbg_pc, dbg_ir, dbg_status);
    end
    if (icount > max_icount) begin
      $fatal(1, "GATE_A_FAIL: icount exceeded cert bound icount=%0d > max_icount=%0d", icount, max_icount);
    end
    if (cycles > max_cycles) begin
      $fatal(1, "GATE_A_FAIL: cycles exceeded cert bound cycles=%0d > max_cycles=%0d", cycles, max_cycles);
    end

    $display("GATE_A_PASS: cycles=%0d icount=%0d max_dsp=%0d cert_max_cycles=%0d cert_max_icount=%0d prog_len=%0d",
             cycles, icount, max_dsp_obs, max_cycles, max_icount, prog_len);
    $finish;
  end

endmodule
