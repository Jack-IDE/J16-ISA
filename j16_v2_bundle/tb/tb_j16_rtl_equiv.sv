`timescale 1ns/1ps

module tb_j16_rtl_equiv;
  import j16_isa_pkg::*;
  import j16_ref_pkg::*;

  // j16_core state encodings (local, for RTL-internal timing checks)
  localparam logic [3:0] CORE_S_INV_WAIT = 4'h5;

  // ------------------------------------------------------------
  // Clock / reset
  // ------------------------------------------------------------
  logic clk = 1'b0;
  logic rst = 1'b1;
  always #5 clk = ~clk;

  // ------------------------------------------------------------
  // DUT debug/trace
  // ------------------------------------------------------------
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

    localparam int unsigned PWORDS = 1024;

`ifdef PROG_HEXFILE
  localparam string PROG_HEXFILE    = `PROG_HEXFILE;
`else
  localparam string PROG_HEXFILE    = "prog_equiv.hex";
`endif
  localparam string PRIMTAB_HEXFILE = "primtab.hex";

  j16_soc_min #(
    .PROG_WORDS(PWORDS),
    .HEXFILE(PROG_HEXFILE),
    .PRIMTABFILE(PRIMTAB_HEXFILE)
  ) dut (
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

  // ------------------------------------------------------------
  // Reference model + loaders
  // ------------------------------------------------------------
  J16Ref ref;

  // ------------------------------------------------------------
  // Simulation primitive implementation for fid=0x0001
  //   RES[0] = ARG[0] XOR ARG[1]
  // ------------------------------------------------------------
  class PrimXor2 extends J16Prim;
    virtual function void invoke(
      inout logic [15:0] mem [0:255],
      output logic [15:0] status,
      output logic [15:0] aux
    );
      logic [15:0] a, b;
      a = mem[ARG_BASE + 8'h00];
      b = mem[ARG_BASE + 8'h01];
      mem[RES_BASE + 8'h00] = a ^ b;
      status = ST_OK;
      aux    = 16'h0000;
    endfunction
  endclass

  // ------------------------------------------------------------
  // Simulation primitive implementation for fid=0x0002
  //   RES[0] = 0xCAFE
  //   RES[1] = 0xBABE
  // ------------------------------------------------------------
  class PrimTwoResPattern extends J16Prim;
    virtual function void invoke(
      inout logic [15:0] mem [0:255],
      output logic [15:0] status,
      output logic [15:0] aux
    );
      mem[RES_BASE + 8'h00] = 16'hCAFE;
      mem[RES_BASE + 8'h01] = 16'hBABE;
      status = ST_OK;
      aux    = 16'h0000;
    endfunction
  endclass


  task automatic check_equal16(string what, logic [15:0] got, logic [15:0] exp, inout int errs);
    if (got !== exp) begin
      $display("MISMATCH %s: got=%h exp=%h", what, got, exp);
      errs++;
    end
  endtask

  task automatic check_equal32(string what, logic [31:0] got, logic [31:0] exp, inout int errs);
    if (got !== exp) begin
      $display("MISMATCH %s: got=%h exp=%h", what, got, exp);
      errs++;
    end
  endtask

  task automatic check_equal1(string what, logic got, logic exp, inout int errs);
    if (got !== exp) begin
      $display("MISMATCH %s: got=%b exp=%b", what, got, exp);
      errs++;
    end
  endtask

  // ------------------------------------------------------------
  // Lockstep run: one ref step per RTL commit
  // ------------------------------------------------------------
  initial begin
    int errors = 0;
    int cycles = 0;
    int commits = 0;

`ifdef EXPECT_TIMING
    bit inv2_seen = 0;
    bit inv2_in_wait = 0;
    int inv2_wait_cycles = 0;
    int inv2_budget = 0;
    int inv2_timer_max = 0;
`endif

    ref = new();
    ref.load_hex(PROG_HEXFILE);
    ref.load_primtab(PRIMTAB_HEXFILE);
    // Register a simulation implementation for fid=0x0001 so INVOKE has an observable effect.
    if (!ref.prim_meta.exists(16'h0001)) begin
      $fatal(1, "primtab is missing fid 0x0001 (required by prog_equiv.hex)");
    end
    ref.register_prim(ref.prim_meta[16'h0001], new PrimXor2());

    // Register a simulation implementation for fid=0x0002 (multi-RES + timing test).
    if (ref.prim_meta.exists(16'h0002)) begin
      ref.register_prim(ref.prim_meta[16'h0002], new PrimTwoResPattern());
    end


    // reset
    rst = 1'b1;
    repeat (5) @(posedge clk);
    rst = 1'b0;

    // Run until HALT/fault or watchdog
    while (cycles < 5000) begin
      @(posedge clk);
      #1; // observe post-NBA values
      cycles++;

`ifdef EXPECT_TIMING
      // RTL-only timing validation for primitive fid=0x0002:
      // - Measure how long the core stays in S_INV_WAIT.
      // - Ensure it runs "late" (near inv_budget) but does not time out.
      if (!inv2_seen) begin
        if (dut.u_core.state == CORE_S_INV_WAIT && {dut.u_core.ir_a, dut.u_core.ir_b} == 16'h0002) begin
          inv2_seen       = 1'b1;
          inv2_in_wait    = 1'b1;
          inv2_wait_cycles = 0;
          inv2_budget     = int'(dut.u_core.inv_budget);
          inv2_timer_max  = int'(dut.u_core.inv_timer);
        end
      end else if (inv2_in_wait) begin
        inv2_wait_cycles++;
        if (int'(dut.u_core.inv_timer) > inv2_timer_max) inv2_timer_max = int'(dut.u_core.inv_timer);

        if (dut.u_core.state != CORE_S_INV_WAIT) begin
          // Left wait state: check expectations.
          if (inv2_budget != 10) begin
            $display("ERROR: fid=0x0002 inv_budget expected 10, got %0d", inv2_budget);
            errors++;
          end
          if (inv2_wait_cycles < (inv2_budget - 2)) begin
            $display("ERROR: fid=0x0002 INVOKE finished too early: wait_cycles=%0d budget=%0d", inv2_wait_cycles, inv2_budget);
            errors++;
          end
          if (inv2_wait_cycles > inv2_budget) begin
            $display("ERROR: fid=0x0002 INVOKE waited too long (risking timeout): wait_cycles=%0d budget=%0d", inv2_wait_cycles, inv2_budget);
            errors++;
          end
          if (inv2_timer_max < (inv2_budget - 2)) begin
            $display("ERROR: fid=0x0002 inv_timer did not advance as expected: timer_max=%0d budget=%0d", inv2_timer_max, inv2_budget);
            errors++;
          end

          inv2_in_wait = 1'b0;
        end
      end
`endif

      if (dbg_commit) begin
        commits++;

        // Reference pc/ir BEFORE stepping
        logic [31:0] ref_pc_before;
        logic [15:0] ref_ir_before;
        ref_pc_before = ref.arch_pc;
        if (int'(ref_pc_before) < ref.rom.size()) ref_ir_before = ref.rom[int'(ref_pc_before)];
        else ref_ir_before = 16'h0000;

        check_equal32($sformatf("commit_pc (commit #%0d)", commits), dbg_pc, ref_pc_before, errors);
        check_equal16($sformatf("commit_ir (commit #%0d)", commits), dbg_ir, ref_ir_before, errors);

        // Compare architectural BEFORE-snapshot (latched by RTL on dbg_commit)
        if (dbg_dsp_before !== ref.dsp) begin
          $display("MISMATCH dsp_before: got=%0d exp=%0d", dbg_dsp_before, ref.dsp);
          errors++;
        end
        check_equal16("tos_before", dbg_tos_before, ref.tos_val(), errors);
        check_equal16("status_before", dbg_status_before, ref.mem[STATUS_ADDR], errors);
        check_equal16("aux_before", dbg_aux_before, ref.mem[AUX_ADDR], errors);
        check_equal1("halted_before", dbg_halted_before, ref.halted, errors);
        check_equal1("faulted_before", dbg_faulted_before, ref.faulted, errors);

        // Step reference once per RTL commit
        void'(ref.step());

        // Compare architectural AFTER-state
        check_equal32("pc_after", dbg_pc_after, ref.arch_pc, errors);
        if (dbg_dsp_after !== ref.dsp) begin
          $display("MISMATCH dsp_after: got=%0d exp=%0d", dbg_dsp_after, ref.dsp);
          errors++;
        end
        check_equal16("tos_after", dbg_tos_after, ref.tos_val(), errors);
        check_equal16("status_after", dbg_status_after, ref.mem[STATUS_ADDR], errors);
        check_equal16("aux_after", dbg_aux_after, ref.mem[AUX_ADDR], errors);
        check_equal1("halted_after", dbg_halted_after, ref.halted, errors);
        check_equal1("faulted_after", dbg_faulted_after, ref.faulted, errors);

        if (dbg_halted_after) begin
          break;
        end
      end
    end

    if (!dbg_halted) begin
      $display("ERROR: watchdog timeout (cycles=%0d commits=%0d)", cycles, commits);
      errors++;
    end

    // ------------------------------------------------------------
    // End-of-run expectations (make the test meaningful, not just lockstep).
    // ------------------------------------------------------------
`ifdef EXPECT_FAULT
    if (!dbg_faulted) begin
      $display("ERROR: expected a fault, but RTL ended without fault (status=%h aux=%h)", dbg_status, dbg_aux);
      errors++;
    end
`elsif EXPECT_TIMING
    if (dbg_faulted) begin
      $display("ERROR: expected clean HALT, but RTL faulted (status=%h aux=%h)", dbg_status, dbg_aux);
      errors++;
    end
    if (!inv2_seen) begin
      $display("ERROR: timing test did not observe fid=0x0002 entering S_INV_WAIT");
      errors++;
    end
    if (inv2_in_wait) begin
      $display("ERROR: timing test ended while still in S_INV_WAIT");
      errors++;
    end
    // Observable check: fid=0x0002 results stored into user RAM[0x81..0x82].
    check_equal16("user_ram[0x81] (RTL)", dut.u_core.ram[8'h81], 16'hCAFE, errors);
    check_equal16("user_ram[0x82] (RTL)", dut.u_core.ram[8'h82], 16'hBABE, errors);
    check_equal16("user_mem[0x81] (REF)", ref.mem[8'h81], 16'hCAFE, errors);
    check_equal16("user_mem[0x82] (REF)", ref.mem[8'h82], 16'hBABE, errors);
`else
    if (dbg_faulted) begin
      $display("ERROR: expected clean HALT, but RTL faulted (status=%h aux=%h)", dbg_status, dbg_aux);
      errors++;
    end
    // Observable check: INVOKE result must have been stored to user RAM[0x80].
    check_equal16("user_ram[0x80] (RTL)", dut.u_core.ram[8'h80], 16'h3333, errors);
    check_equal16("user_mem[0x80] (REF)", ref.mem[8'h80], 16'h3333, errors);
`endif


    if (errors == 0) begin
      $display("PASS: lockstep commit-by-commit equivalence (cycles=%0d commits=%0d)", cycles, commits);
      $finish;
    end else begin
      $fatal(1, "FAIL: %0d mismatches (cycles=%0d commits=%0d)", errors, cycles, commits);
    end
  end

endmodule
