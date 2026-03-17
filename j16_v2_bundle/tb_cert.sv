// tb_cert.sv
// Minimal certifier testbench for Icarus.

module tb_cert;
  logic ok;
  logic [15:0] fail_status;
  logic [15:0] fail_word;
  int unsigned fail_pc;
  int unsigned prog_len;
  int unsigned max_icount;
  int unsigned max_cycles;

  // The certifier prints the JSON certificate via $display when EMIT_CERT_JSON=1.
  // This testbench just checks the structured outputs and prints a short summary.
  j16_certifier #(
    .HEXFILE("prog.hex"),
    .PRIMTABFILE("primtab.hex"),
    .ALLOWFILE("allow_prims.hex"),
    .AUTO_LEN(1'b1),
    .EMIT_CERT_JSON(1'b1)
  ) dut(
    .ok(ok),
    .fail_status(fail_status),
    .fail_word(fail_word),
    .fail_pc(fail_pc),
    .prog_len(prog_len),
    .max_icount(max_icount),
    .max_cycles(max_cycles)
  );

  initial begin
    #1;
    if (!ok) begin
      $display("CERT FAIL: status=%h word=%h pc=%0d", fail_status, fail_word, fail_pc);
      $fatal(1);
    end
    $display("CERT OK: prog_len=%0d max_icount=%0d max_cycles=%0d", prog_len, max_icount, max_cycles);
    $finish;
  end
endmodule
