// j16_imem.sv
// Simple synchronous instruction ROM for simulation/FPGA bring-up.
//
// - Address is word-addressed.
// - Output is registered (1-cycle latency).
// - Loads from a readmemh-compatible hex file.

module j16_imem #(
  parameter int unsigned PROG_WORDS = 1024,
  parameter string HEXFILE = "prog.hex"
)(
  input  logic clk,
  input  logic [$clog2(PROG_WORDS)-1:0] addr,
  output logic [15:0] rdata
);
  logic [15:0] mem [0:PROG_WORDS-1];

  initial begin
    for (int i = 0; i < PROG_WORDS; i++) mem[i] = 16'h0000;
    $readmemh(HEXFILE, mem);
    rdata = 16'h0000;
  end

  always_ff @(posedge clk) begin
    rdata <= mem[addr];
  end
endmodule
