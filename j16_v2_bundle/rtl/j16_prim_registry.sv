// j16_prim_registry.sv
// Standalone primitive registry ROM (simulation-friendly).
//
// NOTE: j16_core.sv already contains an internal copy of the primitive table
// (primtab.hex) when ENFORCE_PRIM_META=1. This module exists to satisfy the
// Makefile targets and to support future SoC-style wiring where other blocks
// may want primitive metadata.

module j16_prim_registry #(
  parameter int unsigned PRIMTAB_WORDS = 256,
  parameter string PRIMTABFILE = "primtab.hex"
)(
  input  logic        clk,
  input  logic [15:0] full_id,

  output logic        valid,
  output logic [3:0]  model,
  output logic [15:0] max_units,
  output logic [15:0] base_cycles,
  output logic [15:0] per_cycles,
  output logic [7:0]  cap_id,
  output logic [7:0]  pops,
  output logic [7:0]  pushes,
  output logic        deterministic
);

  typedef struct packed {
    logic       valid;
    logic [3:0] model;
    logic [15:0] max_units;
    logic [15:0] base_cycles;
    logic [15:0] per_cycles;
    logic [7:0] cap_id;
    logic [7:0] pops;
    logic [7:0] pushes;
    logic deterministic;
  } prim_meta_t;

  logic [127:0] primtab [0:PRIMTAB_WORDS-1];
  prim_meta_t   tab     [0:4095];

  initial begin
    for (int i = 0; i < PRIMTAB_WORDS; i++) primtab[i] = 128'h0;
    for (int i = 0; i < 4096; i++) tab[i] = '{default:'0};
    $readmemh(PRIMTABFILE, primtab);

    for (int i = 0; i < PRIMTAB_WORDS; i++) begin
      logic [15:0] fid;
      fid = primtab[i][127:112];
      tab[fid].valid         = 1'b1;
      tab[fid].model         = primtab[i][111:108];
      tab[fid].max_units     = primtab[i][103:88];
      tab[fid].base_cycles   = primtab[i][87:72];
      tab[fid].per_cycles    = primtab[i][71:56];
      tab[fid].cap_id        = primtab[i][55:48];
      tab[fid].pops          = primtab[i][47:40];
      tab[fid].pushes        = primtab[i][39:32];
      tab[fid].deterministic = primtab[i][31];
    end
  end

  prim_meta_t m;
  always_comb begin
    m = tab[full_id];
    valid         = m.valid;
    model         = m.model;
    max_units     = m.max_units;
    base_cycles   = m.base_cycles;
    per_cycles    = m.per_cycles;
    cap_id        = m.cap_id;
    pops          = m.pops;
    pushes        = m.pushes;
    deterministic = m.deterministic;
  end
endmodule
