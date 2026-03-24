// j16_invoke_stub.sv
// Minimal INVOKE simulation harness with one deterministic "known-good" primitive.
//
// Why this exists:
// - The core marshals args to ARG[] (0x00..0x1F) and expects results in RES[] (0x20..0x3F).
// - In the original stub, primitives did nothing, leaving RES[] = 0. That exercises the path
//   but does not validate any observable effect.
//
// Implemented primitive (simulation-only):
//   full_id 0x0001 (bank=0x0, idx=0x01)
//     - Reads ARG[0] and ARG[1]
//     - Writes RES[0] = ARG[0] XOR ARG[1]
//     - Returns status=ST_OK
//
// All other primitives keep the original behavior:
//   - Always ready
//   - inv_done after 1 cycle
//   - status=ST_OK, aux=0
//   - No primitive mem accesses
//
// NOTE: Primitive mem-bus is restricted by the core to 0x00..0x3F.

module j16_invoke_stub(
  input  logic clk,
  input  logic rst,

  input  logic        inv_valid,
  input  logic [3:0]  inv_bank,
  input  logic [7:0]  inv_idx,
  output logic        inv_ready,

  output logic        inv_done,
  output logic [15:0] inv_status,
  output logic [15:0] inv_aux,

  output logic        inv_mem_valid,
  output logic        inv_mem_we,
  output logic [7:0]  inv_mem_addr,
  output logic [15:0] inv_mem_wdata,
  input  logic [15:0] inv_mem_rdata,
  input  logic        inv_mem_prot
);

  assign inv_ready = 1'b1;

  // Simple, small FSM to allow mem reads/writes while the core is stalled in S_INV_WAIT.
  typedef enum logic [3:0] {
    ST_IDLE     = 4'd0,
    ST_RD0      = 4'd1,
    ST_RD1      = 4'd2,
    ST_WR0      = 4'd3,
    ST_DONE     = 4'd4,
    ST_PEND     = 4'd5,

    // Primitive 0x0002: multi-RES + near-budget delay
    ST_D2_WAIT  = 4'd6,
    ST_D2_DONE  = 4'd7
  } stub_state_e;

  stub_state_e st;

  logic [15:0] a0, a1, res;
  logic [11:0] full_id;

  logic [4:0]  d2_cnt;

  // Drive primitive mem-bus combinationally from FSM state.
  always_comb begin
    inv_mem_valid = 1'b0;
    inv_mem_we    = 1'b0;
    inv_mem_addr  = 8'h00;
    inv_mem_wdata = 16'h0000;

    unique case (st)
      ST_RD0: begin
        inv_mem_valid = 1'b1;
        inv_mem_we    = 1'b0;
        inv_mem_addr  = 8'h00; // ARG_BASE + 0
      end
      ST_RD1: begin
        inv_mem_valid = 1'b1;
        inv_mem_we    = 1'b0;
        inv_mem_addr  = 8'h01; // ARG_BASE + 1
      end
      ST_WR0: begin
        inv_mem_valid = 1'b1;
        inv_mem_we    = 1'b1;
        inv_mem_addr  = 8'h20; // RES_BASE + 0
        inv_mem_wdata = res;
      end

      // Primitive 0x0002 writes two result words into RES region while staying in ST_D2_WAIT.
      ST_D2_WAIT: begin
        if (d2_cnt == 5'd2) begin
          inv_mem_valid = 1'b1;
          inv_mem_we    = 1'b1;
          inv_mem_addr  = 8'h20; // RES_BASE + 0
          inv_mem_wdata = 16'hCAFE;
        end else if (d2_cnt == 5'd6) begin
          inv_mem_valid = 1'b1;
          inv_mem_we    = 1'b1;
          inv_mem_addr  = 8'h21; // RES_BASE + 1
          inv_mem_wdata = 16'hBABE;
        end
      end
      default: begin end
    endcase

    // If core signals protection violation, we still finish with ST_OK here because
    // the core will fault the in-flight INVOKE itself (ST_MEM_PROT) on that cycle.
    // inv_mem_prot is unused (but we keep the input to avoid lint warnings).
  end

  // unused input (keep for lint)
  wire _unused;
  assign _unused = ^inv_mem_prot;

  always_ff @(posedge clk or posedge rst) begin
    if (rst) begin
      st         <= ST_IDLE;
      inv_done   <= 1'b0;
      inv_status <= 16'h0000; // ST_OK
      inv_aux    <= 16'h0000;
      a0         <= 16'h0000;
      a1         <= 16'h0000;
      res        <= 16'h0000;
      full_id    <= 12'h000;
      d2_cnt     <= 5'd0;
    end else begin
      inv_done <= 1'b0;

      // If the core leaves S_INV_WAIT, inv_valid drops. Reset the stub.
      if (!inv_valid && st != ST_IDLE) begin
        st <= ST_IDLE;
      end else begin
        unique case (st)
          ST_IDLE: begin
            if (inv_valid) begin
              full_id <= {inv_bank, inv_idx};

              // Primitive 0x0001: XOR2
              if ({inv_bank, inv_idx} == 12'h001) begin
                st <= ST_RD0;
              end else if ({inv_bank, inv_idx} == 12'h002) begin
                // Primitive 0x0002: multi-RES + near-budget delay
                d2_cnt <= 5'd0;
                st     <= ST_D2_WAIT;
              end else begin
                // Default behavior: done after 1 cycle.
                st <= ST_PEND;
              end
            end
          end

          // During ST_RD0 cycle, inv_mem_rdata reflects ARG[0]. Capture it.
          ST_RD0: begin
            a0 <= inv_mem_rdata;
            st <= ST_RD1;
          end

          // During ST_RD1 cycle, capture ARG[1], compute res for next cycle.
          ST_RD1: begin
            a1  <= inv_mem_rdata;
            res <= a0 ^ inv_mem_rdata;
            st  <= ST_WR0;
          end

          // During ST_WR0 cycle, core performs the RES[0] write on this posedge.
          ST_WR0: begin
            st <= ST_DONE;
          end

          // Pulse inv_done for one cycle (core will consume it while in S_INV_WAIT).
          ST_DONE: begin
            inv_done   <= 1'b1;
            inv_status <= 16'h0000; // ST_OK
            inv_aux    <= 16'h0000;
            st         <= ST_IDLE;
          end

          // Default primitive completion (no mem operations).
          ST_PEND: begin
            st <= ST_DONE;
          end

          // -----------------------------------------------------------------
          // Primitive 0x0002: multi-RES + near-budget delay
          //
          // Behavior:
          //   - While core is stalled in S_INV_WAIT, we run a small timer.
          //   - We emit two RES writes at well-defined times.
          //   - We finish "late" (close to inv_budget) but before timeout.
          //
          // NOTE: inv_done is registered; the core samples it on the next cycle,
          // so the *observed* completion occurs one cycle after ST_D2_DONE.
          // -----------------------------------------------------------------
          ST_D2_WAIT: begin
            d2_cnt <= d2_cnt + 1;

            // Finish late (near budget) but before timeout.
            // We transition to ST_D2_DONE on d2_cnt==6 so that inv_done is
            // asserted early enough (registered) to be observed by the core
            // while inv_timer is still < inv_budget.
            if (d2_cnt == 5'd6) begin
              st <= ST_D2_DONE;
            end
          end

          ST_D2_DONE: begin
            inv_done   <= 1'b1;
            inv_status <= 16'h0000; // ST_OK
            inv_aux    <= 16'h0000;
            st         <= ST_IDLE;
          end

          default: st <= ST_IDLE;
        endcase
      end
    end
  end

endmodule
