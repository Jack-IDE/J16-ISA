`include "j16_isa.svh"
// j16_ref_pkg.sv — J16 v2 Golden Reference Model
//
// This is the normative software stepper for J16 v2.
// Security properties enforced here match the RTL core exactly:
//   - No CALL, no RET, no return stack.
//   - Backward branches (B[7]=1) are ST_ILLEGAL_ENC, not a runtime mode check.
//   - MEM to protected regions is ST_MEM_PROT.
//   - INVOKE mem-bus is restricted to 0x00..0x7F.
//   - LIT16 (OP=0x6) consumes the next ROM word and advances PC by 2.
//   - Stack overflow pre-checked before INVOKE result push.
//
// There is no PROFILE_T parameter. The security model is the only model.

package j16_ref_pkg;
  import j16_isa_pkg::*;

  // --- Arithmetic helpers ---

  function automatic logic [15:0] rotl16(input logic [15:0] x, input int unsigned sh);
    int unsigned s;
    s = sh & 15;
    if (s == 0) rotl16 = x;
    else rotl16 = (x << s) | (x >> (16 - s));
  endfunction

  function automatic logic [15:0] rotr16(input logic [15:0] x, input int unsigned sh);
    int unsigned s;
    s = sh & 15;
    if (s == 0) rotr16 = x;
    else rotr16 = (x >> s) | (x << (16 - s));
  endfunction

  // --- Trace record (for equivalence checking against RTL) ---
  typedef struct packed {
    logic [31:0] step_idx;
    logic [31:0] pc_before;
    logic [15:0] ir;
    logic [3:0]  op;
    logic [3:0]  A;
    logic [7:0]  B;
    logic [15:0] status;
    logic [15:0] aux;
    logic [8:0]  dsp;     // 0..256 (9-bit count)
    logic [15:0] tos;     // TOS value if DSP>0, else 0
  } j16_trace_t;

  // --- Primitive interface ---
  // Primitives are a closed, registered set. This virtual class is for simulation only.
  // In hardware, primitives are fixed silicon blocks, not dynamic dispatch.
  virtual class J16Prim;
    // Primitive must access only mem[0x00..0x7F] via this interface.
    // Attempting to access outside this range triggers ST_MEM_PROT.
    pure virtual function void invoke(
      inout logic [15:0] mem [0:255],
      output logic [15:0] status,
      output logic [15:0] aux
    );
  endclass

  // --- Primitive registry row ---
  typedef struct {
    logic [15:0] full_id;
    logic [3:0]  model;
    logic [15:0] max_units;
    logic [15:0] base_cycles;
    logic [15:0] per_cycles;
    logic [7:0]  cap_id;
    logic [7:0]  pops;
    logic [7:0]  pushes;
    logic        deterministic;
  } prim_meta_t;

  // --- Main reference machine ---
  class J16Ref;
    // Program ROM
    logic [15:0] rom[];
    int unsigned prog_len;

    // Machine state
    logic [15:0] mem  [0:255];
    logic [15:0] dstack [0:255];
    int unsigned dsp;        // count: 0..256

    // Halt/fault flags
    bit halted;
    bit faulted;

    // Primitive registry (simulation dispatch)
    prim_meta_t prim_meta [int];     // keyed by full_id
    J16Prim     prim_impl [int];     // optional simulation implementations

    // Step counter
    int unsigned steps;

    // --- Lifecycle ---

    function new();
      halted = 0;
      faulted = 0;
      arch_pc = 0;
      dsp = 0;
      steps = 0;
      for (int i = 0; i < 256; i++) mem[i] = 16'h0000;
      for (int i = 0; i < 256; i++) dstack[i] = 16'h0000;
    endfunction

    function void load_hex(string hexfile);
      rom = new[1024];
      $readmemh(hexfile, rom);
      prog_len = 0;
      int halt_idx;
      halt_idx = -1;

      // Length is HALT-terminated: prog_len = last SYS HALT + 1.
      // This matches certifier behavior and prevents zero/NOP padding from truncating analysis.
      for (int i = 1023; i >= 0; i--) begin
        if (rom[i] === 16'hF000) begin
          halt_idx = i;
          break;
        end
      end

      if (halt_idx < 0) begin
        prog_len = 1;
        $display("J16_REF WARN: no SYS HALT (16'hF000) terminator found in ROM; prog_len forced to 1.");
      end else begin
        prog_len = halt_idx + 1;

        // Warn if there are any nonzero words after the terminator.
        for (int j = halt_idx + 1; j < 1024; j++) begin
          if (rom[j] !== 16'h0000) begin
            $display("J16_REF WARN: nonzero ROM word after terminating SYS HALT at word[%0d]: word[%0d]=%h", halt_idx, j, rom[j]);
            break;
          end
        end
      end
    endfunction

    function void register_prim(prim_meta_t meta, J16Prim impl = null);
      int key = int'(meta.full_id);
      prim_meta[key] = meta;
      if (impl != null) prim_impl[key] = impl;
    endfunction

    function void load_primtab(string primtabfile);
      logic [127:0] ptab[0:255];
      $readmemh(primtabfile, ptab);
      for (int i = 0; i < 256; i++) begin
        if (ptab[i] !== 128'h0) begin
          prim_meta_t m;
          m.full_id       = ptab[i][127:112];
          m.model         = ptab[i][111:108];
          m.max_units      = ptab[i][103:88];
          m.base_cycles    = ptab[i][87:72];
          m.per_cycles     = ptab[i][71:56];
          m.cap_id         = ptab[i][55:48];
          m.pops           = ptab[i][47:40];
          m.pushes         = ptab[i][39:32];
          m.deterministic  = ptab[i][31];
          prim_meta[int'(m.full_id)] = m;
        end
      end
    endfunction

    // --- Internal helpers ---

    function automatic logic [31:0] pc();
      return mem[STATUS_ADDR] == ST_OK ? 32'(steps) : 32'hFFFFFFFF;
    endfunction

    // Direct access to the architectural PC stored separately
    logic [31:0] arch_pc;

    function automatic void set_fault(logic [15:0] status, logic [15:0] aux_val);
      mem[STATUS_ADDR] = status;
      mem[AUX_ADDR]    = aux_val;
      halted  = 1;
      faulted = 1;
    endfunction

    // Data stack helpers
    function automatic void push(logic [15:0] v);
      if (dsp >= 256) begin
        set_fault(ST_DSTACK_OF, 16'(arch_pc));
      end else begin
        dstack[dsp] = v;
        dsp++;
      end
    endfunction

    function automatic logic [15:0] pop();
      if (dsp == 0) begin
        set_fault(ST_DSTACK_UF, 16'(arch_pc));
        return 16'hDEAD;
      end else begin
        dsp--;
        return dstack[dsp];
      end
    endfunction

    function automatic logic [15:0] tos_val();
      if (dsp == 0) return 16'h0;
      return dstack[dsp-1];
    endfunction

    function automatic bit mem_prot(logic [7:0] addr);
      return ((addr <= PROT_LO_END) || (addr >= PROT_HI_START));
    endfunction

    // --- Single step ---
    // Returns 1 if execution should continue, 0 if halted/faulted.
    function automatic bit step();
      logic [15:0] ir;
      logic [3:0]  op;
      logic [3:0]  A;
      logic [7:0]  B;
      logic [15:0] a_val, b_val, result;
      logic [7:0]  addr8;
      int unsigned tgt;

      if (halted || faulted) return 0;

      // PC bounds check
      if (arch_pc >= 32'(prog_len)) begin
        set_fault(ST_PC_OOB, 16'(arch_pc));
        return 0;
      end

      ir = rom[arch_pc];
      op = ir[15:12];
      A  = ir[11:8];
      B  = ir[7:0];
      steps++;

      case (op)

        // --- NOP ---
        OP_NOP: begin
          if (A != 4'h0 || B != 8'h00) begin
            set_fault(ST_ILLEGAL_ENC, ir);
            return 0;
          end
          arch_pc++;
        end

        // --- LIT: push 12-bit immediate ---
        OP_LIT: begin
          push({A, B});
          if (!faulted) arch_pc++;
        end

        // --- LIT16: push 16-bit immediate from next ROM word ---
        OP_LIT16: begin
          if (A != 4'h0 || B != 8'h00) begin
            set_fault(ST_ILLEGAL_ENC, ir);
            return 0;
          end
          if (arch_pc + 1 >= 32'(prog_len)) begin
            set_fault(ST_PC_OOB, 16'(arch_pc + 1));
            return 0;
          end
          push(rom[arch_pc + 1]);
          if (!faulted) arch_pc += 2;
        end

// --- STACK manipulation ---
OP_STACK: begin
  case (A)
    STACK_DUP: begin
      if (dsp == 0) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      if (dsp >= 256) begin
        set_fault(ST_DSTACK_OF, ir);
        return 0;
      end
      dstack[dsp] = dstack[dsp-1];
      dsp++;
    end
    STACK_DROP: begin
      if (dsp == 0) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      dsp--;
    end
    STACK_SWAP: begin
      if (dsp < 2) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      a_val = dstack[dsp-1]; // tos
      b_val = dstack[dsp-2]; // nos
      dstack[dsp-1] = b_val;
      dstack[dsp-2] = a_val;
    end
    STACK_OVER: begin
      if (dsp < 2) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      if (dsp >= 256) begin
        set_fault(ST_DSTACK_OF, ir);
        return 0;
      end
      dstack[dsp] = dstack[dsp-2]; // push nos
      dsp++;
    end
    default: begin
      set_fault(ST_ILLEGAL_ENC, ir);
      return 0;
    end
  endcase
  arch_pc++;
end

// --- ALU ---
OP_ALU: begin
  case (A)
    // binary ops (need 2 items, net -1)
    ALU_XOR:  begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = dstack[dsp-2] ^ dstack[dsp-1]; dsp--; end
    ALU_AND:  begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = dstack[dsp-2] & dstack[dsp-1]; dsp--; end
    ALU_OR:   begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = dstack[dsp-2] | dstack[dsp-1]; dsp--; end
    ALU_ADD:  begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = dstack[dsp-2] + dstack[dsp-1]; dsp--; end
    ALU_SUB:  begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = dstack[dsp-2] - dstack[dsp-1]; dsp--; end
    ALU_EQ:   begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = (dstack[dsp-2] == dstack[dsp-1]) ? 16'h1 : 16'h0; dsp--; end
    ALU_LT:   begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = (dstack[dsp-2] <  dstack[dsp-1]) ? 16'h1 : 16'h0; dsp--; end
    ALU_NEQ:  begin if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-2] = (dstack[dsp-2] != dstack[dsp-1]) ? 16'h1 : 16'h0; dsp--; end

    // unary ops (need 1 item, net 0)
    ALU_NOT:  begin if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-1] = ~dstack[dsp-1]; end
    ALU_SHL:  begin if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-1] = dstack[dsp-1] << shamt4(B); end
    ALU_SHR:  begin if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-1] = dstack[dsp-1] >> shamt4(B); end
    ALU_ROTL: begin if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-1] = rotl16(dstack[dsp-1], 32'(shamt4(B))); end
    ALU_ROTR: begin if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
                    dstack[dsp-1] = rotr16(dstack[dsp-1], 32'(shamt4(B))); end
    default: begin
      set_fault(ST_ILLEGAL_ENC, ir);
      return 0;
    end
  endcase
  arch_pc++;
end

// --- MEM ---
OP_MEM: begin
  case (A)
    MEM_LD: begin
      // LD [B]: push mem[B]; B must not be in protected region
      if (mem_prot(B)) begin set_fault(ST_MEM_PROT, {8'h00, B}); return 0; end
      if (dsp >= 256) begin set_fault(ST_DSTACK_OF, ir); return 0; end
      dstack[dsp] = mem[B];
      dsp++;
      arch_pc++;
    end
    MEM_ST: begin
      // ST [B]: pop -> mem[B]
      if (mem_prot(B)) begin set_fault(ST_MEM_PROT, {8'h00, B}); return 0; end
      if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
      mem[B] = dstack[dsp-1];
      dsp--;
      arch_pc++;
    end
    MEM_LDI: begin
      // LDI: pop addr, push mem[addr[7:0]] (net 0)
      if (dsp < 1) begin set_fault(ST_DSTACK_UF, ir); return 0; end
      addr8 = dstack[dsp-1][7:0];
      if (mem_prot(addr8)) begin set_fault(ST_MEM_PROT, {8'h00, addr8}); return 0; end
      dstack[dsp-1] = mem[addr8];
      arch_pc++;
    end
    MEM_STI: begin
      // STI: pop addr, pop x, mem[addr[7:0]] = x
      if (dsp < 2) begin set_fault(ST_DSTACK_UF, ir); return 0; end
      addr8 = dstack[dsp-1][7:0];
      if (mem_prot(addr8)) begin set_fault(ST_MEM_PROT, {8'h00, addr8}); return 0; end
      mem[addr8] = dstack[dsp-2];
      dsp -= 2;
      arch_pc++;
    end
    default: begin
      set_fault(ST_ILLEGAL_ENC, ir);
      return 0;
    end
  endcase
end

// --- CTRL: forward-only branches, no CALL/RET ---
OP_CTRL: begin
  // Canonical CTRL semantics live in j16_isa_pkg helpers.
  // Backward branches are illegal encodings (structural rule, not a runtime mode).
  if (!ctrl_b_legal(B)) begin
    set_fault(ST_ILLEGAL_ENC, ir);
    return 0;
  end
  tgt = int'(ctrl_target(arch_pc, B));
  case (A)
    CTRL_JMP: begin
      arch_pc = 32'(tgt);
    end
    CTRL_JZ: begin
      if (dsp < 1) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      a_val = dstack[dsp-1];
      dsp--;
      arch_pc = (a_val == 16'h0) ? 32'(tgt) : (arch_pc + 1);
    end
    CTRL_JNZ: begin
      if (dsp < 1) begin
        set_fault(ST_DSTACK_UF, ir);
        return 0;
      end
      a_val = dstack[dsp-1];
      dsp--;
      arch_pc = (a_val != 16'h0) ? 32'(tgt) : (arch_pc + 1);
    end
    default: begin
      // A >= 0x3: CALL and RET permanently removed
      set_fault(ST_ILLEGAL_ENC, ir);
      return 0;
    end
  endcase
end

        // --- INVOKE: call a registered, bounded, deterministic primitive ---
        OP_INVOKE: begin
          logic [15:0] full_id;
          prim_meta_t  meta;
          int          key;

          full_id = {A, B};
          key = int'(full_id);

          if (!prim_meta.exists(key)) begin
            set_fault(ST_UNKNOWN_INVOKE, full_id);
            return 0;
          end
          meta = prim_meta[key];

          // v2: pre-check stack space before executing (prevents overflow on push)
          begin
            int net = int'(meta.pushes) - int'(meta.pops);
            if (int'(dsp) + net > 256) begin
              set_fault(ST_DSTACK_OF, full_id);
              return 0;
            end
            if (int'(dsp) < int'(meta.pops)) begin
              set_fault(ST_DSTACK_UF, full_id);
              return 0;
            end
          end

          // Pop args, store to ARG region
          begin
            for (int i = 0; i < int'(meta.pops); i++) begin
              a_val = pop();
              if (faulted) return 0;
              mem[ARG_BASE + i[7:0]] = a_val;
            end
          end

          // Dispatch to simulation implementation (if registered)
          begin
            logic [15:0] inv_status = ST_OK;
            logic [15:0] inv_aux    = 16'h0;
            if (prim_impl.exists(key)) begin
              prim_impl[key].invoke(mem, inv_status, inv_aux);
            end
            mem[STATUS_ADDR] = inv_status;
            mem[AUX_ADDR]    = inv_aux;
            if (inv_status != ST_OK) begin
              halted  = 1;
              faulted = 1;
              return 0;
            end
          end

          // Push results from RES region
          begin
            for (int i = 0; i < int'(meta.pushes); i++) begin
              push(mem[RES_BASE + i[7:0]]);
              if (faulted) return 0;
            end
          end

          arch_pc++;
        end

        // --- SYS ---
        OP_SYS: begin
          case (A)
            SYS_HALT: begin
              mem[STATUS_ADDR] = ST_OK;
              mem[AUX_ADDR]    = 16'h0;
              halted  = 1;
              faulted = 0;
              return 0;
            end
            SYS_TRAP: begin
              set_fault(ST_TRAP, {8'h00, B});
              return 0;
            end
            default: begin
              set_fault(ST_ILLEGAL_ENC, ir);
              return 0;
            end
          endcase
        end

        // Any other OP: reserved, illegal
        default: begin
          set_fault(ST_ILLEGAL_ENC, ir);
          return 0;
        end

      endcase

      return !(halted || faulted);
    endfunction

    // Run up to max_steps steps. Returns step count at halt/fault.
    function automatic int unsigned run(int unsigned max_steps = 1000000);
      for (int unsigned i = 0; i < max_steps; i++) begin
        if (!step()) return i + 1;
      end
      return max_steps;
    endfunction

  endclass

endpackage
