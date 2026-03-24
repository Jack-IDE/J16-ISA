#!/usr/bin/env python3
"""j16sym.py — symbol registry tooling for J16

Subcommands:
  - aliases: generate a symbol alias table for the assembler
  - cert:   certify each symbol (as an *expanded* J16 program fragment)

Design notes (v0 / Path A):
  - "CALL <SYM>" is a toolchain-level symbol invocation that expands inline.
  - "cert" therefore certifies the *expanded* words for each symbol.
  - Cycle/ICount budgets are derived by subtracting a baseline harness
    (dummy args + HALT) from a symbol harness (dummy args + CALL SYM + HALT).

This keeps everything spec-locked and requires no ISA changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Tuple, Optional


# ---------------------------------------------------------------------------
# Optional Python certifier backend (j16cert.py — mirrors j16_certifier.sv)
# ---------------------------------------------------------------------------
# j16cert is expected to live in the same directory as j16sym.py.
# If it can't be imported (e.g., missing file), the Python-cert path is
# unavailable and the tool falls back to Icarus or --no-run.
try:
    import importlib.util as _ilu
    _cert_spec = _ilu.spec_from_file_location(
        "j16cert",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "j16cert.py"),
    )
    if _cert_spec and _cert_spec.loader:
        _j16cert_mod = _ilu.module_from_spec(_cert_spec)
        sys.modules[_cert_spec.name] = _j16cert_mod
        _cert_spec.loader.exec_module(_j16cert_mod)   # type: ignore[union-attr]
        _J16CERT_AVAILABLE = True
    else:
        _j16cert_mod = None   # type: ignore[assignment]
        _J16CERT_AVAILABLE = False
except Exception:
    _j16cert_mod = None   # type: ignore[assignment]
    _J16CERT_AVAILABLE = False


def sha256_text(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode('utf-8'))
    return h.hexdigest()


def read_text(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def norm_source(text: str) -> str:
    # Stable-ish normalization: strip trailing whitespace; keep line order.
    return "\n".join([ln.rstrip() for ln in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')]).strip() + "\n"



def _scan_call_symbols(src_text: str) -> List[str]:
    """Return a list of symbol names referenced via `CALL <NAME>` in the given source text.

    This is used for v0 *bank-descending* enforcement even though CALL expands inline.
    We keep this intentionally simple: strip ';' and '#' comments, then search for CALL tokens.
    """
    out: List[str] = []
    txt = src_text.replace('\r\n', '\n').replace('\r', '\n')
    for ln in txt.split('\n'):
        ln = ln.split(';', 1)[0].split('#', 1)[0].strip()
        if not ln:
            continue
        m = re.search(r'\bCALL\b\s+([A-Za-z_.$][A-Za-z0-9_.$]*)', ln, flags=re.IGNORECASE)
        if m:
            out.append(m.group(1).upper())
    return out
def cmd_aliases(args: argparse.Namespace) -> int:
    reg = json.loads(read_text(args.in_path))
    if reg.get('format') != 'j16.symbols.v0':
        print('j16sym: unsupported registry format', file=sys.stderr)
        return 1

    root = os.path.dirname(os.path.abspath(args.in_path))

    out: Dict[str, Any] = {
        'format': 'j16.symbol_aliases.v0',
        'isa': reg.get('isa', ''),
        'symbols': {}
    }

    for bank in reg.get('banks', []) or []:
        b = int(bank.get('bank', 0))
        for s in bank.get('symbols', []) or []:
            name = str(s.get('name', '')).upper()
            idx = int(s.get('index', 0))
            fid = ((b & 0xF) << 8) | (idx & 0xFF)
            src_rel = str(s.get('src', ''))
            src_abs = os.path.normpath(os.path.join(root, '..', src_rel)) if not os.path.isabs(src_rel) else src_rel
            # Registry is at symbols/, so src is relative to bundle root in our layout.
            if not os.path.exists(src_abs):
                # fallback: resolve relative to CWD
                src_abs = os.path.normpath(src_rel)
            src_text = read_text(src_abs)
            src_norm = norm_source(src_text)
            src_hash = sha256_text(src_norm)

            abi = s.get('abi', {}) or {}
            out['symbols'][name] = {
                'bank': b,
                'index': idx,
                'fid': fid,
                'src': src_rel,
                'src_hash': f'sha256:{src_hash}',
                'abi': {
                    'pops': int(abi.get('pops', 0)),
                    'pushes': int(abi.get('pushes', 0)),
                },
                'caps': list(s.get('caps', []) or []),
                'budget': s.get('budget', {}) or {},
            }

    os.makedirs(os.path.dirname(args.out_path) or '.', exist_ok=True)
    with open(args.out_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write('\n')

    return 0


def _hex_read_words(path: str) -> List[int]:
    """Read a $readmemh-style file with one 16-bit word per line."""
    words: List[int] = []
    with open(path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith('#') or ln.startswith('//'):
                continue
            # Allow 0x prefix or bare hex.
            if ln.lower().startswith('0x'):
                ln = ln[2:]
            if not re.fullmatch(r'[0-9a-fA-F]{1,8}', ln):
                raise ValueError(f'bad hex word line in {path}: {ln!r}')
            v = int(ln, 16) & 0xFFFF
            words.append(v)
    return words


def _sha256_words(words: List[int]) -> str:
    # Canonical hash: newline-joined 4-hex uppercase words.
    canon = ''.join([f'{w & 0xFFFF:04X}\n' for w in words])
    return 'sha256:' + sha256_text(canon)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def _isa_load_tables(isa_abs: str) -> Dict[str, Any]:
    m = json.loads(read_text(isa_abs))
    insts = m.get('instructions', [])
    by_op: Dict[int, Dict[str, Any]] = {}
    invoke_op = None
    sys_op = None
    ctrl_op = None
    lit16_op = None

    for it in insts:
        op = int(str(it.get('op', '0')), 16) & 0xF
        fam = str(it.get('family', '')).upper()
        e: Dict[str, Any] = {'family': fam, 'len': 1}

        if fam == 'LIT':
            e['stack'] = (0, 1)
        elif fam == 'NOP':
            e['stack'] = (0, 0)
        elif fam == 'LIT16':
            e['stack'] = (0, 1)
            e['len'] = 2
            lit16_op = op
        elif fam == 'INVOKE':
            # Stack effect is fid-dependent (primtab or symbol registry).
            invoke_op = op
        else:
            subs = {}
            tags = {}
            for sub in it.get('subops', []) or []:
                a = int(str(sub.get('a', '0')), 16) & 0xF
                st = sub.get('stack', {}) or {}
                subs[a] = (int(st.get('pops', 0)), int(st.get('pushes', 0)))
                if 'tag' in sub:
                    tags[a] = str(sub.get('tag'))
            if subs:
                e['subops'] = subs
            if tags:
                e['tags'] = tags
            if fam == 'SYS':
                sys_op = op
            if fam == 'CTRL':
                ctrl_op = op

        by_op[op] = e

    if invoke_op is None:
        raise RuntimeError('ISA manifest missing INVOKE')
    if sys_op is None:
        raise RuntimeError('ISA manifest missing SYS')
    if ctrl_op is None:
        raise RuntimeError('ISA manifest missing CTRL')
    if lit16_op is None:
        raise RuntimeError('ISA manifest missing LIT16')

    return {
        'by_op': by_op,
        'invoke_op': int(invoke_op),
        'sys_op': int(sys_op),
        'ctrl_op': int(ctrl_op),
        'lit16_op': int(lit16_op),
    }


def _primtab_load(primtab_abs: str) -> Tuple[Dict[int, Tuple[int, int]], Dict[int, str], Dict[int, int]]:
    """Return (fid->(pops,pushes), fid->raw128hex, fid->cap_id)."""
    abi: Dict[int, Tuple[int, int]] = {}
    raw: Dict[int, str] = {}
    cap: Dict[int, int] = {}
    if not os.path.exists(primtab_abs):
        return abi, raw, cap
    with open(primtab_abs, 'r', encoding='utf-8') as f:
        for ln, line in enumerate(f, 1):
            t = line.strip()
            if not t:
                continue
            if not re.fullmatch(r'[0-9a-fA-F]{32}', t):
                raise RuntimeError(f'primtab.hex line {ln}: expected 32 hex digits, got: {t!r}')
            v = int(t, 16)
            if v == 0:
                continue
            fid = (v >> 112) & 0xFFFF
            pops = (v >> 40) & 0xFF
            pushes = (v >> 32) & 0xFF
            cap_id = (v >> 48) & 0xFF
            fid_i = int(fid)
            abi[fid_i] = (int(pops), int(pushes))
            raw[fid_i] = t.upper()
            cap[fid_i] = int(cap_id)
    return abi, raw, cap


def _decode_program_words(words: List[int], isa_tab: Dict[str, Any],
                          fid_abi: Dict[int, Tuple[int, int]],
                          strict_unknown_invoke: bool = True) -> List[Dict[str, Any]]:
    """Decode a word stream into instruction records using sequential decoding (handles LIT16)."""
    by_op = isa_tab['by_op']
    invoke_op = isa_tab['invoke_op']
    n = len(words)
    insns: List[Dict[str, Any]] = []

    pc = 0
    while pc < n:
        w = int(words[pc]) & 0xFFFF
        op = (w >> 12) & 0xF
        a = (w >> 8) & 0xF
        b = w & 0xFF
        if op not in by_op:
            raise RuntimeError(f'illegal op at pc={pc}: 0x{w:04X}')
        e = by_op[op]
        fam = e.get('family', '??')
        ilen = int(e.get('len', 1))

        pops = pushes = None
        tag = None
        fid = None

        if op == invoke_op or fam == 'INVOKE':
            fid = ((a & 0xF) << 8) | (b & 0xFF)
            if fid not in fid_abi:
                if strict_unknown_invoke:
                    raise RuntimeError(f'unknown INVOKE fid 0x{fid:04X} at pc={pc}')
                pops, pushes = (0, 0)
            else:
                pops, pushes = fid_abi[fid]
            ilen = 1

        elif fam in ('LIT', 'NOP', 'LIT16'):
            pops, pushes = e.get('stack', (0, 0))
            ilen = int(e.get('len', 1))
            if fam == 'LIT16':
                if pc + 1 >= n:
                    raise RuntimeError(f'truncated LIT16 at pc={pc}')
        else:
            subs = e.get('subops', {})
            if a not in subs:
                raise RuntimeError(f'illegal subop a=0x{a:X} for {fam} at pc={pc}: 0x{w:04X}')
            pops, pushes = subs[a]
            tag = (e.get('tags', {}) or {}).get(a)

        insns.append({
            'pc': pc, 'word': w, 'op': op, 'a': a, 'b': b,
            'family': fam, 'tag': tag, 'len': ilen,
            'pops': int(pops), 'pushes': int(pushes), 'fid': fid,
        })
        pc += ilen

    return insns


def _analyze_stack_depth(words: List[int],
                         isa_tab: Dict[str, Any],
                         fid_abi: Dict[int, Tuple[int, int]],
                         initial_depth: int = 0,
                         expected_exit_depth: int | None = None,
                         require_single_exit: bool = False,
                         require_forward_only: bool = True) -> Dict[str, Any]:
    """Conservative stack-depth verifier over all CTRL paths.

    - Tracks abstract data-stack depth across all reachable paths.
    - Enforces boundary-only CTRL targets (no jumping into LIT16 immediates).
    - By default enforces forward-only CTRL (J16 v2 rule).
    - `initial_depth` lets callers analyze an object fragment that assumes
      arguments are already on the stack.
    """
    by_op = isa_tab['by_op']
    ctrl_op = isa_tab['ctrl_op']
    sys_op = isa_tab['sys_op']
    insns = _decode_program_words(words, isa_tab, fid_abi, strict_unknown_invoke=True)

    # Instruction boundaries (to prevent jumping into LIT16 immediate words).
    boundaries = {i['pc'] for i in insns}
    pc_to_insn = {i['pc']: i for i in insns}
    n = len(words)

    def succs(i: Dict[str, Any]) -> List[int]:
        pc = int(i['pc'])
        fam = i['family']
        op = int(i['op'])
        tag = str(i.get('tag') or '')
        ilen = int(i['len'])
        if op == sys_op or fam == 'SYS':
            # Any SYS instruction (HALT or TRAP, OP=0xF) is a terminal — no successors.
            return []
        if op == ctrl_op or fam == 'CTRL':
            off = int(i['b'])
            if off >= 128:
                off -= 256
            tgt = pc + 1 + off
            if require_forward_only and tgt <= pc:
                raise RuntimeError(f'non-forward CTRL target at pc={pc} -> {tgt}')
            if tgt not in boundaries:
                raise RuntimeError(f'CTRL target into non-boundary at pc={pc} -> {tgt}')
            if tag == 'JMP':
                return [tgt]
            # JZ/JNZ
            fall = pc + 1
            if fall not in boundaries and fall != n:
                raise RuntimeError(f'fallthrough not at boundary at pc={pc} -> {fall}')
            return [fall, tgt]
        nxt = pc + ilen
        if nxt == n:
            # Falling off the end is not a legal termination mode in cert harnesses.
            return []
        if nxt not in boundaries:
            raise RuntimeError(f'next pc not at boundary at pc={pc} -> {nxt}')
        return [nxt]

    depths: Dict[int, set[int]] = {0: {int(initial_depth)}}
    merges_mismatch: List[int] = []
    underflows: List[Tuple[int, int, int]] = []  # (pc, depth, pops)
    overflows: List[Tuple[int, int]] = []        # (pc, depth_after)
    exits: List[Tuple[int, int, str]] = []       # (pc, depth_after, tag)

    for i in insns:
        pc = int(i['pc'])
        if pc not in depths:
            continue
        dset = depths[pc]
        for d in list(dset):
            pops = int(i['pops'])
            pushes = int(i['pushes'])
            if d < pops:
                underflows.append((pc, d, pops))
                continue
            d2 = d - pops + pushes
            if d2 > 255:
                overflows.append((pc, d2))
                continue
            s = succs(i)
            if not s:
                exits.append((pc, d2, str(i.get('tag') or i.get('family'))))
            for spc in s:
                if spc == n:
                    exits.append((pc, d2, 'FALLOFF'))
                    continue
                depths.setdefault(spc, set()).add(d2)
                if len(depths[spc]) > 1:
                    merges_mismatch.append(spc)

    ok = (not underflows) and (not overflows) and (not merges_mismatch)
    msg = None
    if underflows:
        pc, d, pops = underflows[0]
        msg = f'stack underflow at pc={pc}: depth={d} pops={pops}'
    elif overflows:
        pc, d2 = overflows[0]
        msg = f'stack overflow at pc={pc}: depth_after={d2}'
    elif merges_mismatch:
        msg = f'stack depth mismatch at merge pc={merges_mismatch[0]} (multiple possible depths)'
    elif require_single_exit and len(exits) != 1:
        msg = f'expected single exit, found {len(exits)}'
        ok = False
    elif expected_exit_depth is not None:
        # All exits must match expected depth.
        bad = [(pc, d2, t) for (pc, d2, t) in exits if d2 != int(expected_exit_depth)]
        if bad:
            pc, d2, t = bad[0]
            msg = f'exit stack depth mismatch at pc={pc}: depth={d2} expected={expected_exit_depth}'
            ok = False

    return {
        'ok': bool(ok),
        'msg': msg,
        'exits': [{'pc': pc, 'depth': d2, 'tag': t} for (pc, d2, t) in exits],
        'merge_mismatch_pcs': sorted(set(merges_mismatch)),
    }

def _run(cmd: List[str], cwd: str | None = None) -> Tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return int(p.returncode), p.stdout


def _write_file(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def _mk_harness_asm(symbol_name: str | None, pops: int) -> str:
    # Deterministic dummy args: 0xA000 + i
    lines: List[str] = []
    lines.append('; auto-generated by j16sym cert')
    lines.append('; prologue: push dummy args')
    for i in range(pops):
        lines.append(f'LIT16  0x{(0xA000 + i) & 0xFFFF:04X}')
    if symbol_name is not None:
        lines.append(f'CALL   {symbol_name}')
    lines.append('HALT')
    return '\n'.join(lines) + '\n'


def _mk_tb_cert(hexfile: str, primtab: str, allow: str, auto_len: bool, emit_json: bool) -> str:
    # Keep output parseable as a single line.
    auto = "1'b1" if auto_len else "1'b0"
    emit = "1'b1" if emit_json else "1'b0"
    return f'''// auto-generated tb_cert for j16sym
module tb_cert;
  logic ok;
  logic [15:0] fail_status;
  logic [15:0] fail_word;
  int unsigned fail_pc;
  int unsigned prog_len;
  int unsigned max_icount;
  int unsigned max_cycles;

  j16_certifier #(
    .HEXFILE("{hexfile}"),
    .PRIMTABFILE("{primtab}"),
    .ALLOWFILE("{allow}"),
    .AUTO_LEN({auto}),
    .EMIT_CERT_JSON({emit})
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
    $display("J16SYMCERT ok=%0d prog_len=%0d max_icount=%0d max_cycles=%0d fail_status=%h fail_word=%h fail_pc=%0d",
      ok, prog_len, max_icount, max_cycles, fail_status, fail_word, fail_pc);
    if (!ok) $fatal(1);
    $finish;
  end
endmodule
'''


def _run_cert_python(
    hex_path: str,
    primtab_path: str,
    allow_path: str,
) -> Dict[str, Any]:
    """
    Run the Python certifier (j16cert.py) against a compiled hex file.

    Returns a dict with keys: ok, prog_len, max_icount, max_cycles.
    Raises RuntimeError on hard failures (missing j16cert, bad hex, etc.).
    """
    if not _J16CERT_AVAILABLE or _j16cert_mod is None:
        raise RuntimeError(
            "j16cert.py not available — cannot use Python certifier backend. "
            "Install j16cert.py next to j16sym.py or use --no-run."
        )

    mod = _j16cert_mod  # local alias for brevity

    # Load ROM
    rom = mod.load_readmemh(hex_path, max_words=1024)

    # Load primtab
    primtab: Dict[int, Any] = {}
    if os.path.exists(primtab_path):
        primtab = mod.load_primtab(primtab_path)

    # Load allowfile
    allow_set = None
    if os.path.exists(allow_path):
        allow_set = mod.load_allowfile(allow_path)

    result = mod.certify(rom, primtab, allow_set=allow_set)

    return {
        "ok":         bool(result.ok),
        "prog_len":   int(result.prog_len),
        "max_icount": int(result.max_icount),
        "max_cycles": int(result.max_cycles),
        "fail_status": getattr(result, "fail_status", 0),
        "fail_pc":     getattr(result, "fail_pc", 0),
        "fail_msg":    getattr(result, "fail_msg", ""),
    }


def cmd_cert(args: argparse.Namespace) -> int:
    # Resolve tool locations.
    iverilog = args.iverilog
    vvp = args.vvp
    python = args.python

    # Determine which certification backend to use.
    #   1. --python-cert (explicit)         → Python certifier (j16cert.py)
    #   2. iverilog available               → Icarus (original path)
    #   3. iverilog missing + j16cert found → auto-fallback to Python certifier
    #   4. --no-run                         → harness generation only (no budgets)
    use_python_cert: bool = getattr(args, "python_cert", False)
    if not use_python_cert and not args.no_run:
        if shutil.which(iverilog) is None:
            if _J16CERT_AVAILABLE:
                print(
                    "j16sym cert: iverilog not found — using Python certifier "
                    "(j16cert.py) as backend.",
                    file=sys.stderr,
                )
                use_python_cert = True
            else:
                print(
                    "j16sym cert: iverilog/vvp not found. Install Icarus Verilog, "
                    "place j16cert.py next to j16sym.py, or run with --no-run.",
                    file=sys.stderr,
                )
                return 2

    reg_path = os.path.abspath(args.in_path)
    reg = json.loads(read_text(reg_path))
    if reg.get('format') != 'j16.symbols.v0':
        print('j16sym cert: unsupported registry format', file=sys.stderr)
        return 1

    bundle_root = os.path.normpath(os.path.join(os.path.dirname(reg_path), '..'))
    build_dir = os.path.abspath(args.build_dir)
    os.makedirs(build_dir, exist_ok=True)

    # (1) generate aliases used by the assembler for CALL expansion.
    aliases_path = os.path.abspath(args.aliases_out)

    class _A:  # argparse-like
        in_path = reg_path
        out_path = aliases_path

    if cmd_aliases(_A()) != 0:
        return 1

    # Resolve bundle-relative file paths for certifier inputs.
    primtab = os.path.abspath(os.path.join(bundle_root, args.primtab))
    allow = os.path.abspath(os.path.join(bundle_root, args.allow))
    isa = os.path.abspath(os.path.join(bundle_root, args.isa))

    # Load ISA decode tables and primitive ABI (for ABI checking + closure hashes).
    try:
        isa_tab = _isa_load_tables(isa)
    except Exception as e:
        print(f'j16sym cert: failed to load ISA manifest {isa}: {e}', file=sys.stderr)
        return 1

    # Capability map: cap_id (primtab field) -> capability name.
    # Default is cap_id 0 == "pure" (no side effects).
    cap_id_to_name: Dict[int, str] = {0: 'pure'}
    try:
        mf = json.loads(read_text(isa))
        cm = (mf.get('certification', {}) or {}).get('capabilities', {}) or {}
        mp = cm.get('cap_id_to_name', {}) or {}
        if mp:
            cap_id_to_name = {int(k): str(v) for (k, v) in mp.items()}
    except Exception:
        # Keep default map.
        pass

    try:
        prim_abi, prim_raw, prim_cap_id = _primtab_load(primtab)
    except Exception as e:
        print(f'j16sym cert: failed to parse primtab {primtab}: {e}', file=sys.stderr)
        return 1

    # Symbol registry ABI / fid mapping (bank<<8 | index).
    sym_name_by_fid: Dict[int, str] = {}
    sym_abi_by_fid: Dict[int, Tuple[int, int]] = {}
    sym_ref_by_name: Dict[str, Dict[str, Any]] = {}
    sym_fid_by_name: Dict[str, int] = {}
    sym_bank_by_name: Dict[str, int] = {}

    # Capability sets
    bank_caps_by_bank: Dict[int, set[str]] = {}
    bank_allow_prim_caps_by_bank: Dict[int, set[str]] = {}
    sym_caps_by_name: Dict[str, set[str]] = {}

    for bank in reg.get('banks', []) or []:
        b = int(bank.get('bank', 0)) & 0xF

        b_caps = set([str(x) for x in (bank.get('caps', []) or ['pure'])])
        b_allow = set([str(x) for x in (bank.get('allow_prim_caps', bank.get('caps', [])) or b_caps)])
        bank_caps_by_bank[b] = set([c for c in b_caps if c])
        bank_allow_prim_caps_by_bank[b] = set([c for c in b_allow if c])
        for s in bank.get('symbols', []) or []:
            nm = str(s.get('name', '')).upper()
            _caps = s.get('caps', None)
            if _caps is None:
                _caps = list(bank_caps_by_bank.get(b, {'pure'}))
            sym_caps_by_name[nm] = set([str(x) for x in (_caps or []) if str(x)])
            idx = int(s.get('index', 0)) & 0xFF
            fid = (b << 8) | idx
            abi = s.get('abi', {}) or {}
            pops = int(abi.get('pops', 0))
            pushes = int(abi.get('pushes', 0))
            sym_name_by_fid[fid] = nm
            sym_abi_by_fid[fid] = (pops, pushes)
            sym_ref_by_name[nm] = s
            sym_fid_by_name[nm] = fid
            sym_bank_by_name[nm] = b

    # Unified fid ABI lookup for INVOKE (primtab overrides symbol ABI if both exist).
    fid_abi: Dict[int, Tuple[int, int]] = dict(sym_abi_by_fid)
    fid_abi.update(prim_abi)

    # Temporary storage for closure hash computation (filled per symbol during cert loop).
    sym_direct_invoke_fids: Dict[str, List[int]] = {}
    sym_obj_hash: Dict[str, str] = {}
    # Collect symbols.
    sym_list: List[Tuple[Dict[str, Any], int, str]] = []  # (sym_obj, bank, NAME)
    for bank in reg.get('banks', []) or []:
        b = int(bank.get('bank', 0))
        for s in bank.get('symbols', []) or []:
            name = str(s.get('name', '')).upper()
            sym_list.append((s, b, name))

    # Baseline cert runs per pops count.
    baseline_cache: Dict[int, Dict[str, int]] = {}

    # Paths to SV sources.
    sv_ref = os.path.abspath(os.path.join(bundle_root, 'j16_ref_pkg.sv'))
    sv_cert = os.path.abspath(os.path.join(bundle_root, 'j16_certifier.sv'))

    for (sym, bank_id, name) in sym_list:
        abi = sym.get('abi', {}) or {}
        pops = int(abi.get('pops', 0))

        sym_dir = os.path.join(build_dir, 'symcert', f'bank{bank_id:02X}_{name}')
        os.makedirs(sym_dir, exist_ok=True)

        # (A) baseline: args + HALT
        if pops not in baseline_cache:
            base_asm = _mk_harness_asm(None, pops)
            base_s = os.path.join(sym_dir, f'__baseline_p{pops}.s')
            base_hex = os.path.join(sym_dir, f'__baseline_p{pops}.hex')
            _write_file(base_s, base_asm)
            cmd = [python, os.path.join(bundle_root, 'tools', 'j16asm.py'),
                   '--isa', isa, '--symbols', aliases_path,
                   '--in', base_s, '--out', base_hex]
            rc, out = _run(cmd, cwd=bundle_root)
            if rc != 0:
                print(out, file=sys.stderr)
                return 1

            base_info = {'max_cycles': 0, 'max_icount': 0, 'prog_len': 0}
            if args.no_run:
                baseline_cache[pops] = base_info
            elif use_python_cert:
                try:
                    result = _run_cert_python(base_hex, primtab, allow)
                except Exception as e:
                    print(f'j16sym cert: Python certifier failed for baseline (pops={pops}): {e}',
                          file=sys.stderr)
                    return 1
                if not result['ok']:
                    print(f'j16sym cert: baseline (pops={pops}) certification FAILED: '
                          f'status=0x{result["fail_status"]:04x} pc={result["fail_pc"]} '
                          f'msg={result["fail_msg"]}', file=sys.stderr)
                    return 1
                base_info = {
                    'prog_len':   result['prog_len'],
                    'max_icount': result['max_icount'],
                    'max_cycles': result['max_cycles'],
                }
                baseline_cache[pops] = base_info
            else:
                tb_path = os.path.join(sym_dir, f'__tb_cert_baseline_p{pops}.sv')
                _write_file(tb_path, _mk_tb_cert(base_hex, primtab, allow, True, False))
                out_exe = os.path.join(sym_dir, f'__sim_cert_baseline_p{pops}.out')
                rc, out = _run([iverilog, '-g2012', '-o', out_exe, sv_ref, sv_cert, tb_path], cwd=bundle_root)
                if rc != 0:
                    print(out, file=sys.stderr)
                    return 1
                rc, out = _run([vvp, out_exe], cwd=bundle_root)
                if rc != 0:
                    print(out, file=sys.stderr)
                    return 1
                m = re.search(r'J16SYMCERT\s+ok=(\d+)\s+prog_len=(\d+)\s+max_icount=(\d+)\s+max_cycles=(\d+)', out)
                if not m:
                    print('j16sym cert: failed to parse baseline cert output', file=sys.stderr)
                    print(out, file=sys.stderr)
                    return 1
                base_info = {'prog_len': int(m.group(2)), 'max_icount': int(m.group(3)), 'max_cycles': int(m.group(4))}
                baseline_cache[pops] = base_info

        base_info = baseline_cache[pops]

        # (B) symbol harness: args + CALL + HALT
        sym_asm = _mk_harness_asm(name, pops)
        sym_s = os.path.join(sym_dir, f'{name}.harness.s')
        sym_hex = os.path.join(sym_dir, f'{name}.harness.hex')
        _write_file(sym_s, sym_asm)

        cmd = [python, os.path.join(bundle_root, 'tools', 'j16asm.py'),
               '--isa', isa, '--symbols', aliases_path,
               '--in', sym_s, '--out', sym_hex,
               '--lst', os.path.join(sym_dir, f'{name}.harness.lst'),
               '--sym', os.path.join(sym_dir, f'{name}.harness.sym')]
        rc, out = _run(cmd, cwd=bundle_root)
        if rc != 0:
            print(out, file=sys.stderr)
            return 1

        # Compute expanded object hash by stripping prologue words and the final HALT word.
        words = _hex_read_words(sym_hex)
        pro_words = pops * 2  # LIT16 is 2 words
        if len(words) < pro_words + 1:
            print(f'j16sym cert: harness too short for {name}', file=sys.stderr)
            return 1
        obj_words = words[pro_words:-1]
        obj_hash = _sha256_words(obj_words)

        # Safety/ABI checks for the expanded harness and symbol object:
        # - ensure symbol object does not contain SYS (HALT/TRAP) inlined
        # - (default) forbid CTRL inside symbols for v0 baseline_subtract
        # - verify harness exit stack depth equals declared ABI pushes
        sys_op = int(isa_tab['sys_op'])
        ctrl_op = int(isa_tab['ctrl_op'])
        invoke_op = int(isa_tab['invoke_op'])

        if any(((w >> 12) & 0xF) == sys_op for w in obj_words):
            # Checks OP == sys_op (bits [15:12] == 0xF), catching every SYS word
            # (HALT A=0 and TRAP A=1).  Both are forbidden in a v0 symbol body
            # because either would terminate the *caller*, not just the invocation.
            print(f'j16sym cert: symbol {name} contains a SYS instruction (OP=0xF: HALT or TRAP) inside the symbol object; SYS is forbidden in v0 symbol bodies because it would terminate the caller', file=sys.stderr)
            return 1

        if any(((w >> 12) & 0xF) == ctrl_op for w in obj_words):
            print(f'j16sym cert: symbol {name} contains CTRL; frozen v0 certification requires straight-line symbols and rejects internal CTRL.', file=sys.stderr)
            return 1


        # Capability policy (v0): capabilities are monotonic across dependencies.
        # - bank.caps defines the max cap set allowed in the bank
        # - bank.allow_prim_caps defines which primitive capabilities symbols in this bank may invoke
        # - symbol.caps defines the capability set of this symbol
        # Rules:
        #   (1) symbol.caps ⊆ bank.caps
        #   (2) callee_symbol.caps ⊆ caller_symbol.caps  (for CALL or INVOKE to symbols)
        #   (3) primitive.cap ∈ caller_symbol.caps and primitive.cap ∈ bank.allow_prim_caps
        b_cap = int(bank_id) & 0xF
        bank_caps = set(bank_caps_by_bank.get(b_cap, {'pure'}))
        bank_allow_prim_caps = set(bank_allow_prim_caps_by_bank.get(b_cap, bank_caps))

        sym_caps = set([str(x) for x in (sym.get('caps', []) or []) if str(x)])
        if not sym_caps:
            sym_caps = set(bank_caps)

        if not sym_caps.issubset(bank_caps):
            print(f'j16sym cert: capability policy violated: {name} caps={sorted(sym_caps)} not subset of bank{b_cap} caps={sorted(bank_caps)}', file=sys.stderr)
            return 1

        # Scan CALL deps from source (policy checks treat CALL as a dependency even though it expands inline).
        calls: List[str] = []
        if sym.get('src'):
            src_abs = os.path.normpath(os.path.join(bundle_root, sym.get('src')))
            if os.path.exists(src_abs):
                calls = _scan_call_symbols(read_text(src_abs))



        # Enforce v0 bank-descending symbol dependencies ("downcalls" only).
        # A symbol in bank B may only CALL/INVOKE symbols in banks < B.
        # This makes the symbol graph a DAG and makes bank placement deterministic.
        # (1) Source-level CALL dependencies (pre-inline expansion).
        if sym.get('src'):
            src_abs = os.path.normpath(os.path.join(bundle_root, sym.get('src')))
            calls = _scan_call_symbols(read_text(src_abs))
            for callee in calls:
                if callee not in sym_bank_by_name:
                    print(f'j16sym cert: {name} CALLs unknown symbol {callee}', file=sys.stderr)
                    return 1
                callee_bank = int(sym_bank_by_name.get(callee, -1))
                if callee_bank >= (int(bank_id) & 0xF):
                    print(f'j16sym cert: bank-descending rule violated: {name}(bank={bank_id}) CALLs {callee}(bank={callee_bank})', file=sys.stderr)
                    return 1

        inv_fids = sorted({((w & 0x0FFF) if ((w >> 12) & 0xF) == invoke_op else -1)
                           for w in obj_words} - {-1})

        # (2) Object-level INVOKE dependencies (explicit INVOKE fid present in the object words).
        for fid in inv_fids:
            if fid in sym_name_by_fid:
                callee_name = sym_name_by_fid[fid]
                callee_bank = (fid >> 8) & 0xF
                if callee_bank >= (int(bank_id) & 0xF):
                    print(f'j16sym cert: bank-descending rule violated: {name}(bank={bank_id}) INVOKEs {callee_name}(bank={callee_bank}) fid=0x{fid:04X}', file=sys.stderr)
                    return 1

        # Capability checks for dependencies.
        # (A) CALL dependencies.
        for callee in calls:
            if callee not in sym_caps_by_name:
                print(f'j16sym cert: {name} CALLs unknown symbol {callee}', file=sys.stderr)
                return 1
            callee_caps = set(sym_caps_by_name.get(callee, set()))
            if not callee_caps.issubset(sym_caps):
                print(f'j16sym cert: capability policy violated: {name} caps={sorted(sym_caps)} CALLs {callee} caps={sorted(callee_caps)}', file=sys.stderr)
                return 1

        # (B) INVOKE dependencies (including symbol fids and primitive fids).
        for fid in inv_fids:
            if fid in sym_name_by_fid:
                callee_name = sym_name_by_fid[fid]
                callee_caps = set(sym_caps_by_name.get(callee_name, set()))
                if not callee_caps.issubset(sym_caps):
                    print(f'j16sym cert: capability policy violated: {name} caps={sorted(sym_caps)} INVOKEs {callee_name} caps={sorted(callee_caps)} fid=0x{fid:04X}', file=sys.stderr)
                    return 1
            else:
                if fid not in prim_cap_id:
                    print(f'j16sym cert: {name} INVOKEs unknown primitive fid=0x{fid:04X} (missing from primtab)', file=sys.stderr)
                    return 1
                cap_id = int(prim_cap_id[fid])
                cap_name = str(cap_id_to_name.get(cap_id, f'cap{cap_id}'))
                if cap_name not in sym_caps:
                    print(f'j16sym cert: capability policy violated: {name} caps={sorted(sym_caps)} INVOKEs primitive fid=0x{fid:04X} cap={cap_name} not in symbol caps', file=sys.stderr)
                    return 1
                if cap_name not in bank_allow_prim_caps:
                    print(f'j16sym cert: capability policy violated: bank{b_cap} allow_prim_caps={sorted(bank_allow_prim_caps)} does not allow primitive fid=0x{fid:04X} cap={cap_name} (called by {name})', file=sys.stderr)
                    return 1

        sym_direct_invoke_fids[name] = inv_fids
        sym_obj_hash[name] = obj_hash

        try:
            abi_expected_pops = int(sym.get('abi', {}).get('pops', 0))
            abi_expected_pushes = int(sym.get('abi', {}).get('pushes', 0))
            abi_check = _analyze_stack_depth(obj_words, isa_tab, fid_abi,
                                             initial_depth=abi_expected_pops,
                                             expected_exit_depth=abi_expected_pushes,
                                             require_single_exit=True,
                                             require_forward_only=True)
        except Exception as e:
            print(f'j16sym cert: ABI analysis failed for {name}: {e}', file=sys.stderr)
            return 1
        if not abi_check.get('ok', False):
            print(f'j16sym cert: ABI mismatch for {name}: {abi_check.get("msg")}', file=sys.stderr)
            return 1

        cert_info: Dict[str, Any] = {
            'method': 'baseline_subtract',
            'baseline': base_info,
            'harness_words': len(words),
            'obj_words': len(obj_words),
            'obj_hash': obj_hash,
            'abi_check': abi_check,
            'deps': {
                'invoke_fids': inv_fids,
                'invoke_symbols': [sym_name_by_fid[f] for f in inv_fids if f in sym_name_by_fid],
                'invoke_prims': [f for f in inv_fids if f not in sym_name_by_fid],
            },
        }

        if use_python_cert:
            try:
                result = _run_cert_python(sym_hex, primtab, allow)
            except Exception as e:
                print(f'j16sym cert: Python certifier failed for {name}: {e}',
                      file=sys.stderr)
                return 1
            if not result['ok']:
                print(f'j16sym cert: {name} certification FAILED: '
                      f'status=0x{result["fail_status"]:04x} pc={result["fail_pc"]} '
                      f'msg={result["fail_msg"]}', file=sys.stderr)
                return 1
            sym_icount = max(0, result['max_icount'] - int(base_info.get('max_icount', 0)))
            sym_cycles = max(0, result['max_cycles'] - int(base_info.get('max_cycles', 0)))
            cert_info.update({
                'ok':         True,
                'prog_len':   result['prog_len'],
                'max_icount': sym_icount,
                'max_cycles': sym_cycles,
                'raw': {
                    'max_icount': result['max_icount'],
                    'max_cycles': result['max_cycles'],
                },
                'backend': 'python',
            })
        elif not args.no_run:
            tb_path = os.path.join(sym_dir, f'__tb_cert_{name}.sv')
            _write_file(tb_path, _mk_tb_cert(sym_hex, primtab, allow, True, False))
            out_exe = os.path.join(sym_dir, f'__sim_cert_{name}.out')
            rc, out = _run([iverilog, '-g2012', '-o', out_exe, sv_ref, sv_cert, tb_path], cwd=bundle_root)
            if rc != 0:
                print(out, file=sys.stderr)
                return 1
            rc, out = _run([vvp, out_exe], cwd=bundle_root)
            if rc != 0:
                print(out, file=sys.stderr)
                return 1
            m = re.search(r'J16SYMCERT\s+ok=(\d+)\s+prog_len=(\d+)\s+max_icount=(\d+)\s+max_cycles=(\d+)', out)
            if not m:
                print(f'j16sym cert: failed to parse cert output for {name}', file=sys.stderr)
                print(out, file=sys.stderr)
                return 1
            ok = int(m.group(1))
            prog_len = int(m.group(2))
            max_icount = int(m.group(3))
            max_cycles = int(m.group(4))
            sym_icount = max(0, max_icount - int(base_info.get('max_icount', 0)))
            sym_cycles = max(0, max_cycles - int(base_info.get('max_cycles', 0)))
            cert_info.update({
                'ok': bool(ok),
                'prog_len': prog_len,
                'max_icount': sym_icount,
                'max_cycles': sym_cycles,
                'raw': {'max_icount': max_icount, 'max_cycles': max_cycles},
            })
        else:
            cert_info.update({'ok': None, 'max_icount': None, 'max_cycles': None})

        # Write back into registry.
        sym.setdefault('hash', {})
        # Preserve existing src_hash if present (aliases already computed it too).
        if 'src_hash' not in sym['hash'] and sym.get('src'):
            src_abs = os.path.normpath(os.path.join(bundle_root, sym.get('src')))
            sym['hash']['src_hash'] = f'sha256:{sha256_text(norm_source(read_text(src_abs)))}'
        sym['hash']['obj_hash'] = obj_hash

        sym['budget'] = {
            'max_cycles': cert_info.get('max_cycles'),
            'max_icount': cert_info.get('max_icount'),
        }
        sym['cert'] = cert_info

        if args.verbose:
            print(f'cert {name}: ok={cert_info.get("ok")} max_cycles={cert_info.get("max_cycles")} obj_hash={obj_hash}')

    # Enforce: symbol INVOKE dependency graph must be acyclic.
    # This is a core "banked symbols" safety property: cycles imply recursion.
    # NOTE: if bank-descending is enabled (default), cycles are structurally impossible,
    # Keep this check for clear diagnostics even though frozen v0 always requires descending bank dependencies.
    def _sym_invoke_edges() -> Dict[str, List[str]]:
        g: Dict[str, List[str]] = {}
        for nm in sym_ref_by_name.keys():
            fids = sym_direct_invoke_fids.get(nm, []) or []
            deps: List[str] = []
            for fid in fids:
                if fid in sym_name_by_fid:
                    deps.append(sym_name_by_fid[fid])
            g[nm] = sorted(set(deps))
        return g

    def _find_cycle_path(g: Dict[str, List[str]]) -> Optional[List[str]]:
        state: Dict[str, int] = {n: 0 for n in g.keys()}  # 0=unseen,1=visiting,2=done
        parent: Dict[str, str] = {}

        def dfs(u: str) -> Optional[List[str]]:
            state[u] = 1
            for v in g.get(u, []):
                if v not in state:
                    # INVOKE to a symbol name we don't know about (should not happen if registry is consistent)
                    continue
                if state[v] == 0:
                    parent[v] = u
                    cyc = dfs(v)
                    if cyc:
                        return cyc
                elif state[v] == 1:
                    # Found a back-edge u -> v. Reconstruct cycle v .. u -> v.
                    path = [v]
                    cur = u
                    while True:
                        path.append(cur)
                        if cur == v:
                            break
                        cur = parent.get(cur, '')
                        if not cur:
                            # Fallback: can't reconstruct; still report minimal cycle.
                            return [v, u, v]
                    path.reverse()
                    return path
            state[u] = 2
            return None

        for n in sorted(g.keys()):
            if state[n] == 0:
                cyc = dfs(n)
                if cyc:
                    return cyc
        return None

    g = _sym_invoke_edges()
    cyc = _find_cycle_path(g)
    if cyc:
        parts: List[str] = []
        for nm in cyc:
            fid = sym_fid_by_name.get(nm, -1)
            b = sym_bank_by_name.get(nm, -1)
            parts.append(f'{nm}(bank={b},fid=0x{fid:04X})')
        print('j16sym cert: cyclic symbol INVOKE dependency forbidden: ' + ' -> '.join(parts), file=sys.stderr)
        return 1

    # Compute closure_hash for each symbol (tamper-evident dependency commitment).
    # closure_hash(name) := sha256("v1\n" + "obj:<obj_hash>\n" + for dep in sorted(deps): "dep:<fid>:<dep_hash>\n")
    # where dep_hash is either another symbol's closure_hash (if dep is a symbol fid),
    # or a leaf hash of the primtab row (if dep is an external primitive).
    prim_leaf_hash: Dict[int, str] = {}
    for fid, raw128 in prim_raw.items():
        prim_leaf_hash[fid] = 'sha256:' + _sha256_hex('primtab_row_v1\n' + raw128 + '\n')

    memo: Dict[str, str] = {}
    visiting: set[str] = set()

    def _closure(name: str) -> str:
        if name in memo:
            return memo[name]
        if name in visiting:
            raise RuntimeError(f'cycle detected in symbol dependency graph at {name}')
        if name not in sym_ref_by_name:
            raise RuntimeError(f'unknown symbol in closure computation: {name}')
        visiting.add(name)

        obj = sym_obj_hash.get(name)
        if not obj:
            raise RuntimeError(f'missing obj_hash for {name} (did cert run?)')

        deps = sym_direct_invoke_fids.get(name, []) or []
        dep_items: List[Tuple[int, str]] = []
        for fid in sorted(set(deps)):
            if fid in sym_name_by_fid:
                dep_name = sym_name_by_fid[fid]
                dep_items.append((fid, _closure(dep_name)))
            elif fid in prim_leaf_hash:
                dep_items.append((fid, prim_leaf_hash[fid]))
            else:
                raise RuntimeError(f'{name}: INVOKE fid 0x{fid:04X} missing from symbol registry and primtab')

        data = 'v1\n' + f'obj:{obj}\n' + ''.join([f'dep:{fid:04X}:{h}\n' for (fid, h) in dep_items])
        out = 'sha256:' + _sha256_hex(data)
        memo[name] = out
        visiting.remove(name)
        return out

    try:
        for nm in sorted(sym_ref_by_name.keys()):
            sref = sym_ref_by_name[nm]
            sref.setdefault('hash', {})
            sref['hash']['closure_hash'] = _closure(nm)
    except Exception as e:
        print(f'j16sym cert: closure_hash computation failed: {e}', file=sys.stderr)
        return 1

    out_path = os.path.abspath(args.out_path)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(reg, f, indent=2, sort_keys=True)
        f.write('\n')

    return 0
def main() -> int:
    ap = argparse.ArgumentParser(description='J16 symbol tooling')
    sub = ap.add_subparsers(dest='cmd', required=True)

    ap_a = sub.add_parser('aliases', help='Generate symbol aliases JSON for the assembler')
    ap_a.add_argument('--in', dest='in_path', required=True, help='Input symbols_v0.json')
    ap_a.add_argument('--out', dest='out_path', required=True, help='Output symbols_aliases.json')
    ap_a.set_defaults(func=cmd_aliases)

    ap_c = sub.add_parser('cert', help='Certify each symbol and write back budgets/hashes')
    ap_c.add_argument('--in', dest='in_path', required=True, help='Input symbols_v0.json')
    ap_c.add_argument('--out', dest='out_path', required=True, help='Output symbols_v0.json (updated)')
    ap_c.add_argument('--isa', default='docs/isa_v2.json', help='ISA manifest path (bundle-relative)')
    ap_c.add_argument('--primtab', default='primtab.hex', help='primtab.hex path (bundle-relative)')
    ap_c.add_argument('--allow', default='allow_prims.hex', help='allow_prims.hex path (bundle-relative)')
    ap_c.add_argument('--build', dest='build_dir', default='build', help='Build/output dir')
    ap_c.add_argument('--aliases-out', default='build/symbols_aliases.json', help='Where to write symbols_aliases.json')
    ap_c.add_argument('--iverilog', default='iverilog', help='iverilog executable')
    ap_c.add_argument('--vvp', default='vvp', help='vvp executable')
    ap_c.add_argument('--python', default=sys.executable, help='Python executable to run the assembler')
    ap_c.add_argument('--python-cert', action='store_true',
                      help='Use Python certifier (j16cert.py) instead of Icarus Verilog. '
                           'Auto-enabled when iverilog is not found and j16cert.py is available.')
    ap_c.add_argument('--no-run', action='store_true', help='Do not invoke Icarus; still generate harnesses and hashes')
    ap_c.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    ap_c.set_defaults(func=cmd_cert)

    args = ap.parse_args()
    return int(args.func(args))


if __name__ == '__main__':
    raise SystemExit(main())
