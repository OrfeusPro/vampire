"""Find relocation-masked clock/Ping candidates; matches do not establish roles."""
import hashlib
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
OLD = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
NEW = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
# Historical addresses are search seeds only. All results need current evidence.
SEEDS = dict(producer=0x1467d0d10, ready=0x144ab2060, ready_core=0x144ab35d0,
    clock_get=0x1445ce230, init=0x1445d4bc0, refresh=0x1445dad40,
    setter=0x1445d8a30, tick=0x1445d8b20, utc=0x14156ae00,
    platform=0x1415da9a0, date=0x1415483d0, lobby_handler=0x1467ace30,
    ping_ctor=0x1456d8b40, ping_id=0x14140d460)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seeds',type=Path,help='Explicit JSON name/address seeds from reviewed historical evidence')
    args = parser.parse_args()
    seeds = {k:int(v,16) for k,v in json.loads(args.seeds.read_text('utf-8')).items()} if args.seeds else SEEDS
    if not 1 <= len(seeds) <= 32:
        raise ValueError('Explicit candidate seed budget is 1..32')
    spec = importlib.util.spec_from_file_location('ping_candidate_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    images = []
    for sha in (OLD, NEW):
        path = ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('Candidate source SHA differs')
        images.append((raw, native.Image(raw)))
    old, oi = images[0]; new, ni = images[1]
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    text = next(s for s in ni.pe.sections if s['name'] == '.text')
    lo, hi = text['raw'], text['raw'] + text['raw_size']
    results = {}
    for name, address in seeds.items():
        offset = oi.offset(address - oi.pe.base)
        pattern, mask = bytearray(), bytearray()
        for ins in cs.disasm(old[offset:offset+160], address):
            data = bytearray(ins.bytes); keep = bytearray(b'\xff'*len(data))
            if (ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP)) and ins.imm_size:
                keep[ins.imm_offset:ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
            if any(op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP for op in ins.operands):
                keep[ins.disp_offset:ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
            pattern.extend(data); mask.extend(keep)
            if len(pattern) >= 64 or ins.mnemonic in ('ret', 'jmp'):
                break
        # Longest consecutive fixed byte span is a bounded candidate-search anchor.
        spans, start = [], None
        for i, flag in enumerate(mask + b'\0'):
            if flag and start is None: start = i
            if not flag and start is not None:
                spans.append((start, i)); start = None
        a, b = max(spans, key=lambda p:p[1]-p[0])
        if b-a < 3: raise ValueError('Search anchor too short')
        hits, cursor = [], lo
        while True:
            at = new.find(bytes(pattern[a:b]), cursor, hi)
            if at < 0: break
            cursor = at+1; candidate = at-a
            if candidate < lo or candidate+len(pattern) > hi: continue
            if all(not flag or new[candidate+i] == pattern[i] for i, flag in enumerate(mask)):
                va = ni.pe.base+text['rva']+candidate-lo
                root = ni.containing(va)
                hits.append(dict(address=hex(va), unwind_root=(hex(ni.pe.base+ni.roots[root][0]) if root is not None else None)))
                if len(hits)>256: break
        results[name] = dict(historical_address=hex(address), pattern=pattern.hex(), mask=mask.hex(),
            truncated=len(hits)>256, candidates=hits[:256])
    report = dict(source_sha256=NEW, baseline_sha256=OLD, candidates=results,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Masked prefix candidates only; no semantic, callee, data or full-body verification.',
                'No authentication, network or runtime profile changes.'])
    payload = (json.dumps(report, indent=2)+'\n').encode()
    sha = hashlib.sha256(payload).hexdigest()
    folder = ROOT/'code-clues/login-ping-candidates'/sha; folder.mkdir(parents=True, exist_ok=True)
    (folder/'manifest.json').write_bytes(payload)
    print(json.dumps(dict(report=str(folder/'manifest.json'), sha256=sha,
        candidates={k:v['candidates'] for k,v in results.items()})))


if __name__ == '__main__': main()
