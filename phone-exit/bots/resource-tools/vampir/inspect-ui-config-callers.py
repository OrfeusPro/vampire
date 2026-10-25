"""Static exact caller edges / NNV diagnostic literals; no event or active configuration inference."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('caller_hash', HERE / 'replay-ui-config-hash.py')
key_hash = importlib.util.module_from_spec(spec); spec.loader.exec_module(key_hash)
native, getter = key_hash.native, key_hash.getter
ROOTS = (0x1455086b0, 0x145509470, 0x145517810)
EDGES = {0x1455086df: 0x1445cbd00, 0x1455094f0: 0x1445cbd00,
         0x145517933: 0x1445cbd00, 0x145517a35: 0x1445d6ec0,
         0x1455179d6: 0x1445cb6c0, 0x145517a8b: 0x1445cb6c0,
         0x145517a40: 0x1445d1cd0}
LITERALS = {0x1455086fe: '\t%s = %s\n', 0x14550950d: '\t%s = %s\n',
            0x14551787c: 'GNn', 0x1455178e5: '~', 0x14551790a: 'Reload',
            0x145517946: 'The specified substring[%s] is not exist in NNVs.\n',
            0x145517998: 'List up potential NNVs ...\n', 0x145517a51: 'List up all NNVs ...\n'}


def inspect(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет всех явных caller roots')
    if native.capstone.__version__ != '5.0.6': raise ValueError('Изменился закреплённый decoder')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for address in ROOTS:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for at, target in EDGES.items():
        if rows[at]['mnemonic'] != 'call' or rows[at]['direct_target'] != target:
            raise ValueError('Изменилась точная caller edge')
    literals = []
    for at, text in LITERALS.items():
        refs = rows[at]['rip_references']
        if len(refs) != 1: raise ValueError('Неоднозначная literal reference')
        target = refs[0]; offset = image.offset(target - image.pe.base); data = (text + '\0').encode('utf-16le')
        if raw[offset:offset + len(data)] != data: raise ValueError('Изменился точный diagnostic literal')
        literals.append(dict(instruction=hex(at), address=hex(target), value=text, sha256=getter.sha(data)))
    expected = {0x14551788b: ('call', '0x141438a20'), 0x145517892: ('je', '0x1455178cb'),
        0x1455178a2: ('call', '0x141438180'), 0x14551789a: ('lea', 'rdx, [rbp - 0x39]'),
        0x145517894: ('mov', 'r8d, 3'), 0x1455178d4: ('je', '0x145517a47'),
        0x1455178df: ('je', '0x145517a47'), 0x1455178f6: ('je', '0x145517a40'),
        0x14551791d: ('je', '0x145517a40'), 0x145517938: ('cmp', 'dword ptr [rbp - 0x11], 1'),
        0x14551793c: ('jg', '0x145517a0d'), 0x145517a0d: ('mov', 'ecx, dword ptr [rdi + 8]'),
        0x145517a1b: ('je', '0x145517a3a'), 0x145517a32: ('mov', 'rcx, rbx'),
        0x145517a35: ('call', '0x1445d6ec0'), 0x1455094dc: ('je', '0x145509558')}
    for at, pair in expected.items():
        if (rows[at]['mnemonic'], rows[at]['operands']) != pair:
            raise ValueError('Изменились static diagnostic gates / data flow')
    return dict(source_sha256=getter.SHA, fragments=fragments, literals=literals,
        call_edges=[dict(instruction=hex(a), target=hex(t), boundary_verified=True) for a, t in EDGES.items()],
        conditions=dict(empty_key='zero count or count-1 == 0 takes list-all branch',
            special_keys=['~', 'Reload'], special_target='0x1445d1cd0',
            read_gate='nonempty nonspecial key calls read consumer',
            missing_or_empty_value='read result count <=1 builds diagnostic text and enumerates candidate entries',
            write_gate='read result count >1 AND incoming value count-1 !=0 calls write consumer',
            helper_prefix='GNn with helper length argument3; helper matching/strip semantics not executed'),
        limits=['Static exact instruction/call/literal checks, not native execution of these callers.',
            'Direct E8 scan found four verified consumer callsites; indirect callers and full command registration not covered.',
            'Diagnostic NNV path is indicated by literals/branches; actual console exposure, permissions and event source unknown.',
            'Read count<=1 conflates missing binding and an existing empty string; do not infer key absence from this gate.',
            'Reload target name/behavior, prefix helpers, formatting/output and iterator callback semantics not established.',
            'No active config, UI application, source precedence, persistence or game command proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = inspect(json.loads(args.request.read_text('utf-8')))
    result['inspector_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(roots=len(ROOTS), edges=len(result['call_edges']), literals=len(result['literals']))))
