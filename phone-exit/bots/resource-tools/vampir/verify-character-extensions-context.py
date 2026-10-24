"""Native appearance vector and optional map on bounded preallocated storage."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_component(context, root, kind):
    common = {name: int(at, 16) for name, at in context['input_functions'].items()}
    functions = {name: int(at, 16) for name, at in context['components'][kind].items()}
    roots = set(common.values()) | set(functions.values())
    h = load('update-native-harness').make_harness(context, context['exports'], roots,
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in bindings.rows(native, h.image, at) if r['call']} for name, at in dict(common, **functions).items()}
    if calls != context['call_sites'][kind]:
        raise ValueError('Character extensions call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    for block in context['blocks']:
        payload = bytes.fromhex(block['bytes'])
        address = int(block['address'], 16)
        require(data(address, len(payload)) == payload
                and hashlib.sha256(payload).hexdigest() == block['sha256'], 'Character extensions source block differs')
        for page in range(address & ~4095, (address + len(payload) + 4095) & ~4095, 4096):
            if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096); h.uc.mem_write(page, data(page, 4096))
    b = {name: int(at, 16) for name, at in context['bindings'].items()}
    for table, slot, function in context['links'][kind]:
        require(struct.unpack('<Q', data(int(table, 16) + slot, 8))[0] == int(function, 16),
                'Character extensions table link differs')
    uc, x = h.uc, h.x
    obj, archive, callback, buffer, store, buckets = [h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x5000, 0x8000, 0x9000)]
    mp = obj + 0x10
    state, operations, insertions, rehashes = {}, [], [], []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def number(at, size):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def init_map(address):
        require(address == mp, 'Character optional map receiver differs')
        uc.mem_write(mp, bytes(0x50)); uc.mem_write(store, bytes(8 * 0x38))
        put(mp, 'QII', store, 0, 8); put(mp + 0x2c, 'I', 128)
        put(mp + 0x30, 'ii', -1, 0); put(mp + 0x38, 'i', -1); put(mp + 0x48, 'I', 1)

    def rehash(address):
        require(address == mp, 'Character optional rehash receiver differs')
        count, size = number(mp + 8, 4), number(mp + 0x48, 4)
        require(count <= 8 and size in (1, 2, 4, 8, 16), 'Character optional bucket/count budget')
        heads = [-1] * size
        for index in range(count):
            at = store + index * 0x38; key = number(at, 1); bucket = key & (size - 1)
            put(at + 0x30, 'iI', heads[bucket], bucket); heads[bucket] = index
        if size > 1:
            uc.mem_write(buckets, struct.pack('<' + 'i' * size, *heads)); put(mp + 0x40, 'Q', buckets)
        else:
            put(mp + 0x38, 'i', heads[0]); put(mp + 0x40, 'Q', 0)
        rehashes.append(size)

    def fixture(machine, name):
        a, d = reg('RCX'), reg('RDX')
        value = 0
        if name == 'appearance_clear':
            require(d == 0, 'Character appearance initial cleanup count differs')
        elif name == 'appearance_allocate':
            require(a == obj, 'Character appearance allocation receiver differs')
            if d > 8:
                raise BufferError('Character appearance local storage budget')
            put(obj, 'Q', store if d else 0); put(obj + 0xc, 'I', d)
        elif name == 'appearance_grow':
            raise ValueError('Character appearance unexpectedly exceeded reserved count')
        elif name in ('map_init', 'map_clear'):
            if name == 'map_clear':
                require(d == 0, 'Character optional clear argument differs')
            init_map(a)
        elif name == 'map_rehash':
            rehash(a)
        elif name == 'map_grow':
            raise BufferError('Character optional local storage budget')
        elif name == 'bit_append':
            require(a == mp + 0x10 and d == 0, 'Character optional bit append differs')
        elif name == 'insert_predicate':
            require(a == mp, 'Character optional insert receiver differs')
            count = number(mp + 8, 4)
            require(1 <= count <= 8 and not any(number(store + i * 0x38, 1) == d for i in range(count - 1)),
                    'Duplicate optional key unexpectedly reached insert')
            insertions.append(d)
        elif name == 'value_cleanup':
            require(h.scratch + 0x30000 <= a < h.scratch + 0x38000, 'Character optional temporary cleanup differs')
        else:
            raise ValueError('Unknown character extension fixture')
        h.finish(value)
    protected = roots | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'][kind].items():
        require(int(at, 16) not in protected, 'Character extension fixture overlaps native code')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
    import unicorn
    primitives = {common[key]: key for key in ('u16', 'u32', 'u64', 'bool', 'raw')}
    def entered(machine, at, size, unused):
        if at in primitives:
            require(reg('RCX') == archive, 'Character extension primitive receiver differs')
            pos = number(archive + 0x30, 8) - buffer
            require(0 <= pos <= len(state['body']), 'Character extension cursor outside buffer')
            operations.append(dict(kind=primitives[at], consumed=pos))
            if len(operations) - 1 == state['fail_at']:
                h.finish(0)
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list
    record_body = load('verify-character-record-context').body_for()

    def run(body, fail_at=None, extra=False):
        require(type(body) is bytes and len(body) <= 4096, 'Character extension input byte budget')
        state.update(body=body, fail_at=fail_at); operations.clear(); insertions.clear(); rehashes.clear()
        uc.mem_write(obj - 16, b'\xa5' * 16 + bytes(0x60) + b'\xa6' * 16)
        storage_size = 8 * (0x10 if kind == 'appearance' else 0x38)
        uc.mem_write(store - 16, b'\xa7' * 16 + bytes(storage_size) + b'\xa8' * 16)
        if kind == 'optional':
            put(obj, 'Q', b['optional_table']); init_map(mp)
        else:
            put(callback, 'Q', b['appearance_callbacks'])
        uc.mem_write(archive - 16, b'\xa9' * 16 + bytes(0x40) + b'\xaa' * 16)
        uc.mem_write(buffer - 16, b'\xab' * 16 + body + b'\xac' * 16)
        uc.reg_write(x.UC_X86_REG_RDX, buffer); uc.reg_write(x.UC_X86_REG_R8, len(body)); uc.reg_write(x.UC_X86_REG_R9, 1)
        put(h.scratch + 0x38028, 'Q', 0); h.call(common['archive_constructor'], archive)
        before = bytes(uc.mem_read(archive - 16, 0x60))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        if kind == 'appearance':
            uc.reg_write(x.UC_X86_REG_RDX, obj); uc.reg_write(x.UC_X86_REG_R8, callback)
        else:
            uc.reg_write(x.UC_X86_REG_RDX, archive)
        try:
            returned = h.call(functions['vector' if kind == 'appearance' else 'optional_reader'],
                              archive if kind == 'appearance' else obj, budget=300000) & 255
        except BufferError:
            return dict(accepted=False, status='local_storage_budget')
        except unicorn.UcError as error:
            raise ValueError('Character ' + kind + ' memory fault at ' + hex(reg('RIP'))) from error
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Character extension ABI differs')
        consumed = number(archive + 0x30, 8) - buffer
        require(0 <= consumed <= len(body), 'Character extension consumed outside input')
        after = bytes(uc.mem_read(archive - 16, 0x60))
        mutable = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        require(all(a == z for i, (a, z) in enumerate(zip(before, after)) if i not in mutable)
                and bytes(uc.mem_read(buffer - 16, len(body) + 32)) == b'\xab' * 16 + body + b'\xac' * 16,
                'Character extension input buffer/guards differ')
        for address, length, left, right in ((obj, 0x60, b'\xa5', b'\xa6'), (store, storage_size, b'\xa7', b'\xa8')):
            require(bytes(uc.mem_read(address - 16, 16)) == left * 16 and bytes(uc.mem_read(address + length, 16)) == right * 16,
                    'Character extension output guards differ')
        values = None
        if returned:
            wire = body[:consumed] if extra else body
            if kind == 'appearance':
                count = number(obj + 8, 4); require(count <= 8, 'Character appearance output budget')
                require(all(number(store + i * 16, 8) == b['appearance_item_table'] for i in range(count)),
                        'Character appearance item table differs')
                values = [[number(store + i * 16 + off, size) for off, size in ((8, 4), (12, 1), (14, 2))] for i in range(count)]
                record = record_body[:-28] + wire + record_body[-26:]
            else:
                flag = number(obj + 8, 1); count = number(mp + 8, 4); require(count <= 8, 'Character optional output budget')
                require(all(number(store + i * 0x38 + 8, 8) == b['optional_value_table']
                            and number(store + i * 0x38 + 0x20, 8) == b['time_table'] for i in range(count)),
                        'Character optional value/time table differs')
                values = sorted([[number(store + i * 0x38 + off, size) for off, size in
                                  ((0, 1), (0x10, 1), (0x14, 4), (0x18, 4), (0x1c, 4), (0x28, 8))] for i in range(count)]) if flag else None
                record = record_body[:-1] + wire
            decoded = decode_character_list(struct.pack('<IIH', 0, 0, 1) + record + bytes(28),
                                            max_payload_size=4096, max_characters=1, max_extension_items=32).records[0]
            expected = decoded.appearance_items if kind == 'appearance' else decoded.optional_items
            expected = [list(row) for row in expected] if expected is not None else None
            require(values == expected, 'Character extension runtime projection differs')
        return dict(accepted=bool(returned), consumed=consumed, values=values, operations=operations.copy(),
                    insertions=insertions.copy(), rehashes=rehashes.copy())

    if kind == 'appearance':
        groups = ((), ((0, 0, 0),), ((0xffffffff, 255, 65535), (0x12345678, 45, 0x8000)),
                  ((1, 2, 3),) * 8, tuple((i, 44 + i, 0xffff - i) for i in range(8)))
        bodies = [struct.pack('<H', len(items)) + b''.join(struct.pack('<IBH', *item) for item in items) for items in groups]
        oversized = struct.pack('<H', 9)
    else:
        groups = ((), ((0, 0, 0, 0, 0, 0),), ((255, 9, 0xffffffff, 0x80000000, 1, 0xffffffffffffffff),),
                  ((1, 255, 1, 2, 3, 4), (9, 10, 5, 6, 7, 8), (1, 2, 9, 10, 11, 12)),
                  tuple((i * 16 + 1, 255 - i, i, 0xffffffff - i, 0x80000000 + i, 0xffffffffffffffff - i) for i in range(8)))
        groups += (groups[-1] + ((1, 0, 9, 8, 7, 6),),)
        bodies = [bytes([flag]) + struct.pack('<H', len(items)) + b''.join(struct.pack('<BBIIIQ', *item) for item in items)
                  for flag in (1, 2, 255) for items in groups] + [b'\0']
        oversized = b'\1' + struct.pack('<H', 9) + b''.join(struct.pack('<BBIIIQ', i, 1, 2, 3, 4, 5) for i in range(9))
    cases = [run(body) for body in bodies]
    require(all(c['accepted'] and c['consumed'] == len(body) for c, body in zip(cases, bodies)), 'Character extension complete input rejected')
    if kind == 'optional':
        for body, case in zip(bodies[:-1], cases[:-1]):
            keys = [body[i] for i in range(3, len(body), 22)]
            require(case['insertions'] == list(dict.fromkeys(keys)), 'Character optional duplicate inserted another node')
        require(any(case['rehashes'] for case in cases), 'Character optional rehash path not exercised')
    one = bodies[-1] if kind == 'appearance' else bodies[-2]
    baseline = run(one)
    truncated = [run(one[:size]) for size in range(len(one))]
    failures = [run(one, fail_at=i) for i in range(len(baseline['operations']))]
    require(all(not case['accepted'] for case in truncated + failures), 'Character extension truncated/failing input accepted')
    require(all(len(case['operations']) == i + 1 for i, case in enumerate(failures)), 'Character extension continued after read failure')
    budget = run(oversized); require(not budget['accepted'] and budget.get('status') == 'local_storage_budget', 'Character extension storage budget not enforced')
    return dict(kind=kind, roots=len(roots), cases=cases, truncated=truncated, failures=failures, budget=budget,
                extra=run(one + b'extra', extra=True), evidence=h.evidence)


def verify(context, root):
    parts = [verify_component(context, root, kind) for kind in ('appearance', 'optional')]
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', components=parts,
                network_used=False, profile_activated=False,
                limits=['Separate explicit native component harnesses; input/loop/callback/item/value readers and map insertion execute.',
                        'Array allocation/cleanup, map reset/preallocated storage, bit-vector capacity, unseen-key predicate and bucket rehash are fixtures.',
                        'Duplicate hash-chain lookup/overwrite and clamp/read behavior are native; allocator lifetime and complete container implementations are not proved.',
                        'No whole-record/list integration, result handler, network, creation or runtime profile promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-character-extensions-checks', result)
    print(json.dumps(dict(report=str(path), components=[dict(kind=p['kind'], roots=p['roots'], cases=len(p['cases']),
        truncated=len(p['truncated']), failures=len(p['failures'])) for p in result['components']])))
