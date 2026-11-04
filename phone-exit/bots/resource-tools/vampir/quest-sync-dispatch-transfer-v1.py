"""Transfer the QuestSync 1854 handler and receiver from a reviewed baseline."""
import hashlib
import json
from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
RECIPE = 'quest-sync-dispatch-transfer-v1'
POLICY = HERE / 'knowledge/quest-sync-dispatch-transfer.json'
SHA = re.compile('[0-9a-f]{64}')
FLAGS = dict(target_exports_verified=False, native_consumer_verified=False,
             consumer_semantic_verified=False, runtime_activated=False, profile_activated=False)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tools():
    names = ('quest-action-transfer-rules-v1', 'quest-reader-transfer-rules-v1',
             'quest-input-seed-v2', 'update-bindings', 'update-native-contexts',
             'update-native-version-result', 'update-native-archive-wire',
             'build-native-entry-code', 'extract-native-enums')
    return {str(path): digest(path) for path in (Path(__file__).resolve(), POLICY,
             HERE / 'knowledge/quest-reader-transfer-rules.json',
             *(HERE / (name + '.py') for name in names))}


def policy():
    raw = POLICY.read_bytes()
    value = json.loads(raw)
    if (len(raw) > 8192 or set(value) != {'schema', 'recipe', 'baseline_probe_sha256',
            'registration_relocation_bytes', 'fixture_offsets', 'indirect_model_apply'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['recipe'] != RECIPE or not SHA.fullmatch(value['baseline_probe_sha256'])
            or set(value['fixture_offsets']) != {'reset_prepare', 'reset_storage', 'reset_finish', 'progress',
                'key_wrapper', 'notify_lookup', 'notify_flag', 'notify_model', 'notify_dispatch'}
            or value['indirect_model_apply'] != dict(offset=225, operand='rbp', slot='0x48', fixture='0x2803e000')):
        raise ValueError('QuestSync dispatch rule differs')
    return value


def baseline(index, args):
    rule = policy()
    sha = rule['baseline_probe_sha256']
    folder = Path(args.root) / 'knowledge/quest-sync-dispatch-static-probe-v1'
    pointer = dict(path=str((folder / sha / 'manifest.json').resolve()), sha256=sha)
    probe = index.extension('quest-action-transfer-rules-v1').document(index, pointer, folder)
    if (type(probe.get('schema')) is not int or probe['schema'] != 1 or probe['packet_id'] != 1854
            or probe.get('recipe') != 'quest-sync-dispatch-static-probe-v1'
            or probe.get('whole_instruction_shape_verified') is not True
            or any(probe.get(key) is not False for key in ('native_execution', 'network_used', 'profile_activated'))):
        raise ValueError('QuestSync dispatch baseline probe scope differs')
    return pointer, probe


def dependencies(index, args, reader_proof_pointer):
    """Independent immutable dependencies for the caller's journal key and final guard."""
    pointer, probe = baseline(index, args)
    seed = index.extension('quest-input-seed-v2')
    if not seed.exact_pointer(reader_proof_pointer):
        raise ValueError('QuestSync dispatch reader proof pointer differs')
    export = probe['baseline_exports']
    export_receipt = index.receipt_for(Path(export['path'])).resolve()
    return tools() | {p['path']: p['sha256'] for p in (pointer, export, reader_proof_pointer)} | {
        str(export_receipt): index.digest(export_receipt)}


def getter(rules, api, image, at):
    raw = api.image_bytes(image, at, 8)
    if raw[:3] != bytes.fromhex('488b05') or raw[-1] != 0xc3:
        raise ValueError('QuestSync pointer getter instruction shape changed')
    storage = at + 7 + struct.unpack_from('<i', raw, 3)[0]
    rules.mutable_storage(image, storage)
    return raw.hex(), storage


def read_table(api, image, at):
    rva = at - image.pe.base
    sections = [s for s in image.pe.sections if s['name'] == '.rdata'
                and s['rva'] <= rva and rva + 24 <= s['rva'] + s['raw_size']]
    if at % 8 or len(sections) != 1:
        raise ValueError('QuestSync handler table outside readonly source storage')
    raw = api.image_bytes(image, at, 24)
    slots = struct.unpack('<3Q', raw)
    if len(set(slots)) != 3 or any(not slot for slot in slots):
        raise ValueError('QuestSync handler table aliases or null slots')
    return raw, slots


def registration_owner(image, address, size):
    first, last = image.containing(address), image.containing(address + size - 1)
    if first is None or last is None or image.roots[first] != image.roots[last]:
        raise ValueError('QuestSync registration window crosses unwind roots')
    return image.pe.base + image.roots[first][0]


def reader_context(index, args, pointer):
    seed = index.extension('quest-input-seed-v2')
    folder = Path(args.root) / 'knowledge/quest-reader-transfer-proofs-v1'
    if (not seed.exact_pointer(pointer) or Path(pointer['path']).name != 'manifest.json'
            or Path(pointer['path']).parent.name != pointer['sha256']):
        raise ValueError('QuestSync dispatch reader proof address differs')
    proof = seed.pointer_document(index, pointer, folder)
    if (type(proof.get('schema')) is not int or proof['schema'] != 1
            or proof.get('recipe') != 'quest-reader-transfer-v1' or proof.get('method') != 'static'
            or any(proof.get(key) is not False for key in ('native_consumer_verified', 'runtime_activated', 'profile_activated'))):
        raise ValueError('QuestSync dispatch reader proof scope differs')
    index.extension('quest-reader-transfer-rules-v1').validate_package(proof['package'], proof['inputs'])
    return proof['package']['target_contexts']['quest-sync'], proof['inputs']['baseline_source_sha256']


def transfer(index, args, reader_proof_pointer):
    rules = index.extension('quest-action-transfer-rules-v1')
    reader_rules = index.extension('quest-reader-transfer-rules-v1')
    bindings = index.extension('update-bindings')
    native = index.extension('build-native-entry-code')
    api = index.extension('update-native-contexts')
    add_link = index.extension('update-native-archive-wire').add_link
    pointer, probe = baseline(index, args)
    rule = policy()
    old = probe['baseline']
    old_sha = old['source']['sha256']
    context, seed_sha = reader_context(index, args, reader_proof_pointer)
    sha = context['source_sha256']
    source = Path(args.root) / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if (old_sha != seed_sha or old_sha == sha or not SHA.fullmatch(sha)
            or Path(context['source']).resolve() != source.resolve()):
        raise ValueError('QuestSync dispatch ordered baseline or target source differs')
    before = args.source_store.image(native, old_sha)
    after = args.source_store.image(native, sha)
    old_export = rules.document(index, probe['baseline_exports'], Path(args.root) / 'ghidra/request-exports' / old_sha)
    if old_export.get('new_source_sha256', old_export.get('source_sha256')) != old_sha:
        raise ValueError('QuestSync dispatch baseline export source differs')
    roots = {name: int(row['entry'], 16) for name, row in old['roots'].items()}
    old_rows = {name: bindings.rows(native, before, address) for name, address in roots.items()}
    for name, rows in old_rows.items():
        matches = [fn for fn in old_export['functions'] if fn['address'] == hex(roots[name])]
        if (len(matches) != 1 or matches[0].get('decompilation_completed') is not True
                or [(int(row['address'], 16), row['bytes'].lower()) for row in matches[0]['instructions']]
                != [(row['address'], row['bytes']) for row in rows] or old['roots'][name]['rows'] != rows):
            raise ValueError('QuestSync dispatch baseline whole export differs: ' + name)

    packet_ctor = int(context['functions']['packet_constructor'], 16)
    packet_reader = context['functions']['reader']
    tables = [table for table, slot, at in context['bindings'] if slot == '0x20' and at == packet_reader]
    if len(tables) != 1:
        raise ValueError('QuestSync reader packet table association differs')
    packet_table = int(tables[0], 16)
    getters = [at for table, slot, at in context['bindings'] if table == tables[0] and slot == '0x28']
    if (len(getters) != 1 or context['leaves'].get(getters[0]) != 'b83e070000c3'
            or api.image_bytes(after, int(getters[0], 16), 6) != bytes.fromhex('b83e070000c3')
            or struct.unpack('<Q', api.image_bytes(after, packet_table + 0x28, 8))[0] != int(getters[0], 16)):
        raise ValueError('QuestSync dispatch packet ID association differs')

    reg = old['registration']
    old_at = int(reg['entry'], 16)
    raw = bytes.fromhex(reg['bytes'])
    if len(raw) != 57 or api.image_bytes(before, old_at, 57) != raw:
        raise ValueError('QuestSync baseline registration window changed')
    if registration_owner(before, old_at, 57) != int(reg['owner'], 16):
        raise ValueError('QuestSync baseline registration owner differs')
    reg_rows = rules.decode(native, before, old_at, 57)
    start_mapping = {int(old['constructor'], 16): packet_ctor, int(old['packet_table'], 16): packet_table}

    def registration_link(target):
        linked = dict(start_mapping)
        rules.pair(native, reg_rows, rules.decode(native, after, target, 57), linked, reg['policy'])
        registration_owner(after, target, 57)
        return linked

    def candidate_matches(target):
        try:
            registration_link(target)
        except ValueError:
            return False
        return True

    candidates = rules.masked_hits(after, old_at, raw, rule['registration_relocation_bytes'], candidate_matches)
    if len(candidates) != 1:
        raise ValueError('QuestSync registration window missing or ambiguous: ' + str(len(candidates)))
    target_at = candidates[0]
    mapping = registration_link(target_at)
    old_table = int(old['handler_table']['entry'], 16)
    table = mapping[old_table]
    old_table_bytes, old_slots = read_table(api, before, old_table)
    table_bytes, slots = read_table(api, after, table)
    if (old_table_bytes.hex() != old['handler_table']['bytes']
            or old_slots != tuple(int(at, 16) for at in old['handler_table']['slots'])
            or old_slots[2] != roots['handler']):
        raise ValueError('QuestSync dispatch baseline handler slots differ')
    for old_slot, slot in zip(old_slots, slots):
        add_link(mapping, old_slot, slot)
    trampoline = bytes.fromhex('488b0148ff6010')
    if any(api.image_bytes(image, at, len(trampoline)) != trampoline for image, at in (
            (before, old_slots[1]), (after, slots[1]))):
        raise ValueError('QuestSync dispatch +0x08 trampoline shape differs')

    new_rows = {}
    for name in ('handler', 'receiver'):
        new_rows[name] = bindings.rows(native, after, mapping[roots[name]])
        rules.pair(native, old_rows[name], new_rows[name], mapping, old['roots'][name]['policy'])
    old_provider = int(old['provider']['entry'], 16)
    provider = mapping[old_provider]
    provider_bytes, storage = getter(rules, api, after, provider)
    old_provider_bytes, old_storage = getter(rules, api, before, old_provider)
    if old_provider_bytes != old['provider']['bytes'] or hex(old_storage) != old['provider']['mutable_global']:
        raise ValueError('QuestSync baseline model pointer getter differs')
    add_link(mapping, old_storage, storage)

    calls = old['roots']['receiver']['policy']['calls']
    indirect = rule['indirect_model_apply']
    consumed = {str(indirect['offset'])}
    if calls[str(indirect['offset'])] != indirect['operand']:
        raise ValueError('QuestSync baseline indirect callback shape differs')
    fixtures, callers, boundaries = {}, {}, {}
    for role, offsets in rule['fixture_offsets'].items():
        entries = {int(calls[str(offset)], 16) for offset in offsets}
        if not offsets or len(entries) != 1 or consumed.intersection(map(str, offsets)):
            raise ValueError('QuestSync direct fixture role is ambiguous: ' + role)
        consumed.update(map(str, offsets))
        address = entries.pop()
        target = mapping[address]
        if role == 'notify_lookup':
            _, old_value = getter(rules, api, before, address)
            _, value = getter(rules, api, after, target)
            add_link(mapping, old_value, value)
            boundary = dict(baseline=hex(address), target=hex(target), kind='excluded-pointer-getter', body_verified=False)
        else:
            boundary = reader_rules.check_boundary(native, bindings, before, after, address, target)
        fixtures[role] = hex(target)
        callers[role] = [hex(mapping[roots['receiver'] + offset]) for offset in offsets]
        boundaries[role] = boundary
    if consumed != set(calls) or len(set(fixtures.values())) != len(fixtures):
        raise ValueError('QuestSync receiver fixture caller coverage differs')
    callsite = hex(mapping[roots['receiver'] + indirect['offset']])
    fixtures['model_apply'] = indirect['fixture']
    callers['model_apply'] = [callsite]
    data = old['roots']['receiver']['policy']['data']
    callback = int(data['297'][0], 16)
    if set(data) != {'297'} or any(api.image_bytes(image, at, 6) != bytes.fromhex('488b01ff6028')
            for image, at in ((before, callback), (after, mapping[callback]))):
        raise ValueError('QuestSync notify callback association differs')

    context = dict(schema=1, recipe=RECIPE, method='static', family='quest-sync-dispatch', packet_id=1854,
        source=str(source.resolve()), source_sha256=sha, baseline_source_sha256=old_sha, baseline_probe=pointer,
        reader_proof=reader_proof_pointer, functions={name: hex(mapping[at]) for name, at in roots.items()},
        leaves={hex(provider): provider_bytes, hex(slots[1]): trampoline.hex()}, provider=hex(provider),
        handler_global=hex(storage),
        handler_table=hex(table), handler_trampoline=hex(slots[1]), packet_table=hex(packet_table),
        tables=[dict(target=hex(table), bytes=table_bytes.hex())],
        bindings=[[hex(table), hex(offset), hex(slot)] for offset, slot in zip((8, 16), slots[1:])],
        fixtures=fixtures, fixture_calls=callers, fixture_boundaries=boundaries,
        indirect_fixtures=[[callsite, indirect['operand'], indirect['fixture']]],
        notify_callback=hex(mapping[callback]), registration=dict(baseline=hex(old_at), target=hex(target_at),
            bytes=api.image_bytes(after, target_at, 57).hex(), owner=hex(registration_owner(after, target_at, 57)),
            constructor=hex(packet_ctor), helper=hex(mapping[int(reg['register_helper'], 16)]), owner_executed=False),
        whole_instruction_shape_verified=True, **FLAGS)
    validate_package(context, sha, reader_proof_pointer)
    return context


def validate_package(context, sha=None, reader_proof_pointer=None):
    """Validate scope and the projections consumed by the native adapter."""
    if (not isinstance(context, dict) or type(context.get('schema')) is not int
            or context['schema'] != 1 or context.get('recipe') != RECIPE
            or context.get('family') != 'quest-sync-dispatch' or context.get('method') != 'static'
            or type(context.get('packet_id')) is not int or context['packet_id'] != 1854
            or context.get('whole_instruction_shape_verified') is not True
            or any(context.get(key) is not False for key in FLAGS)
            or not SHA.fullmatch(context['source_sha256']) or not SHA.fullmatch(context['baseline_source_sha256'])
            or (sha is not None and context['source_sha256'] != sha)
            or (reader_proof_pointer is not None and context['reader_proof'] != reader_proof_pointer)):
        raise ValueError('QuestSync dispatch static context scope differs')
    rule = policy()
    indirect = rule['indirect_model_apply']
    fixtures = context['fixtures']
    roles = set(rule['fixture_offsets']) | {'model_apply'}
    functions = context['functions']
    if (set(fixtures) != roles or set(context['fixture_calls']) != roles
            or set(context['fixture_boundaries']) != set(rule['fixture_offsets'])
            or fixtures['model_apply'] != indirect['fixture'] or len(set(fixtures.values())) != len(roles)
            or set(functions) != {'handler', 'receiver'} or len(set(functions.values())) != 2
            or len(context['leaves']) != 2 or context['provider'] == context['handler_trampoline']
            or not re.fullmatch('488b05[0-9a-f]{8}c3', context['leaves'].get(context['provider'], ''))
            or context['leaves'].get(context['handler_trampoline']) != '488b0148ff6010'
            or context['registration'].get('owner_executed') is not False or len(bytes.fromhex(context['registration']['bytes'])) != 57):
        raise ValueError('QuestSync dispatch static role coverage differs')
    if set(fixtures.values()) & (set(functions.values()) | set(context['leaves'])):
        raise ValueError('QuestSync dispatch fixtures overlap native entries')
    receiver = int(functions['receiver'], 16)
    callsite = hex(receiver + indirect['offset'])
    if (context['indirect_fixtures'] != [[callsite, indirect['operand'], indirect['fixture']]]
            or context['fixture_calls']['model_apply'] != [callsite]):
        raise ValueError('QuestSync dispatch indirect fixture link differs')
    for role, offsets in rule['fixture_offsets'].items():
        boundary = context['fixture_boundaries'][role]
        kind = 'excluded-pointer-getter' if role == 'notify_lookup' else 'exact-unwind-entry'
        if (context['fixture_calls'][role] != [hex(receiver + offset) for offset in offsets]
                or boundary['target'] != fixtures[role] or boundary['kind'] != kind
                or boundary['body_verified'] is not False):
            raise ValueError('QuestSync dispatch cached fixture provenance differs: ' + role)
    provider = int(context['provider'], 16)
    raw_getter = bytes.fromhex(context['leaves'][context['provider']])
    if int(context['handler_global'], 16) != provider + 7 + struct.unpack_from('<i', raw_getter, 3)[0]:
        raise ValueError('QuestSync dispatch cached model pointer link differs')
    registration = context['registration']
    target = int(registration['target'], 16)
    window = bytes.fromhex(registration['bytes'])
    for displacement, end, expected in ((3, 7, context['handler_table']),
            (34, 38, registration['constructor']), (53, 57, registration['helper'])):
        if target + end + struct.unpack_from('<i', window, displacement)[0] != int(expected, 16):
            raise ValueError('QuestSync dispatch cached registration links differ')
    expected_bindings = [[context['handler_table'], '0x8', context['handler_trampoline']],
                         [context['handler_table'], '0x10', functions['handler']]]
    if context['bindings'] != expected_bindings or len(context['tables']) != 1:
        raise ValueError('QuestSync dispatch handler table projection differs')
    table = context['tables'][0]
    raw_table = bytes.fromhex(table['bytes'])
    if (table['target'] != context['handler_table'] or len(raw_table) != 24
            or struct.unpack('<3Q', raw_table)[1:] !=
                (int(context['handler_trampoline'], 16), int(functions['handler'], 16))):
        raise ValueError('QuestSync dispatch cached handler table bytes differ')
