"""Leased, source-bound stat observations; never changes the socket owner's state."""
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import time

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / 'resource-tools/vampir'
ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
CODEC_SHA = '70624e1a1225ddf14fddb6e215cf2d31de36285160db76296c42f7db6bcb9cd5'
PROOFS = {
    'notify': '4b6d7da19c0a9af1f043608d84ea7d097679b421448a70326ad3dada99b9c2b8',
    'initial': '99fa2824cb6fd12065e41111dadff2233b0e115e315552adcd4072f801343bd8',
}
PACKET_BINDINGS = {
    '321': 'c390d402da90e1b0a4aef9347c5b87d38aa0c4828264eeaeb1e5e5eae3675b3f',
    '322': '4dcd921f619e8883cabf5a231723b33e06a609abf1f93ca7007733536a08d93f',
}
ENUM_SHA = 'a9a373cdc17c73008ae0bc804a335d0996749187f092b49d7c8afc71a53d98e5'
FIELDS = {3: 'level', 4: 'hp', 5: 'max_hp', 9: 'mp', 10: 'max_mp'}
SAFE_INTEGER = 2**53 - 1


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pinned_document(relative, expected):
    path = ROOT / relative / expected / 'manifest.json'
    if path.stat().st_size > 262144 or digest(path) != expected:
        raise ValueError('Stat proof changed')
    return json.loads(path.read_text(encoding='utf-8'))


def packet_binding_verified(report, packet_id):
    reader, table, constructor, packet_name = {
        321: ('0x1456c4b20', '0x149922028', '0x1456bf0c0', 'PktCharacterLevelUpNotify'),
        322: ('0x1456c5a10', '0x149923e48', '0x1456c0770', 'PktStatChangeNotify'),
    }[packet_id]
    slots = report.get('slots')
    constructors = report.get('reviewed_constructors')
    if (report.get('source_sha256') != SOURCE or report.get('binding_verified') is not True
            or report.get('packet_id') != packet_id or report.get('reader') != reader
            or report.get('candidate_table') != table or report.get('packet') != packet_name
            or report.get('id_getter_bytes') != (b'\xb8' + struct.pack('<I', packet_id) + b'\xc3').hex()
            or type(slots) is not list or len(slots) != 8 or slots[4] != reader
            or report.get('table_bytes') != struct.pack('<8Q', *(int(slot, 16) for slot in slots)).hex()
            or type(constructors) is not list or len(constructors) != 1
            or constructors[0].get('owner') != constructor
            or not any(row.get('bytes') == '488901' for row in constructors[0].get('instructions', []))
            or digest(TOOLS / 'inspect-stat-bindings-11318.py') != report.get('tool_sha256')):
        raise ValueError('Packet ID to stat reader proof changed')


def enum_verified(report):
    rows = report.get('enums', {}).get('EStat')
    if (report.get('source_sha256') != SOURCE or report.get('known_vital_ids_match') is not True
            or type(rows) is not list or len(rows) != 208
            or digest(TOOLS / 'extract-native-enums.py') != report.get('tool_sha256')
            or digest(TOOLS / 'align-stat-batch-11318.py') != report.get('producer_sha256')):
        raise ValueError('Current stat enum proof changed')
    names, values = set(), set()
    for row in rows:
        if (type(row) is not dict or type(row.get('name')) is not str
                or type(row.get('value')) is not int or type(row.get('descriptor_offset')) is not int
                or row['descriptor_offset'] < 0 or type(row.get('name_offset')) is not int or row['name_offset'] < 0):
            raise ValueError('Current stat descriptor changed')
        names.add(row['name']);values.add(row['value'])
    expected = {'EStat::Level': 3, 'EStat::Hp': 4, 'EStat::MaxHp': 5, 'EStat::Mp': 9, 'EStat::MaxMp': 10}
    actual = {row['name']: row['value'] for row in rows}
    if (FIELDS != {3: 'level', 4: 'hp', 5: 'max_hp', 9: 'mp', 10: 'max_mp'}
            or len(names) != 208 or values != set(range(208)) or any(actual.get(k) != v for k, v in expected.items())):
        raise ValueError('Current vital enum mapping changed')


def load_codec():
    """Small immutable proof checks only; the owner preflight verifies its EXE.

    The samples endpoint supplies the immutable owner source identity. Repeating
    full EXE/native analysis in every disposable observer worker is unnecessary.
    """
    from vampir_core import stat_change_11318 as codec
    if codec.SOURCE_SHA256 != SOURCE or digest(codec.__file__) != CODEC_SHA:
        raise ValueError('Stat decoder evidence changed')
    for kind, expected in PROOFS.items():
        report = pinned_document('code-clues/stat-' + kind + '-11318', expected)
        if (report['source_sha256'] != SOURCE or report['portable_decoder_sha256'] != CODEC_SHA
                or len(report['cases']) != {'notify': 1119, 'initial': 203}[kind]
                or digest(TOOLS / ('replay-stat-' + kind + '-11318.py')) != report['tool_sha256']
                or digest(TOOLS / ('knowledge/native-contexts/stat-' + kind + '-11318.json')) != report['context_sha256']
                or digest(TOOLS / 'stat-support-11318.py') != report['fixture_tool_sha256']):
            raise ValueError('Stat proof source or producer changed')
        for relative, expected_dependency in report.get('dependency_sha256', {}).items():
            if Path(relative).name != relative or digest(TOOLS / relative) != expected_dependency:
                raise ValueError('Stat proof dependency changed')
    for packet_id, expected in PACKET_BINDINGS.items():
        packet_binding_verified(pinned_document('code-clues/stat-packet-bindings-11318', expected), int(packet_id))
    enum_verified(pinned_document('knowledge/stat-enums-11318', ENUM_SHA))
    return codec


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,48}', value)


def uint_text(value):
    return (type(value) is str and re.fullmatch(r'\d{1,20}', value)
            and int(value) <= 2**64 - 1)


def analyze(batch):
    if type(batch) is not dict:
        raise ValueError('Invalid observer batch')
    state, samples, events = (batch.get(name) for name in ('state', 'samples', 'events'))
    if not all(type(value) is dict for value in (state, samples, events)):
        raise ValueError('Invalid observer envelopes')
    bot, session = state.get('bot_id'), state.get('session_id')
    if not identifier(bot) or not identifier(session):
        raise ValueError('Invalid observer identity')
    person = state.get('character') or {}
    key, world = person.get('key'), str(person.get('world_id', ''))
    scope = dict(bot_id=bot, session_id=session, character_key=key if uint_text(key) else None,
                 world_id=world if uint_text(world) else None)
    result = dict(schema=1, semantics='last_received_stat_notification', source_sha256=SOURCE,
        **scope, status='waiting_for_notification', reason=None, stats=[],
        vitals={name: None for name in FIELDS.values()}, last_sample=None, sample_cursor=0,
        updated_at_ms=time.time_ns() // 1000000,
        sample_gap=False, event_gap=events.get('gap') is True, malformed_samples=0,
        provenance=dict(decoder_sha256=CODEC_SHA, native_proofs=dict(PROOFS),
                        packet_bindings=dict(PACKET_BINDINGS), enum_sha256=ENUM_SHA),
        owner_character_modified=False)
    def output():
        return dict(readonly_stats=result)
    if state.get('state') != 'connected' or scope['character_key'] is None or scope['world_id'] is None:
        result.update(status='unavailable', reason='character_not_connected')
        return output()
    if (samples.get('source_sha256') != SOURCE or samples.get('bot_id') != bot
            or samples.get('session_id') != session):
        result.update(status='unavailable', reason='sample_scope_not_verified')
        return output()
    rows, cursor = samples.get('samples'), samples.get('cursor')
    if (type(rows) is not list or len(rows) > 32 or type(cursor) is not int
            or not 0 <= cursor <= SAFE_INTEGER or type(samples.get('gap')) is not bool):
        raise ValueError('Invalid sample budget or cursor')
    result.update(sample_cursor=cursor, sample_gap=samples['gap'])
    try:
        codec = load_codec()
    except (OSError, ValueError, KeyError, ImportError, TypeError):
        result.update(status='unavailable', reason='decoder_proof_not_verified')
        return output()
    previous = (batch.get('previous') or {}).get('readonly_stats')
    values = {}
    last_cursor = 0
    if (type(previous) is dict and all(previous.get(k) == v for k, v in scope.items())
            and previous.get('source_sha256') == SOURCE and previous.get('provenance') == result['provenance']
            and not result['sample_gap'] and not result['event_gap']
            and type(previous.get('sample_cursor')) is int and 0 <= previous['sample_cursor'] <= cursor):
        last_cursor = previous['sample_cursor']
        prior = previous.get('stats')
        if type(prior) is list and len(prior) <= 256:
            for row in prior:
                if (type(row) is dict and type(row.get('id')) is int and -2**31 <= row['id'] < 2**31
                        and type(row.get('value')) is str and re.fullmatch(r'-?\d{1,20}', row['value'])
                        and -2**63 <= int(row['value']) < 2**63):
                    values[row['id']] = int(row['value'])
                else:
                    values.clear()
                    break
            if values:
                result['last_sample'] = previous.get('last_sample')
    sequence = last_cursor
    for row in rows:
        if (type(row) is not dict or type(row.get('seq')) is not int or not 1 <= row['seq'] <= cursor
                or type(row.get('packet_id')) is not int):
            raise ValueError('Invalid sample identity')
        if row['seq'] <= last_cursor:
            continue
        if row['seq'] <= sequence:
            raise ValueError('Sample order changed')
        sequence = row['seq']
        packet_id = row['packet_id']
        if packet_id not in (321, 322):
            continue
        body64 = row.get('body_base64')
        try:
            if type(body64) is not str or len(body64) > 87384:
                raise ValueError('Sample byte limit')
            body = base64.b64decode(body64, validate=True)
            decoder = codec.decode_stat_change if packet_id == 322 else codec.decode_character_level_up
            change = decoder(body, source_sha256=SOURCE, max_records=256)
            if str(change.entity_key) != key:
                continue
            for stat in change.values:
                values[stat.stat_type] = stat.signed_second
            if len(values) > 256:
                raise BufferError('Observed stat budget')
            result['last_sample'] = dict(seq=row['seq'], packet_id=packet_id)
        except (ValueError, BufferError, TypeError):
            values.clear()
            result['last_sample'] = None
            result['malformed_samples'] += 1
    result['stats'] = [dict(id=stat, value=str(value)) for stat, value in sorted(values.items())]
    for stat, name in FIELDS.items():
        value = values.get(stat)
        result['vitals'][name] = value if type(value) is int and 0 <= value <= SAFE_INTEGER else None
    if values:
        result['status'] = 'observed_partial'
    elif result['malformed_samples']:
        result['reason'] = 'malformed_notification'
    elif result['sample_gap'] or result['event_gap']:
        result['reason'] = 'observation_gap'
    return output()
