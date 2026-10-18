"""Version-bound static evidence for separate AreaReward/NpcReward consumers.

Reads the installed client only. Does not establish server kill/reward rules.
"""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    native = module('scope_native', 'build-native-entry-code.py')
    calls = module('scope_calls', 'build-entry-window-code.py')
    source = json.loads((native.ROOT / 'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Installed client SHA changed')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    image = native.Image(data)
    managers = [
        dict(table='AreaReward', name_getter=0x145b63820, loader=0x145b67fb0,
             name_slot=0x1499ae4e0, accessor=0x145b62f10, group_lookup=0x145b5a790),
        dict(table='NpcReward', name_getter=0x145b63bc0, loader=0x145b6b950,
             name_slot=0x1499b0318, accessor=0x145b63210, group_lookup=0x145b5aee0),
    ]
    candidates = []
    targets = {row['group_lookup'] for row in managers}
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates += calls.direct_call_candidates(data, section['raw'],
                section['raw_size'], image.pe.address, targets)
    addresses = {address for address, _ in candidates}
    addresses.update(row[key] for row in managers
                     for key in ('name_getter', 'accessor', 'group_lookup'))
    roots = {image.roots[image.containing(address)] for address in addresses
             if image.containing(address) is not None}
    groups = {root: [] for root in roots}
    for function in image.ranges:
        if image.roots[function] in groups:
            groups[image.roots[function]].append(function)
    fragments, failures = [], []
    for root, functions in groups.items():
        try:
            fragments += native.decode_ranges(image, {root}, functions)
        except ValueError as error:
            failures.append(dict(root_begin_rva=root[0], error=str(error)))
    instructions = {row['address']: row for fragment in fragments
                    for row in fragment['instructions']}
    verified_calls = [dict(address=address, target=target) for address, target in candidates
                      if calls.checked_call(instructions.get(address), target)]
    literal_refs = []
    for fragment in fragments:
        for row in fragment['instructions']:
            for address in row['rip_references']:
                try:
                    offset = image.offset(address - image.pe.base)
                except ValueError:
                    continue
                match = re.match(rb'(?:[\x20-\x7e]\x00){5,}', data[offset:offset + 1024])
                if match:
                    literal_refs.append(dict(instruction_address=row['address'],
                        root_begin_rva=fragment['root_begin_rva'], file_offset=offset,
                        text=match.group().decode('utf-16le')))
    for manager in managers:
        offset = image.offset(manager['name_slot'] - image.pe.base)
        if struct.unpack_from('<Q', data, offset)[0] != manager['name_getter']:
            raise ValueError('Manager name slot changed')
        if struct.unpack_from('<Q', data, offset - 16)[0] != manager['loader']:
            raise ValueError('Manager loader slot changed')
        root = image.roots[image.containing(manager['group_lookup'])][0]
        if not any(fragment['root_begin_rva'] == root and any(
                row['call'] and row['direct_target'] == manager['accessor']
                for row in fragment['instructions']) for fragment in fragments):
            raise ValueError('Group lookup no longer calls reviewed manager')
        manager['name_slot_file_offset'] = offset
    # These two paths independently reference AreaReward lookup and client UI resources.
    reviewed = [
        (0x1464cbdfd, 0x145b5a790, 'Map/CommonT/WBP_MapDropItemListT'),
        (0x1460bfce2, 0x145b5a790, 'Dungeon/WBP_MonsterInfoRewardT'),
        (0x1460c3a02, 0x145b5aee0, 'Dungeon/WBP_MonsterInfoRewardT'),
    ]
    observations = []
    for address, target, text in reviewed:
        if not calls.checked_call(instructions.get(address), target):
            raise ValueError('Reviewed UI lookup call changed')
        root = image.roots[image.containing(address)][0]
        refs = [row for row in literal_refs
                if row['root_begin_rva'] == root and row['text'] == text]
        if not refs:
            raise ValueError('Reviewed UI resource reference missing')
        observations.append(dict(call_address=address, lookup_target=target,
            root_begin_rva=root, ui_resource=text, resource_references=refs))
    result = dict(source=source['source'], sha256=source['sha256'],
        managers=managers, direct_group_lookup_calls=verified_calls,
        ui_observations=observations, literal_references=literal_refs, fragments=fragments,
        undecoded_roots=failures,
        limits=['Static client UI consumption only; no gameplay was executed.',
                'The area key producer and server kill reward application remain unproved.',
                'No percentage denominator or final chance calculation is established.'])
    path = native.ROOT / 'code-clues/reward-scope-code.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(output=str(path), verified_group_calls=len(verified_calls),
        ui_observations=len(observations), fragments=len(fragments))))


if __name__ == '__main__':
    main()
