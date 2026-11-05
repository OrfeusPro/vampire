"""Bounded SDK candidate transfer from a pinned reviewed context."""
import argparse
import bisect
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys


HERE = Path(__file__).resolve().parent
WINDOW = 0x20000


@lru_cache(maxsize=None)
def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(path, sha):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('SDK transfer input changed: ' + path.name)
    return raw


def image_bytes(image, address, size):
    return load('update-native-contexts').image_bytes(image, address, size)


class Transfer:
    def __init__(self, root, context_path, source_sha, progress=None):
        if not re.fullmatch('[0-9a-f]{64}', source_sha):
            raise ValueError('SDK transfer requires full target SHA')
        self.root = Path(root)
        self.context_path = Path(context_path).resolve()
        self.context = json.loads(self.context_path.read_bytes())
        self.progress = progress
        if self.context.get('schema') != 1 or len(self.context.get('roots', {})) != 34:
            raise ValueError('Reviewed SDK context root set differs')
        self.inputs = {str(self.context_path): digest(self.context_path)}
        policy_path = HERE / 'knowledge/sdk-batch-rules.json'
        self.policy = json.loads(policy_path.read_bytes())
        pointer = self.policy['baseline_context']
        if (self.policy.get('schema') != 1 or self.policy.get('recipe') != 'sdk-batch-v1'
                or (HERE / 'knowledge' / pointer['path']).resolve() != self.context_path
                or digest(self.context_path) != pointer['sha256']):
            raise ValueError('SDK reviewed baseline policy differs')
        native_proof = self.policy['baseline_native']
        proof = json.loads(checked(Path(native_proof['path']), native_proof['sha256']))
        if proof['source_sha256'] != self.context['source_sha256'] or proof['native_case_executions'] != 3667:
            raise ValueError('SDK reviewed native proof differs')
        self.inputs[str(policy_path)] = digest(policy_path)
        self.inputs[native_proof['path']] = native_proof['sha256']
        for name in ('sdk-batch-transfer.py', 'build-native-entry-code.py',
                     'update-native-contexts.py', 'extract-native-enums.py'):
            self.inputs[str(HERE / name)] = digest(HERE / name)
        self.native = load('build-native-entry-code')
        self.signature = load('update-native-contexts').signature
        self.decoder = self.native.capstone.Cs(self.native.capstone.CS_ARCH_X86, self.native.capstone.CS_MODE_64)
        self.decoder.detail = True
        self.images = []
        for sha in (self.context['source_sha256'], source_sha):
            path = self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
            self.images.append(self.native.Image(checked(path, sha)))
            self.inputs[str(path)] = sha
        self.before, self.after = self.images
        self.source_sha = source_sha
        windows = []
        for at in sorted(int(at, 16) for at in self.context['roots'].values()):
            if windows and at - WINDOW <= windows[-1][1]:
                windows[-1][1] = at + WINDOW
            else:
                windows.append([at - WINDOW, at + WINDOW])
        starts = [low for low, _ in windows]
        self.fragments = {}
        for image in self.images:
            selected = {}
            for fragment, root in image.roots.items():
                at = image.pe.base + root[0]
                position = bisect.bisect_right(starts, at) - 1
                if position >= 0 and at <= windows[position][1]:
                    selected.setdefault(root, []).append(fragment)
            self.fragments[id(image)] = selected
        self.exports = {}
        for run, sha in self.context['exports'].items():
            if Path(run).name != run or not run.startswith('run-'):
                raise ValueError('Invalid reviewed SDK export path')
            path = self.root / 'ghidra/request-exports' / self.context['source_sha256'] / run / 'details.json'
            document = json.loads(checked(path, sha))
            if document['new_source_sha256'] != self.context['source_sha256']:
                raise ValueError('Reviewed SDK export source differs')
            self.inputs[str(path)] = sha
            for function in document['functions']:
                address = int(function['address'], 16)
                if address in self.exports:
                    raise ValueError('Duplicate reviewed SDK export')
                self.exports[address] = function
        for name, sha in self.context['generated_files'].items():
            if Path(name).name != name or not name.endswith('.py'):
                raise ValueError('Invalid SDK template path')
            path = HERE / name
            checked(path, sha)
            self.inputs[str(path)] = sha
        self.special = {int(item['current'], 16): item for item in self.context['switches']}
        if len(self.special) != 2:
            raise ValueError('SDK switch set differs')
        self.mapping = {}
        self.candidate_rows = {}
        self.switches = []

    def switch_rows(self, image, address, spec, baseline):
        function = self.exports[int(spec['current'], 16)]
        if not all(function.get(key) is True for key in (
                'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
            raise ValueError('Incomplete SDK switch export')
        entry = int(function['address'], 16)
        end = max(int(row['address'], 16) + len(bytes.fromhex(row['bytes'])) for row in function['instructions'])
        size = end - entry
        data = image_bytes(image, address, size)
        instructions = list(self.decoder.disasm(data, address))
        if sum(ins.size for ins in instructions) != size or not instructions or instructions[-1].mnemonic != 'ret':
            raise ValueError('SDK switch code prefix differs')
        rows = []
        table = None
        table_offset = int(spec['table'], 16) - self.before.pe.base
        for ins in instructions:
            encoded = bytearray(ins.bytes)
            call = ins.group(self.native.capstone.CS_GRP_CALL)
            branch = ins.group(self.native.capstone.CS_GRP_JUMP)
            target = ins.operands[0].imm if (call or branch) and ins.operands[0].type == self.native.X86_OP_IMM else None
            refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
                    if op.type == self.native.X86_OP_MEM and op.mem.base == self.native.X86_REG_RIP]
            offset = ins.address - address
            old_at = entry + offset
            old_row = next((row for row in function['instructions'] if int(row['address'], 16) == old_at), None)
            if old_row is None or len(bytes.fromhex(old_row['bytes'])) != ins.size:
                raise ValueError('SDK switch instruction boundary differs')
            if baseline and bytes(ins.bytes).hex() != old_row['bytes']:
                raise ValueError('Reviewed SDK switch instruction differs from source')
            old_ins = next(self.decoder.disasm(bytes.fromhex(old_row['bytes']), old_at))
            old_tables = [op for op in old_ins.operands if op.type == self.native.X86_OP_MEM
                          and op.mem.base != self.native.X86_REG_RIP and op.mem.disp == table_offset]
            if old_tables:
                if table is not None or len(old_tables) != 1 or ins.disp_size != 4:
                    raise ValueError('SDK switch operand differs')
                operand = ins.operands[list(old_ins.operands).index(old_tables[0])]
                table = image.pe.base + operand.mem.disp
                encoded[ins.disp_offset:ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
            rows.append(dict(address=ins.address, bytes=encoded.hex(), mnemonic=ins.mnemonic,
                             operands=ins.op_str, call=call, branch=branch, direct_target=target, rip_references=refs))
        part = image.containing(address)
        if part is None or image.roots[part] != part or image.pe.base + part[0] != address:
            raise ValueError('SDK switch unwind boundary differs')
        if table != address + size + 1 or table + spec['count'] * 4 != image.pe.base + part[1]:
            raise ValueError('SDK switch table boundary differs')
        padding = image_bytes(image, address + size, 1)
        if padding not in (b'\x90', b'\xcc'):
            raise ValueError('SDK switch padding differs')
        raw_table = image_bytes(image, table, spec['count'] * 4)
        if baseline and (raw_table.hex() != spec['bytes'] or hashlib.sha256(raw_table).hexdigest() != spec['sha256']):
            raise ValueError('Reviewed SDK switch table changed')
        targets = [image.pe.base + rva for rva in struct.unpack('<' + 'I' * spec['count'], raw_table)]
        if not set(targets) <= {row['address'] for row in rows}:
            raise ValueError('SDK switch target is outside code')
        return rows, dict(table=hex(table), offsets=[target - address for target in targets],
                          padding=padding.hex(), bytes=raw_table.hex(), count=spec['count'])

    def rows(self, image, address, original):
        key = (id(image), address, original if original in self.special else None)
        if key not in self.candidate_rows:
            if original in self.special:
                result = self.switch_rows(image, address, self.special[original], image is self.before)
            else:
                part = image.containing(address)
                if part is None or image.roots[part][0] + image.pe.base != address:
                    raise ValueError('SDK candidate is not an unwind root')
                root = image.roots[part]
                fragments = self.native.decode_ranges(image, {root}, functions=self.fragments[id(image)][root])
                rows = [row for fragment in fragments for row in fragment['instructions']]
                if sum(len(bytes.fromhex(row['bytes'])) for row in rows) > 65536:
                    raise ValueError('SDK candidate code budget exceeded')
                if image is self.before:
                    function = self.exports[address]
                    if not all(function.get(field) is True for field in (
                            'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                        raise ValueError('Incomplete reviewed SDK root')
                    exported = {int(row['address'], 16): row['bytes'] for row in function['instructions']}
                    if exported != {row['address']: row['bytes'] for row in rows}:
                        raise ValueError('Reviewed SDK export differs from whole unwind code')
                result = rows, None
            self.candidate_rows[key] = result
        return self.candidate_rows[key]

    def pair(self, original, current):
        before, old_table = self.rows(self.before, original, original)
        after, new_table = self.rows(self.after, current, original)
        self.add_rows(before, after)
        if old_table:
            if old_table['offsets'] != new_table['offsets'] or old_table['padding'] != new_table['padding']:
                raise ValueError('SDK switch targets differ')
            self.mapping.setdefault(int(old_table['table'], 16), set()).add(int(new_table['table'], 16))
            self.switches.append(dict(baseline=hex(original), current=hex(current), **new_table))

    def add_rows(self, before, after):
        if self.signature(self.native, before) != self.signature(self.native, after):
            raise ValueError('SDK complete instruction/control shape differs')
        for old, new in zip(before, after):
            self.mapping.setdefault(old['address'], set()).add(new['address'])
            if old['direct_target'] is not None:
                self.mapping.setdefault(old['direct_target'], set()).add(new['direct_target'])
            if len(old['rip_references']) != len(new['rip_references']):
                raise ValueError('SDK data reference arity differs')
            for a, b in zip(old['rip_references'], new['rip_references']):
                self.mapping.setdefault(a, set()).add(b)

    def leaf_rows(self, image, address, size):
        data = image_bytes(image, address, size)
        instructions = list(self.decoder.disasm(data, address))
        if sum(ins.size for ins in instructions) != size:
            raise ValueError('SDK leaf instruction boundary differs')
        return [dict(address=ins.address, bytes=bytes(ins.bytes).hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
                     call=ins.group(self.native.capstone.CS_GRP_CALL), branch=ins.group(self.native.capstone.CS_GRP_JUMP),
                     direct_target=ins.operands[0].imm if ins.operands and ins.operands[0].type == self.native.X86_OP_IMM
                     and (ins.group(self.native.capstone.CS_GRP_CALL) or ins.group(self.native.capstone.CS_GRP_JUMP)) else None,
                     rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                                     if op.type == self.native.X86_OP_MEM and op.mem.base == self.native.X86_REG_RIP])
                for ins in instructions]

    def transfer_leaves(self):
        result = []
        for spec in self.policy['leaves']:
            at = int(spec['address'], 16)
            raw = image_bytes(self.before, at, spec['size'])
            hits = self.mapping.get(at)
            if hits is None:
                offset = self.after.offset(at - self.after.pe.base - WINDOW)
                end = self.after.offset(at - self.after.pe.base + WINDOW) + len(raw)
                hits = set()
                while offset < end:
                    offset = self.after.data.find(raw, offset, end)
                    if offset < 0:
                        break
                    hits.add(self.after.pe.address(offset))
                    offset += 1
            if len(hits) != 1:
                raise ValueError('SDK leaf mapping missing or ambiguous: ' + hex(at))
            target, = hits
            before = self.leaf_rows(self.before, at, spec['size'])
            after = self.leaf_rows(self.after, target, spec['size'])
            self.add_rows(before, after)
            current = image_bytes(self.after, target, spec['size'])
            result.append(dict(baseline=hex(at), target=hex(target), size=spec['size'], kind=spec['kind'],
                               baseline_bytes=raw.hex(), target_bytes=current.hex(),
                               baseline_sha256=hashlib.sha256(raw).hexdigest(), target_sha256=hashlib.sha256(current).hexdigest()))
        return result

    def candidates(self, original):
        expected, old_table = self.rows(self.before, original, original)
        shape = self.signature(self.native, expected)
        part = self.before.roots[self.before.containing(original)]
        low = bisect.bisect_left(self.after.begins, original - self.after.pe.base - WINDOW)
        high = bisect.bisect_right(self.after.begins, original - self.after.pe.base + WINDOW)
        result = []
        for current_part in self.after.ranges[low:high]:
            if current_part != self.after.roots[current_part] or current_part[1] - current_part[0] != part[1] - part[0]:
                continue
            current = self.after.pe.base + current_part[0]
            if image_bytes(self.before, original, 4) != image_bytes(self.after, current, 4):
                continue
            try:
                rows, new_table = self.rows(self.after, current, original)
            except (ValueError, StopIteration, IndexError):
                continue
            if self.signature(self.native, rows) != shape:
                continue
            if old_table and (old_table['offsets'], old_table['padding']) != (new_table['offsets'], new_table['padding']):
                continue
            if not self.initializer_literals(expected, rows):
                continue
            result.append(current)
        if len(result) > 32:
            raise ValueError('SDK candidate budget exceeded at ' + hex(original))
        return result

    def initializer_literals(self, before, after):
        if before[0]['address'] >= 0x141300000:
            return True
        for old, new in zip(before, after):
            if old['mnemonic'] != 'lea' or not old['operands'].startswith('rdx,') or len(old['rip_references']) != 1:
                continue
            literals = []
            for image, row in ((self.before, old), (self.after, new)):
                value = image_bytes(image, row['rip_references'][0], 256)
                end = next((n for n in range(0, 256, 2) if value[n:n + 2] == b'\0\0'), None)
                if end is None:
                    return False
                literals.append(value[:end + 2])
            if literals[0] != literals[1]:
                return False
        return True

    def constrained(self, original, candidates):
        before, _ = self.rows(self.before, original, original)
        accepted = []
        for current in candidates:
            after, _ = self.rows(self.after, current, original)
            known = self.mapping.get(original)
            consistent = known is None or current in known
            for old, new in zip(before, after):
                for a, b in zip(old['rip_references'], new['rip_references']):
                    if a in self.mapping and b not in self.mapping[a]:
                        consistent = False
            if consistent:
                accepted.append(current)
        return accepted

    def run(self):
        addresses = sorted(int(at, 16) for at in self.context['roots'].values())
        if len(set(addresses)) != 34 or not set(addresses) <= set(self.exports):
            raise ValueError('SDK roots missing from reviewed exports')
        candidates = {}
        for at in addresses:
            candidates[at] = self.candidates(at)
            if self.progress:
                self.progress(dict(address=hex(at), candidates=len(candidates[at])))
        pending = set(addresses)
        roots = {}
        while pending:
            progress = False
            for at in sorted(pending):
                hits = self.constrained(at, candidates[at])
                if len(hits) == 1:
                    self.pair(at, hits[0])
                    roots[hex(at)] = hex(hits[0])
                    pending.remove(at)
                    progress = True
            if not progress:
                break
        leaves = self.transfer_leaves() if not pending else []
        for path, sha in self.inputs.items():
            checked(Path(path), sha)
        return dict(schema=1, recipe='sdk-batch-transfer-v1', source_sha256=self.source_sha,
                    baseline_sha256=self.context['source_sha256'], inputs=self.inputs, roots=roots,
                    unresolved={hex(at): [hex(hit) for hit in self.constrained(at, candidates[at])] for at in sorted(pending)},
                    links={hex(at): [hex(value) for value in sorted(values)] for at, values in sorted(self.mapping.items())},
                    switches=self.switches, leaves=leaves,
                    semantic_verification=False, network_used=False, profile_activated=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    args = parser.parse_args()
    report = Transfer(args.root, args.baseline, args.source_sha256,
                      progress=lambda row: print(json.dumps(row), file=sys.stderr, flush=True)).run()
    path = load('research-workflow').snapshot(args.root, 'sdk-batch-transfer-v1', report)
    print(json.dumps(dict(report=str(path), roots=len(report['roots']), unresolved=report['unresolved'])))
