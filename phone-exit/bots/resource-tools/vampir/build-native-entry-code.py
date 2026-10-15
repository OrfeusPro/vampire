"""Read-only entry-code evidence: RIP xrefs, chained unwind ranges and decoded edges.

Does not execute the game, read process memory, patch code, or infer UI input.
"""
import bisect
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

spec = importlib.util.spec_from_file_location('entry_pe', HERE / 'extract-native-enums.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class Image:
    def __init__(self, data):
        self.data, self.pe = data, native.PE(data)
        header = struct.unpack_from('<I', data, 60)[0]
        # PE32+ data-directory[3]: exception table, not raw .pdata padding.
        rva, size = struct.unpack_from('<II', data, header + 24 + 112 + 3 * 8)
        if not size or size % 12:
            raise ValueError('Unsupported exception directory')
        offset = self.offset(rva)
        self.ranges = [struct.unpack_from('<III', data, position)
                       for position in range(offset, offset + size, 12)]
        if any(not 0 < b < e or not u for b, e, u in self.ranges):
            raise ValueError('Invalid runtime function range')
        self.ranges.sort()
        if any(a[1] > b[0] for a, b in zip(self.ranges, self.ranges[1:])):
            raise ValueError('Overlapping exception ranges')
        self.begins = [row[0] for row in self.ranges]
        self.roots = {row: self.unwind_root(row) for row in self.ranges}

    def offset(self, rva):
        for section in self.pe.sections:
            delta = rva - section['rva']
            if 0 <= delta < section['raw_size']:
                return section['raw'] + delta
        raise ValueError('RVA outside file-backed sections')

    def unwind_root(self, function):
        seen = set()
        while True:
            if function in seen or len(seen) >= 32:
                raise ValueError('Invalid unwind chain')
            seen.add(function)
            offset = self.offset(function[2])
            version_flags, _, count, _ = struct.unpack_from('<BBBB', self.data, offset)
            if version_flags & 7 not in (1, 2):
                raise ValueError('Unsupported unwind version')
            flags = version_flags >> 3
            if flags & 4:
                if flags & 3:
                    raise ValueError('Chained unwind also has handler')
                position = offset + 4 + ((count + 1) // 2) * 4
                function = struct.unpack_from('<III', self.data, position)
                if not 0 < function[0] < function[1]:
                    raise ValueError('Invalid chained range')
            else:
                return function

    def containing(self, address):
        rva = address - self.pe.base
        index = bisect.bisect_right(self.begins, rva) - 1
        if index >= 0 and rva < self.ranges[index][1]:
            return self.ranges[index]
        return None


def rip_candidates(image, targets):
    """Fast candidate scan only; caller must verify decoded instruction boundaries."""
    found = []
    for section in image.pe.sections:
        if section['name'] != '.text':
            continue
        start, size = section['raw'], section['raw_size']
        data = image.data[start:start + size]
        for match in re.finditer(rb'[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', data):
            offset = start + match.start()
            if offset + 7 > start + size:
                continue
            address = image.pe.address(offset)
            target = address + 7 + struct.unpack_from('<i', image.data, offset + 3)[0]
            if target in targets:
                found.append((address, target))
    return found


def decode_ranges(image, roots, functions=None):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    result = []
    for function in image.ranges if functions is None else functions:
        root = image.roots[function]
        if root not in roots:
            continue
        begin, end, unwind = function
        if end - begin > 100000:
            raise ValueError('Unexpectedly large entry fragment')
        offset = image.offset(begin)
        raw = image.data[offset:offset + end - begin]
        address = image.pe.base + begin
        rows = []
        for ins in decoder.disasm(raw, address):
            references = [ins.address + ins.size + op.mem.disp for op in ins.operands
                          if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            is_branch = ins.group(capstone.CS_GRP_JUMP)
            is_call = ins.group(capstone.CS_GRP_CALL)
            direct_target = (ins.operands[0].imm if (is_branch or is_call) and ins.operands
                             and ins.operands[0].type == X86_OP_IMM else None)
            rows.append(dict(address=ins.address, file_offset=offset + ins.address - address,
                bytes=bytes(ins.bytes).hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
                rip_references=references, branch=is_branch, call=is_call, direct_target=direct_target))
        if not rows or sum(len(bytes.fromhex(row['bytes'])) for row in rows) != len(raw):
            raise ValueError('Fragment not fully decoded')
        result.append(dict(begin_rva=begin, end_rva=end, unwind_rva=unwind,
            root_begin_rva=root[0], file_offset=offset, sha256=hashlib.sha256(raw).hexdigest(), instructions=rows))
    return result


def reviewed_checks(instructions):
    """Version-bound observations, not an executable game or GUI state machine."""
    checks = [
        dict(id='signin_result_branch',
             anchors=[(0x14641809c, 'e85f1a1fff'), (0x1464180a1, '84c0'),
                      (0x1464180a3, '0f8513010000'), (0x1464181bf, 'e86cd50000')],
             observation='Result AL nonzero branches toward the direct call at 0x1464181bf; zero falls through to SignIn-failure diagnostics.',
             unresolved='Callee at 0x145609b00 and earlier gating conditions are not fully reconstructed.'),
        dict(id='last_server_value',
             anchors=[(0x1464257b5, '8bb008030000'), (0x1464257c0, '448bc6'),
                      (0x1464257f0, '3b358a4b1f03'), (0x1464257f6, '753b'),
                      (0x1464257f8, '8b3536fdcf04')],
             observation='The value logged as GetLastPlayedServerId is loaded from [RAX+0x308]. Comparison to a global controls substitution from another global.',
             unresolved='Global identities, fallback value and server validity policy are unresolved.'),
        dict(id='server_record_null',
             anchors=[(0x14642588b, 'e8b03b91ff'), (0x146425893, '4885c0'),
                      (0x146425896, '0f8510010000')],
             observation='The call receives ESI in EDX; a null result enters the None server Info diagnostic branch, nonnull branches to 0x1464259ac.',
             unresolved='No concrete popup widget has been bound to this failure branch.'),
        dict(id='sequence_storage_and_4_to_7',
             anchors=[(0x1464263dc, '889ed90b0000'), (0x1464263eb, '80fb04'),
                      (0x1464263f7, '7409'), (0x146426400, '753c'),
                      (0x146426402, 'b307'), (0x146426404, 'e959ffffff')],
             observation='Sequence BL is stored at [RSI+0xbd9]. For value 4, failed AL checks select 7 and loop to sequence processing.',
             unresolved='Sequence enum and both AL-returning callees are unresolved; this is not mapped to ELobbyState.'),
        dict(id='sequence_7_to_10',
             anchors=[(0x146426409, '80fb07'), (0x14642640c, '0f8545020000'),
                      (0x146426437, 'b30a'), (0x146426439, 'e924ffffff')],
             observation='The value-7 branch reaches BL=10 after intervening calls and loops to sequence processing.',
             unresolved='Names for these sequence values and their visible screens are unresolved.'),
    ]
    for check in checks:
        evidence = []
        for address, expected in check.pop('anchors'):
            row = instructions.get(address)
            if row is None or row['bytes'] != expected:
                raise ValueError('Reviewed native anchor changed: ' + hex(address))
            evidence.append(row)
        check.update(instructions=evidence, used_for_bot_input=False)
    return checks


def main():
    if capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    entry = json.loads((ROOT / 'ui-geometry/entry-reference.json').read_text(encoding='utf-8'))
    source = entry['native_entry']
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native source changed')
    image = Image(data)
    targets = {}
    for clue in source['diagnostic_strings']:
        encoded = clue['text'].encode('utf-16le') + b'\0\0'
        offset = clue['file_offset']
        if data[offset:offset + len(encoded)] != encoded:
            raise ValueError('Diagnostic evidence changed')
        targets[image.pe.address(offset)] = clue
    candidates = rip_candidates(image, targets)
    roots = {image.roots[row] for address, _ in candidates if (row := image.containing(address)) is not None}
    fragments = decode_ranges(image, roots)
    instructions = {row['address']: row for fragment in fragments for row in fragment['instructions']}
    xrefs = []
    for address, target in candidates:
        instruction = instructions.get(address)
        if instruction is None or instruction['mnemonic'] != 'lea' or target not in instruction['rip_references']:
            raise ValueError('Candidate xref is not a verified instruction')
        function = image.containing(address)
        xrefs.append(dict(instruction=instruction, diagnostic=targets[target],
                          root_begin_rva=image.roots[function][0]))
    unresolved = [clue['text'] for target, clue in targets.items()
                  if not any(x['diagnostic'] == clue for x in xrefs)]
    result = dict(source=source['source'], sha256=source['sha256'], image_base=image.pe.base,
        capstone_version=capstone.__version__, exception_ranges=len(image.ranges),
        xrefs=xrefs, fragments=fragments, diagnostics_without_verified_lea=unresolved,
        reviewed_checks=reviewed_checks(instructions),
        limitations=['LEA RIP-relative references only, not a complete whole-program xref index.',
                     'Root association uses Windows chained unwind records; native names are diagnostic clues only.',
                     'Decoded branches/calls do not prove high-level semantics, GUI visibility or Android parity.',
                     'Static read-only analysis; no game execution, memory read or patching.'])
    output = ROOT / 'code-clues/entry-code.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(roots=len(roots), fragments=len(fragments), xrefs=len(xrefs),
                         missing=unresolved, instructions=len(instructions))))


if __name__ == '__main__':
    main()
