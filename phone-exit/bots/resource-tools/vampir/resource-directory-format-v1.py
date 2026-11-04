"""Ограниченные форматы PAK directory; без исполнения кода и записи ключа."""
import hashlib
from pathlib import PurePosixPath
import re
import struct


SHA = re.compile('[0-9a-f]{64}')
MAX_ENCODED = 32 * 1024 * 1024
MAX_PATH = 4096


def _invalid_key():
    # Neither key material nor instruction operands belong in diagnostics.
    raise ValueError('Invalid static directory key proof')


def key_from_proof(proof, raw, decoder):
    """Extract a candidate from exact source stores, matching all saved cases.

    This does not execute the callback or establish its binding in another EXE.
    The caller separately admits the immutable proof and verifies PAK indexes.
    """
    from capstone import CS_ARCH_X86, CS_MODE_64, CsError
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RBP
    if not isinstance(proof, dict) or not isinstance(raw, (bytes, bytearray)):
        _invalid_key()
    if (getattr(decoder, 'arch', None) != CS_ARCH_X86
            or getattr(decoder, 'mode', None) != CS_MODE_64
            or getattr(decoder, 'detail', False) is not True):
        _invalid_key()
    source = proof.get('key_candidate_source_sha256', proof.get('exe_sha256'))
    if (not isinstance(source, str) or not SHA.fullmatch(source)
            or hashlib.sha256(raw).hexdigest() != source):
        _invalid_key()
    callback = proof.get('key_callback')
    if not isinstance(callback, dict):
        _invalid_key()
    cases, fragments = callback.get('cases'), callback.get('fragments')
    if (not isinstance(cases, list) or len(cases) != 4
            or not isinstance(fragments, list) or not 1 <= len(fragments) <= 64):
        _invalid_key()
    expected_cases = {(0, 0), (1, 85), (15, 170), (16, 255)}
    actual_cases, output_hashes = set(), set()
    for case in cases:
        if (not isinstance(case, dict) or case.get('guards_unchanged') is not True
                or type(case.get('output_bytes')) is not int or case['output_bytes'] != 32
                or type(case.get('destination_delta')) is not int
                or type(case.get('poison')) is not int
                or not isinstance(case.get('output_sha256'), str)
                or not SHA.fullmatch(case['output_sha256'])):
            _invalid_key()
        actual_cases.add((case['destination_delta'], case['poison']))
        output_hashes.add(case['output_sha256'])
    if actual_cases != expected_cases or len(output_hashes) != 1:
        _invalid_key()
    stores, seen, count = {}, set(), 0
    for fragment in fragments:
        if not isinstance(fragment, dict):
            _invalid_key()
        start, begin, end = (fragment.get(key) for key in ('file_offset', 'begin_rva', 'end_rva'))
        instructions, digest = fragment.get('instructions'), fragment.get('sha256')
        if (any(type(value) is not int for value in (start, begin, end))
                or not 0 <= begin < end or not 0 <= start <= len(raw) - (end - begin)
                or not isinstance(digest, str) or not SHA.fullmatch(digest)
                or hashlib.sha256(raw[start:start + end - begin]).hexdigest() != digest
                or not isinstance(instructions, list) or not instructions):
            _invalid_key()
        cursor, address_end = start, None
        for row in instructions:
            count += 1
            if count > 4096 or not isinstance(row, dict):
                _invalid_key()
            offset, address, encoded = row.get('file_offset'), row.get('address'), row.get('bytes')
            if (type(offset) is not int or offset != cursor or type(address) is not int
                    or not 0 <= address < 2**64 or (address_end is not None and address != address_end)
                    or not isinstance(encoded, str) or not re.fullmatch('[0-9a-f]{2,30}', encoded)
                    or len(encoded) % 2):
                _invalid_key()
            data = bytes.fromhex(encoded)
            if (offset in seen or cursor + len(data) > start + end - begin
                    or raw[offset:offset + len(data)] != data):
                _invalid_key()
            seen.add(offset)
            try:
                decoded = list(decoder.disasm(data, address))
            except CsError:
                _invalid_key()
            if (len(decoded) != 1 or decoded[0].address != address
                    or decoded[0].size != len(data) or bytes(decoded[0].bytes) != data):
                _invalid_key()
            instruction = decoded[0]
            if instruction.mnemonic == 'mov' and len(instruction.operands) == 2:
                destination, value = instruction.operands
                if (destination.type == X86_OP_MEM and destination.size == 4
                        and destination.mem.base == X86_REG_RBP and destination.mem.index == 0
                        and destination.mem.segment == 0 and value.type == X86_OP_IMM):
                    displacement = destination.mem.disp
                    if displacement in stores:
                        _invalid_key()
                    stores[displacement] = struct.pack('<I', value.imm & 0xffffffff)
            cursor += len(data)
            address_end = address + len(data)
        if cursor != start + end - begin:
            _invalid_key()
    if len(stores) != 8:
        _invalid_key()
    ordered = sorted(stores)
    if ordered != list(range(ordered[0], ordered[0] + 32, 4)):
        _invalid_key()
    candidate = b''.join(stores[offset] for offset in ordered)
    if hashlib.sha256(candidate).hexdigest() not in output_hashes:
        _invalid_key()
    return candidate


def entry_prefix(encoded, offset):
    """Read known scalar fields only; block arrays and payloads remain unparsed."""
    if (not isinstance(encoded, (bytes, bytearray)) or not 0 < len(encoded) <= MAX_ENCODED
            or type(offset) is not int or not 0 <= offset <= len(encoded) - 4):
        raise ValueError('Invalid encoded directory entry prefix')
    cursor = offset
    def number(code):
        nonlocal cursor
        size = struct.calcsize(code)
        if cursor + size > len(encoded):
            raise ValueError('Truncated encoded directory entry prefix')
        value = struct.unpack_from(code, encoded, cursor)[0]
        cursor += size
        return value
    bits = number('<I')
    method, blocks = (bits >> 23) & 63, (bits >> 6) & 65535
    if method not in (0, 1) or (method == 0 and blocks != 0) or (method == 1 and blocks == 0):
        raise ValueError('Unsupported encoded directory entry prefix')
    position = number('<I' if bits & (1 << 31) else '<Q')
    usize = number('<I' if bits & (1 << 30) else '<Q')
    size = number('<I' if bits & (1 << 29) else '<Q') if method else usize
    if method and (usize == 0 or size == 0):
        raise ValueError('Empty encoded directory entry prefix')
    return dict(offset=position, bytes=size, uncompressed=usize, method=method,
        encrypted=bool(bits & (1 << 22)), blocks=blocks)


def canonical_path(mount, path):
    """Return a logical archive path; never resolve or write a host file path."""
    if any(not isinstance(value, str) or not value or len(value) > MAX_PATH
            or any(char in value for char in ('\\', '\0', ':'))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or value.startswith('/') for value in (mount, path)):
        raise ValueError('Invalid logical directory path')
    if mount.startswith('../../../'):
        mount = mount[len('../../../'):]
    mount = mount[:-1] if mount.endswith('/') else mount
    if any(part in ('.', '..', '') for part in path.split('/')):
        raise ValueError('Invalid relative directory path')
    if mount and any(part in ('.', '..', '') for part in mount.split('/')):
        raise ValueError('Invalid directory mount')
    result = str(PurePosixPath(mount)/PurePosixPath(path))
    if len(result) > MAX_PATH:
        raise ValueError('Logical directory path exceeds budget')
    return result
