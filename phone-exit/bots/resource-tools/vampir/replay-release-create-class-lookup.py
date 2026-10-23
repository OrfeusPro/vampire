"""Whole creation class lookup and sparse iterator on explicit table fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run(class_rows=None):
    spec = importlib.util.spec_from_file_location('create_lookup_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    h = archive.make_harness(extra_addresses=(0x145896a10, 0x14142e7d0))
    uc = h.uc
    owner, storage, bits = h.scratch + 0x10000, h.scratch + 0x11000, h.scratch + 0x1f000
    profiles = [(0, (), None), (1, (0,), None), (5, (0, 1, 2, 3, 4), None),
        (5, (0, 2, 4), None), (35, (0, 3, 31, 32, 34), None)]
    if class_rows is not None:
        if not 1 <= len(class_rows) <= 35:
            raise ValueError('Creation class data fixture count bound')
        profiles.append((len(class_rows), tuple(range(len(class_rows))), class_rows))
    cases = []
    for count, occupied, provided in profiles:
        def row_values(index):
            return (provided[index]['id'], provided[index]['type']) if provided is not None else (0x80000000 + index, index % 5 + 1)
        uc.mem_write(owner, bytes(0x80))
        uc.mem_write(storage, b'\xa5' * (35 * 0x1c8))
        words = [0] * max(1, (count + 31) // 32)
        for index in occupied: words[index // 32] |= 1 << (index % 32)
        uc.mem_write(owner + 0x18, struct.pack('<Q', storage))
        uc.mem_write(owner + 0x40, struct.pack('<I', count))
        if count > 32:
            uc.mem_write(bits, struct.pack('<' + 'I' * len(words), *words))
            uc.mem_write(owner + 0x38, struct.pack('<Q', bits))
        else:
            uc.mem_write(owner + 0x28, struct.pack('<I', words[0]))
        for index in occupied:
            row = storage + index * 0x1c8 + 8
            identifier, kind = row_values(index)
            uc.mem_write(row + 8, struct.pack('<I', identifier))
            uc.mem_write(row + 0x28, bytes((kind,)))
        before = bytes(uc.mem_read(storage, 35 * 0x1c8))
        for selected_type in (0, 1, 2, 3, 4, 5, 99, 100, 255):
            expected = next((index for index in occupied if row_values(index)[1] == selected_type), None)
            pointer = h.call(0x145896a10, owner, selected_type, budget=50000)
            target = storage + expected * 0x1c8 + 8 if expected is not None else 0
            if pointer != target:
                raise ValueError('Creation class lookup differs from occupied sparse rows')
            if bytes(uc.mem_read(storage, 35 * 0x1c8)) != before:
                raise ValueError('Creation class lookup changed table rows')
            identifier = int.from_bytes(uc.mem_read(pointer + 8, 4), 'little') if pointer else None
            if identifier != (row_values(expected)[0] if expected is not None else None):
                raise ValueError('Creation class row ID source differs')
            cases.append(dict(slots=count, occupied=list(occupied), selected_type=selected_type,
                row_index=expected, row_id=identifier, provided_data=provided is not None))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases,
        limits=['Whole lookup 0x145896a10 and sparse bit iterator 0x14142e7d0 execute.',
            'Table pointer, sparse storage, occupation bits, row types and IDs are synthetic fixtures.',
            'Lookup returns first occupied matching row; table identity and installed live row values are not proven.',
            'UI setter is separate static evidence; no whole UI, producer, JSON, packet send or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-create-class-lookup', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
