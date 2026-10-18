"""Bounded references for the already validated 96/32-byte cooked package layout."""
import struct


def references(asset, parsed):
    names = parsed['names']
    exports = parsed['exports']
    size = struct.unpack_from('<i', asset, 32)[0]
    summary = 36 + size
    package_raw = asset[36:summary]
    if not 0 < size < 4096 or not package_raw.endswith(b'\0'):
        raise ValueError('Unsupported package name')
    package_name = package_raw[:-1].decode('utf-8')
    ec, eo, ic, io = struct.unpack_from('<iiii', asset, summary + 28)
    if ec != len(exports) or not 0 < ec <= 40000 or not 0 <= ic <= 10000:
        raise ValueError('Unsupported reference counts')
    if eo < 0 or io < 0 or eo + ec * 96 > len(asset) or io + ic * 32 > len(asset):
        raise ValueError('Reference table outside package')

    def fname(index, number):
        if not 0 <= index < len(names) or number < 0:
            raise ValueError('Invalid reference name')
        return names[index] + ('_' + str(number - 1) if number else '')

    rows = {}
    for i in range(ic):
        pos = io + i * 32
        outer, ni, number = struct.unpack_from('<iii', asset, pos + 16)
        rows[-i - 1] = dict(index=-i - 1, kind='import', name=fname(ni, number), outer=outer,
                            table_offset=pos, table_bytes=asset[pos:pos + 32].hex())
    for e in exports:
        pos = eo + (e['index'] - 1) * 96
        cls, super_index, template, outer, ni, number = struct.unpack_from('<iiiiii', asset, pos)
        name = fname(ni, number)
        if name != e['name'] or outer != e['outer']:
            raise ValueError('Export layout differs from validated package')
        rows[e['index']] = dict(index=e['index'], kind='export', name=name, outer=outer,
                                class_index=cls, super_index=super_index, template_index=template,
                                table_offset=pos, table_bytes=asset[pos:pos + 96].hex())
    for row in rows.values():
        for key in ['outer', 'class_index', 'super_index', 'template_index']:
            ref = row.get(key, 0)
            if ref != 0 and ref not in rows:
                raise ValueError('Reference outside package tables')

    def path(index, active):
        if index in active:
            raise ValueError('Cyclic reference outer chain')
        row = rows[index]
        if len(active) >= 128:
            raise ValueError('Reference outer chain too deep')
        prefix = path(row['outer'], active | {index}) if row['outer'] else (package_name if index > 0 else '')
        return prefix + ('.' if prefix else '') + row['name']

    for index, row in rows.items():
        row['path'] = path(index, set())
    return dict(package_name=package_name, package_name_offset=36, package_name_bytes=package_raw.hex(), references=rows)
