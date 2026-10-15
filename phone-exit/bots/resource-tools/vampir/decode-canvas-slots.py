"""Decode the observed cooked CanvasPanelSlot layout, with complete byte checks.

Schema inferred from serialized records; absolute layout/DPI remains unverified.
Unknown layouts fail explicitly and never generate click coordinates.
"""
import json
import os
import struct
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, fmt):
        size = struct.calcsize(fmt)
        if self.pos + size > len(self.data):
            raise ValueError('Truncated property')
        values = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return values[0] if len(values) == 1 else list(values)

    def header(self):
        fragments, index, count = [], 0, 0
        while True:
            word = self.read('<H')
            skip, zeroes, last, values = word & 127, bool(word & 128), bool(word & 256), word >> 9
            index += skip
            fragments.append((index, values, zeroes))
            index += values
            count += values if zeroes else 0
            if len(fragments) > 64:
                raise ValueError('Invalid unversioned header')
            if last:
                break
        mask = 0
        if count:
            size = 1 if count <= 8 else 2 if count <= 16 else ((count + 31) // 32) * 4
            if self.pos + size > len(self.data):
                raise ValueError('Truncated zero mask')
            mask = int.from_bytes(self.data[self.pos:self.pos + size], 'little')
            self.pos += size
        result, bit = [], 0
        for start, values, has_zero in fragments:
            for index in range(start, start + values):
                zero = bool(mask & (1 << bit)) if has_zero else False
                bit += int(has_zero)
                result.append((index, zero))
        return result

    def margin(self):
        out = dict(left=0, top=0, right=0, bottom=0)
        keys = list(out)
        for index, zero in self.header():
            if index >= 4:
                raise ValueError('Unknown margin schema')
            out[keys[index]] = 0 if zero else self.read('<f')
        return out

    def anchors(self):
        out = dict(minimum=[0, 0], maximum=[0, 0])
        keys = list(out)
        for index, zero in self.header():
            if index >= 2:
                raise ValueError('Unknown anchor schema')
            out[keys[index]] = [0, 0] if zero else self.read('<dd')
        return out

    def layout(self):
        out = dict(offsets=dict(left=0, top=0, right=0, bottom=0),
                   anchors=dict(minimum=[0, 0], maximum=[0, 0]), alignment=[0, 0])
        present = []
        for index, zero in self.header():
            if index >= 3:
                raise ValueError('Unknown layout schema')
            present.append(index)
            if zero:
                continue
            key = ['offsets', 'anchors', 'alignment'][index]
            out[key] = self.margin() if index == 0 else self.anchors() if index == 1 else self.read('<dd')
        out['serialized_fields'] = present
        return out

    def slot(self):
        result = {}
        for index, zero in self.header():
            if index not in range(5):
                raise ValueError('Unknown CanvasPanelSlot schema')
            key = ['layout', 'auto_size', 'z_order', 'parent_export', 'content_export'][index]
            if zero:
                result[key] = False if index == 1 else 0
            else:
                result[key] = self.layout() if index == 0 else self.read('<B') if index == 1 else self.read('<i')
        # UObject serialization suffix, observed as four zero bytes.
        if self.read('<I') != 0 or self.pos != len(self.data):
            raise ValueError('Unaccounted serialization suffix')
        return result


def main():
    folder = ROOT / 'ui-layout-study'
    index = json.loads((folder / 'index.json').read_text(encoding='utf-8'))
    slots, failures = [], []
    for package in index:
        if 'file' not in package:
            continue
        report = json.loads((folder / package['file']).read_text(encoding='utf-8'))
        exports = {e['index']: e for e in report['exports']}
        for export in exports.values():
            if export['type'] != 'CanvasPanelSlot':
                continue
            provenance = dict(file=package['file'], slot_export=export['index'], offset=export['offset'],
                              sha256=export['sha256'], source=report['source'], entry=report['entry'])
            try:
                decoded = Reader(bytes.fromhex(export['serialized_hex'])).slot()
                parent, child = decoded.get('parent_export', 0), decoded.get('content_export', 0)
                if parent not in exports or child not in exports or exports[parent]['type'] != 'CanvasPanel':
                    raise ValueError('Parent/content reference does not match CanvasPanel schema')
                decoded.update(parent=dict(index=parent, name=exports[parent]['name'], type=exports[parent]['type']),
                               content=dict(index=child, name=exports[child]['name'], type=exports[child]['type']))
                slots.append(dict(provenance=provenance, decoded=decoded))
            except Exception as error:
                failures.append(dict(provenance=provenance, error=str(error)))
    out = ROOT / 'ui-geometry'
    out.mkdir(exist_ok=True)
    (out / 'canvas-slots.json').write_text(json.dumps(dict(slots=slots, failures=failures,
        schema_status='inferred_from_cooked_data_and_reference_checks',
        absolute_screen_geometry_verified=False,
        limitations=['Omitted struct fields use inferred zero defaults; archetype overrides not resolved',
                     'Other panel slot classes, DPI, safe zones, scaling, animation and runtime visibility not resolved',
                     'Not used to generate bot taps']), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(decoded=len(slots), failures=len(failures), examples=failures[:3]), ensure_ascii=False))


if __name__ == '__main__':
    main()
