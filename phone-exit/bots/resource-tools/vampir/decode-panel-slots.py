"""Decode observed box/overlay/switcher slots and preserve source references.

Local layout only; no absolute screen position is inferred or used for input.
"""
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
spec = importlib.util.spec_from_file_location('canvas_reader', Path(__file__).with_name('decode-canvas-slots.py'))
canvas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canvas)


class Reader(canvas.Reader):
    def child_size(self):
        result = dict(value=1.0, rule=0, serialized_fields=[])
        for index, zero in self.header():
            if index not in (0, 1):
                raise ValueError('Unknown SlateChildSize schema')
            key = ['value', 'rule'][index]
            result['serialized_fields'].append(index)
            result[key] = 0 if zero else self.read('<f') if index == 0 else self.read('<B')
        return result

    def panel_slot(self, kind):
        if kind in ('HorizontalBoxSlot', 'VerticalBoxSlot'):
            fields = ['size', 'padding', 'horizontal_alignment', 'vertical_alignment', 'parent_export', 'content_export']
        elif kind in ('OverlaySlot', 'WidgetSwitcherSlot', 'SizeBoxSlot', 'ButtonSlot', 'BorderSlot'):
            fields = ['padding', 'horizontal_alignment', 'vertical_alignment', 'parent_export', 'content_export']
        elif kind == 'ScaleBoxSlot':
            fields = ['horizontal_alignment', 'vertical_alignment', 'parent_export', 'content_export']
        elif kind == 'SafeZoneSlot':
            fields = [None, None, None, None, None, 'parent_export', 'content_export']
        else:
            raise ValueError('Unsupported slot class')
        result = dict(serialized_fields=[])
        for index, zero in self.header():
            if index >= len(fields):
                raise ValueError('Unknown slot property')
            key = fields[index]
            if key is None:
                raise ValueError('SafeZone explicit layout properties not decoded')
            result['serialized_fields'].append(key)
            if zero:
                result[key] = dict(left=0, top=0, right=0, bottom=0) if key == 'padding' else 0
            elif key == 'size':
                result[key] = self.child_size()
            elif key == 'padding':
                result[key] = self.margin()
            else:
                result[key] = self.read('<i') if key.endswith('_export') else self.read('<B')
            if key.endswith('_alignment') and result[key] not in (0, 1, 2, 3):
                raise ValueError('Alignment outside observed enum range')
        if self.read('<I') != 0 or self.pos != len(self.data):
            raise ValueError('Unaccounted serialization suffix')
        return result


def main():
    folder = ROOT / 'ui-layout-study'
    slots, failures = [], []
    counts = {}
    for package in json.loads((folder / 'index.json').read_text(encoding='utf-8')):
        if 'file' not in package:
            continue
        report = json.loads((folder / package['file']).read_text(encoding='utf-8'))
        exports = {e['index']: e for e in report['exports']}
        for export in exports.values():
            kind = export['type']
            if kind not in ('HorizontalBoxSlot', 'VerticalBoxSlot', 'OverlaySlot', 'WidgetSwitcherSlot',
                            'SizeBoxSlot', 'ButtonSlot', 'BorderSlot', 'ScaleBoxSlot', 'SafeZoneSlot'):
                continue
            provenance = dict(file=package['file'], slot_export=export['index'], slot_type=kind, offset=export['offset'],
                              sha256=export['sha256'], source=report['source'], entry=report['entry'])
            row = None
            try:
                row = Reader(bytes.fromhex(export['serialized_hex'])).panel_slot(kind)
                parent, child = row.get('parent_export'), row.get('content_export')
                if parent not in exports or child not in exports or exports[parent]['type'] != kind[:-4]:
                    raise ValueError('Parent/content type mismatch')
                row.update(parent=dict(index=parent, name=exports[parent]['name'], type=exports[parent]['type']),
                           content=dict(index=child, name=exports[child]['name'], type=exports[child]['type']))
                slots.append(dict(provenance=provenance, decoded=row))
                counts[kind] = counts.get(kind, 0) + 1
            except Exception as error:
                failures.append(dict(provenance=provenance, error=str(error), decoded_candidate=row))
    dest = ROOT / 'ui-geometry/panel-slots.json'
    dest.write_text(json.dumps(dict(slots=slots, failures=failures,
        schema_status='inferred_from_cooked_data_and_reference_checks', absolute_screen_geometry_verified=False,
        limitations=['Property omissions and archetype defaults not resolved', 'Sibling order, desired sizes and DPI not fully resolved',
                     'Switcher active child and runtime visibility unknown', 'Not used for bot input']), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(decoded=len(slots), by_type=counts, failures=len(failures), examples=failures[:2]), ensure_ascii=False))


if __name__ == '__main__':
    main()
