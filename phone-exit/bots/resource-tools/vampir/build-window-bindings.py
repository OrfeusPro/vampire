"""Bind observed message text to localization, retaining unproven widget candidates."""
import csv
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'
MESSAGE_KEY = 'KICKOUT_FOR_INSPECT'
MESSAGE_TEXT = 'Connection terminated for safe gameplay.'


def bind_text(rows, key, expected):
    matches = [(index, row) for index, row in enumerate(rows, 2) if row.get('Key') == key]
    if len(matches) != 1 or matches[0][1].get('Value') != expected:
        raise ValueError('Localization key/text changed or ambiguous')
    index, row = matches[0]
    return dict(csv_record=index, row=row)


def main():
    meta = next(r for r in json.loads((ROOT / 'table-study/index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables'] if r['entry'] == 405)
    path = ROOT / 'table-study' / meta['file']
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Localization source changed')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        text = bind_text(list(csv.DictReader(stream)), MESSAGE_KEY, MESSAGE_TEXT)
    candidates = []
    catalog = ROOT / 'ui-catalog'
    names = {'WBP_MessageBoxConfirmPopup', 'WBP_MessageBoxPopup', 'WBP_SystemMessageBoxPopup'}
    for item in json.loads((catalog / 'index.json').read_text(encoding='utf-8'))['windows']:
        if item['name'] not in names:
            continue
        resource = json.loads((catalog / item['file']).read_text(encoding='utf-8'))
        controls = [c for c in resource['controls'] if c['name'] in ('ButtonOk', 'ButtonCancel', 'TextMessage', 'TextOk', 'SizeBox_0')]
        slot_ids = {link['slot_export'] for control in controls for link in control['parent_chain']}
        candidates.append(dict(file=item['file'], paths=resource['resource_paths'], source=resource['source'],
            entry=resource['entry'], asset_sha256=resource['asset_sha256'], body_sha256=resource['body_sha256'],
            container_native_schema=resource.get('container_native_schema'),
            controls=controls, slots=[s for s in resource['decoded_slots'] if s['provenance']['slot_export'] in slot_ids],
            binding_status='candidate_only_no_native_caller_link'))
    provenance = json.loads((ROOT / 'phone-tests/shop-901030/template-provenance.json').read_text(encoding='utf-8'))
    observed = next(t for t in provenance['templates'] if t['name'] == 'connection_terminated_inspect')
    alternatives = [t for t in provenance['templates'] if t['name'].startswith('connection_terminated_inspect_')]
    result = dict(schemaVersion=1, messages={MESSAGE_KEY: dict(localization=dict(source=meta, **text),
        template=observed, alternative_templates=alternatives, behavior='pause_without_dismissal_or_reconnect',
        widget_candidates=candidates, widget_binding_proven=False,
        limitation='Exact localized text confirmed; dynamic caller-to-widget binding and absolute geometry unresolved')})
    (MODULE / 'ui-window-reference.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    config = json.loads((MODULE / 'vision.json').read_text(encoding='utf-8'))
    config.setdefault('manual_screen_sources', {})['connection_terminated_inspect'] = dict(
        localization_key=MESSAGE_KEY, reference='ui-window-reference.json', widget_binding_proven=False)
    (MODULE / 'vision.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(key=MESSAGE_KEY, csv_record=text['csv_record'], widget_candidates=len(candidates), widget_binding_proven=False)))


if __name__ == '__main__':
    main()
