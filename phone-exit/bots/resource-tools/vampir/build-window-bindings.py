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


def attach_system_message_reference(reference, report, report_hash):
    """Attach a Windows path without changing the observed security-message policy."""
    if (report['native_class'] != '/Script/NkUMG.NkSystemMessageUI' or
            report['text_field'] != 0xa00 or report['runtime_actions_enabled'] is not False):
        raise ValueError('Unexpected system-message native scope')
    variants = report['variants']
    if (len(variants) != 4 or len({v['file'] for v in variants}) != 4 or
            sum(v['name'] == 'WBP_SystemMessageUI' for v in variants) != 2):
        raise ValueError('Incomplete system-message variants')
    for variant in variants:
        controls = {c['name']: c['type'] for c in variant['controls']}
        if variant['absolute_screen_geometry_verified'] is not False:
            raise ValueError('Unproven absolute message geometry')
        if variant['name'] == 'WBP_SystemMessageUI':
            if (variant['superclass']['path'] != report['native_class'] or
                    controls.get('TextMessage') != 'NkRichTextBlock' or
                    controls.get('CommonMessageNotifyLightUI') != 'WBP_CommonMessageNotifyLightUI_C'):
                raise ValueError('System-message control/class mismatch')
        elif variant['name'] != 'WBP_CommonMessageNotifyLightUI' or controls.get('ImageBackGround') != 'Image':
            raise ValueError('System-message background mismatch')
    reference['systemMessageReference'] = dict(
        scope='Windows_native_message_path_only', nativeClass=report['native_class'],
        textField=report['text_field'], nativeSource={k: report[k] for k in ('source', 'sha256')},
        reportSha256=report_hash, variants=variants, runtimeActionsEnabled=False,
        appliesToObservedKickout=False, absoluteScreenGeometryVerified=False)


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
    confirm_path = MODULE / 'inspect-confirm-reference.json'
    if confirm_path.exists():
        confirm = json.loads(confirm_path.read_text(encoding='utf-8'))
        template = MODULE / 'templates/connection_terminated_confirm.png'
        if (confirm['localization_key'] != MESSAGE_KEY or confirm['widget_binding_proven'] is not False
                or hashlib.sha256(template.read_bytes()).hexdigest() != confirm['template_sha256']):
            raise ValueError('Invalid observed confirm reference')
        result['messages'][MESSAGE_KEY].update(behavior=confirm['behavior'], observedConfirm=confirm)
    idle_path = MODULE / 'idle-confirm-reference.json'
    if idle_path.exists():
        idle = json.loads(idle_path.read_text(encoding='utf-8'))
        with path.open(encoding='utf-8-sig', newline='') as stream:
            idle_text = bind_text(list(csv.DictReader(stream)),
                'CHARACTER_IDLE_KICKOUT_POPUP_INFO', 'You have been disconnected due to inactivity.')
        if (idle['localization']['csv_record'] != idle_text['csv_record'] or
                idle['localization']['source']['sha256'] != meta['sha256'] or
                idle['widget_binding_proven'] is not False):
            raise ValueError('Invalid idle-message source binding')
        for variant in idle['variants']:
            if hashlib.sha256((MODULE / 'templates' / (variant['name'] + '.png')).read_bytes()).hexdigest() != variant['sha256']:
                raise ValueError('Idle template changed')
        result['messages']['CHARACTER_IDLE_KICKOUT_POPUP_INFO'] = dict(
            localization=dict(source=meta, **idle_text), observedConfirm=idle,
            behavior=idle['behavior'], widget_binding_proven=False,
            widget_candidates=candidates)
    system_path = ROOT / 'code-clues/system-message-link.json'
    system_bytes = system_path.read_bytes()
    system_report = json.loads(system_bytes)
    if hashlib.sha256(Path(system_report['source']).read_bytes()).hexdigest() != system_report['sha256']:
        raise ValueError('System-message native source changed')
    attach_system_message_reference(result, system_report, hashlib.sha256(system_bytes).hexdigest())
    (MODULE / 'ui-window-reference.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    config = json.loads((MODULE / 'vision.json').read_text(encoding='utf-8'))
    config.setdefault('manual_screen_sources', {})['connection_terminated_inspect'] = dict(
        localization_key=MESSAGE_KEY, reference='ui-window-reference.json', widget_binding_proven=False)
    (MODULE / 'vision.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(key=MESSAGE_KEY, csv_record=text['csv_record'], widget_candidates=len(candidates), widget_binding_proven=False)))


if __name__ == '__main__':
    main()
