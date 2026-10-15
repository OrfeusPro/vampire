"""Index entry layouts without treating resource names as observed screen states."""
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
POLICIES = {
    'WBP_TitleUI': 'container_only',
    'WBP_TitlePanelUI': 'needs_screen_binding_and_saved_server_identity',
    'WBP_CharacterSelectUI': 'needs_screen_binding_and_saved_character_identity',
    'WBP_ServerSelectPopup': 'needs_explicit_server_identity',
    'WBP_ServerSelectMyCharacterT': 'needs_explicit_character_identity_and_server_state',
    'WBP_PatchUI': 'wait_without_restart',
    'WBP_PatchPopup': 'needs_review_of_download_network_and_storage',
    'WBP_LoginPopup': 'manual_authentication',
    'WBP_SecurityLoginPopup': 'manual_authentication',
    'WBP_SecurityLoginCodePopup': 'manual_authentication',
}
ENTRY_CLUES = [
    'UTitleUI::_BeginGame()', '_BeginGame() failed cause of SignIn.',
    'UTitleUI::_BeginGameImpl()',
    'UTitleUI::_BeginGameImpl() - GetLastPlayedServerId( %d )',
    'UTitleUI::_BeginGameImpl() - serverId == InvalidInfoId ( %d )',
    'UTitleUI::_BeginPatch()', 'UTitleUI::_ChangeSequence()',
    'UTitleUI::OnSuccessNetmarbleSDKAuth()',
    'UTitleUI::ProcessNetmarbleSDK()',
]


def collect(catalog, directory):
    result = []
    for item in catalog['windows']:
        if item['name'] not in POLICIES:
            continue
        path = directory / item['file']
        data = json.loads(path.read_text(encoding='utf-8'))
        if data['name'] != item['name']:
            raise ValueError('Catalog root mismatch: ' + item['file'])
        # Keep complete controls: sibling sizing and switchers also affect hit zones.
        fields = ('name', 'resource_paths', 'root_export', 'source', 'entry',
                  'asset_sha256', 'body_sha256', 'controls', 'decoded_slots',
                  'container_native_schema')
        result.append(dict(catalog_file=item['file'],
            catalog_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            policy=POLICIES[item['name']], screen_binding_verified=False,
            absolute_click_geometry_verified=False,
            **{key: data[key] for key in fields if key in data}))
    missing = set(POLICIES) - {row['name'] for row in result}
    if missing:
        raise ValueError('Missing entry layouts: ' + ', '.join(sorted(missing)))
    return result


def title_link(layouts, panels):
    links = []
    for layout in layouts:
        if layout['name'] != 'WBP_TitleUI':
            continue
        matches = [row for row in panels['panels']
                   if row['provenance']['file'] == layout['catalog_file']
                   and row['provenance']['name'] == 'TitlePanelUI']
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous serialized title panel')
        row = matches[0]
        source, decoded = row['provenance'], row['decoded']
        if any(source[k] != layout[k] for k in ('entry', 'source', 'asset_sha256', 'body_sha256')):
            raise ValueError('Deferred panel source mismatch')
        controls = [c for c in layout['controls'] if c['export'] == source['export']]
        if (len(controls) != 1 or controls[0]['type'] != 'NkDeferredPanel'
                or controls[0]['sha256'] != source['sha256']):
            raise ValueError('Deferred panel control mismatch')
        expected = '/Game/RED/UI/Lobby/WBP_TitlePanelUI'
        if (decoded['status'] != 'explicit_asset_path' or decoded['package']['name'] != expected
                or decoded['asset']['name'] != 'WBP_TitlePanelUI' or decoded['subpath']):
            raise ValueError('Serialized title panel target changed')
        targets = [item['catalog_file'] for item in layouts
                   if item['name'] == 'WBP_TitlePanelUI' and expected in item['resource_paths']]
        if not targets or set(targets) != set(decoded['catalog_targets']):
            raise ValueError('Title panel target layouts changed')
        links.append(dict(provenance=source, decoded=decoded, target_catalog_files=targets))
    if not links:
        raise ValueError('Missing TitleUI layout')
    return dict(container='WBP_TitleUI', control='TitlePanelUI', control_type='NkDeferredPanel',
                target='WBP_TitlePanelUI', serialized_asset_binding_verified=True,
                dynamic_class_binding_verified=False, variants=links,
                native_schema=panels['native_schema'])


def native_entry_evidence(native_schema):
    path = ROOT / 'code-clues/native-enums.json'
    enums = json.loads(path.read_text(encoding='utf-8'))
    if any(enums[key] != native_schema[key] for key in ('source', 'sha256')):
        raise ValueError('Entry native sources disagree')
    data = Path(enums['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != enums['sha256']:
        raise ValueError('Entry native executable changed')
    states = enums['enums']['ELobbyState']
    for row in states:
        encoded = row['name'].encode('ascii') + b'\0'
        offset = row['name_offset']
        if data[offset:offset + len(encoded)] != encoded:
            raise ValueError('Lobby enum string evidence changed')
    clues = []
    for text in ENTRY_CLUES:
        needle = text.encode('utf-16le') + b'\0\0'
        offsets = [match.start() for match in re.finditer(re.escape(needle), data)]
        if len(offsets) != 1:
            raise ValueError('Entry native clue changed or ambiguous: ' + text)
        clues.append(dict(text=text, encoding='utf-16le', file_offset=offsets[0]))
    return dict(source=enums['source'], sha256=enums['sha256'],
        enum_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        lobby_states=states, diagnostic_strings=clues,
        limitation='Enums and diagnostic text only; order, branch conditions and calls are not reconstructed.')


def main():
    directory = ROOT / 'ui-catalog'
    index = directory / 'index.json'
    layouts = collect(json.loads(index.read_text(encoding='utf-8')), directory)
    panel_path = ROOT / 'ui-geometry/deferred-panels.json'
    link = title_link(layouts, json.loads(panel_path.read_text(encoding='utf-8')))
    result = dict(schemaVersion=1, catalog_sha256=hashlib.sha256(index.read_bytes()).hexdigest(),
        layouts=layouts, executable_transitions=[],
        deferred_report_sha256=hashlib.sha256(panel_path.read_bytes()).hexdigest(),
        title_panel_link=link,
        native_entry=native_entry_evidence(link['native_schema']),
        limitations=[
            'Cooked Windows resources; equality to Android assets is not established.',
            'Layout membership is proven, runtime order/visibility and native handlers are not.',
            'No login screen templates reviewed; launch_buttons remains empty.',
            'DPI curve, safe-zone insets and inherited defaults prevent absolute click coordinates.',
        ])
    target = ROOT / 'ui-geometry/entry-reference.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(layouts=len(layouts), unique_windows=len(POLICIES),
                         executable_transitions=0, output=str(target))))


if __name__ == '__main__':
    main()
