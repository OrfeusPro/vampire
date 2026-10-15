"""Join native UI-scale option to exact presets, defaults, localization and settings tabs."""
import csv
import hashlib
import json
import math
import os
import re
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
LEVELS = ('VerySmall', 'Small', 'Normal', 'Large', 'VeryLarge')
PROFILES = ('PC', 'IOS', 'AOS', 'IOSTablet', 'AOSTablet')


def presets(rows):
    grouped = {}
    for index, row in enumerate(rows, 2):
        match = re.fullmatch(r'DisplayUIScale(PC|IOS|AOS|IOSTablet|AOSTablet)\.(VerySmall|Small|Normal|Large|VeryLarge)', row.get('Key', ''))
        if not match:
            continue
        profile, level = match.groups()
        if row['ValueType'] != 'float':
            raise ValueError('Unexpected scale value type')
        value = float(row['Value'])
        if not math.isfinite(value) or not 0 < value <= 4:
            raise ValueError('Invalid scale preset')
        if level in grouped.setdefault(profile, {}):
            raise ValueError('Duplicate scale preset')
        grouped[profile][level] = dict(value=value, csv_record=index, row=row)
    if set(grouped) != set(PROFILES) or any(set(grouped[p]) != set(LEVELS) for p in grouped):
        raise ValueError('Incomplete scale preset set')
    return grouped


def one(rows, field, value):
    selected = [r for r in rows if str(r[field]) == str(value)]
    if len(selected) != 1:
        raise ValueError('Expected unique ' + field + '=' + str(value))
    return selected[0]


def main():
    index = json.loads((ROOT / 'table-study/index-pakchunk1-Windows.json').read_text(encoding='utf-8'))
    metadata = {r['entry']: r for r in index['tables']}
    sources = {}

    def load(entry):
        meta = metadata[entry]
        path = ROOT / 'table-study' / meta['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('Changed scale source: ' + str(entry))
        sources[str(entry)] = meta
        with path.open(encoding='utf-8-sig', newline='') as stream:
            return [dict(row, source=dict(entry=entry, csv_record=i)) for i, row in enumerate(csv.DictReader(stream), 2)]

    native = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(native['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != native['sha256']:
        raise ValueError('Changed native enum source')
    option_enum = one(native['enums']['EOptionType'], 'name', 'EOptionType::DisplayUIScale')
    constants = load(68)
    values = presets(constants)
    option = one(load(1429), 'OptionType', option_enum['value'])
    labels = one(load(488), 'OptionType', 'DisplayUIScale')
    label_list = labels['WidgetName'].split('<t>')
    if len(label_list) != len(LEVELS):
        raise ValueError('UI scale label count changed')
    group = one(load(1430), 'Id', option['OptionGroupInfoId'])
    subtab = one(load(1433), 'Id', group['OptionSubTabInfoId'])
    main_tab = one(load(1431), 'Id', subtab['OptionMainTabInfoId'])
    parent_enum = one(native['enums']['EOptionType'], 'value', option['Parent'])
    quality_overrides = [r for r in load(1432) if r['Type'] == str(option_enum['value'])]
    dependencies = json.loads((ROOT / 'code-clues/table-dependencies.json').read_text(encoding='utf-8'))
    if dependencies['sha256'] != native['sha256']:
        raise ValueError('Reference declarations are from a different client')
    declared_links = [r for r in dependencies['references'] if r['source']['workbook'].startswith('Option/')]
    catalog = json.loads((ROOT / 'ui-catalog/index.json').read_text(encoding='utf-8'))
    widget_candidates = [dict(row, binding_status='candidate_only_widget_type_handler_not_recovered')
        for row in catalog['windows'] if row['name'].startswith(('WBP_OptionSetting', 'WBP_OptionGroup')) or row['name'] == 'WBP_OptionUI']
    defaults = {platform: dict(raw_value=option[field],
        candidate_zero_based_label=label_list[int(option[field])],
        candidate_zero_based_preset=values[profile][LEVELS[int(option[field])]],
        mapping_status='Candidate from label order; native dropdown-index handler not recovered')
        for platform, field, profile in [('AOS', 'DefaultValueForAOS', 'AOS'),
                                         ('IOS', 'DefaultValueForIOS', 'IOS'), ('Win', 'DefaultValueForWin', 'PC')]}
    literals = []
    for text in ('GetViewportScale', 'UIScaleCurve', 'ApplicationScale', 'CustomScalingRuleClass', 'UIScaleRule'):
        for encoding in ('ascii', 'utf-16le'):
            for match in re.finditer(re.escape(text.encode(encoding)), data):
                literals.append(dict(text=text, encoding=encoding, offset=match.start(), interpretation='Static literal only, not active value'))
    report = dict(native_source=dict(source=native['source'], sha256=native['sha256']), sources=sources,
        option_enum=option_enum, presets=values, option=option, labels=labels, defaults=defaults, parent_enum=parent_enum,
        group=group, subtab=subtab, main_tab=main_tab, native_literals=literals,
        declared_table_links=declared_links, quality_override_rows=quality_overrides, widget_candidates=widget_candidates,
        native_dpi_rules=native['enums']['EUIScalingRule'], active_phone_scale=None,
        limitations=['Windows data may differ from Android patch', 'Defaults are not current saved preferences',
                     'Preset is not proven equal to viewport DPI or global scale of every window',
                     'Native index-to-label mapping and runtime rule/curve not recovered',
                     'No new scale or coordinates applied to bot input'])
    output = ROOT / 'ui-geometry/ui-scale-reference.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(profiles=len(values), presets=sum(map(len, values.values())),
        option_type=option_enum['value'], default_AOS=option['DefaultValueForAOS'], default_Win=option['DefaultValueForWin'])))


if __name__ == '__main__':
    main()
