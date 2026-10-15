"""Join extracted quest/tutorial rows with coordinates, localization and UI keys.

No phone actions. Keeps raw values and provenance; does not infer current state.
"""
import csv
import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def main():
    tables = ROOT / 'table-study'
    index = json.loads((tables / 'index-pakchunk1-Windows.json').read_text(encoding='utf-8'))
    metadata = {r['entry']: r for r in index['tables']}
    sources = {}
    native = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    with Path(native['source']).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != native['sha256']:
            raise ValueError('Native executable changed; rebuild enum evidence')
    unknown_types = []

    def native_name(enum, value, provenance):
        match = next((r for r in native['enums'][enum] if str(r['value']) == value), None)
        if not match:
            unknown_types.append(dict(enum=enum, value=value, source=provenance))
        return match['name'] if match else None

    def load(name, entry, required):
        meta = metadata[entry]
        data = (tables / meta['file']).read_bytes()
        if hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('Changed CSV: ' + meta['file'])
        if not set(required) <= set(meta['header']):
            raise ValueError('Unexpected schema: ' + name)
        sources[name] = meta
        with (tables / meta['file']).open(encoding='utf-8-sig', newline='') as stream:
            rows = list(csv.DictReader(stream))
        if len(rows) != meta['rows'] or any(None in row for row in rows):
            raise ValueError('CSV row structure mismatch: ' + name)
        return [dict(row, provenance=dict(table=name, entry=entry, csv_record=i + 2)) for i, row in enumerate(rows)]

    quests = load('Quest', 1448, ['Id', 'PreQuestId', 'SequenceId'])
    tasks = load('QuestTask', 1454, ['Id', 'QuestInfoId', 'Param', 'QuestActionPosX'])
    actions = load('QuestTaskAction', 1455, ['Id', 'TaskId', 'ConditionParam', 'ActionParam'])
    tutorials = load('Tutorial', 1551, ['Id', 'ActivateType'])
    steps = load('TutorialStep', 1555, ['Id', 'TutorialId', 'Step', 'TaskParam'])
    controls = load('TutorialUI', 1556, ['Key', 'WBPName', 'WidgetName', 'ControlName'])
    spots = load('WorldSpot', 1573, ['Id', 'WorldInfoId', 'PosX', 'PosY', 'PosZ'])
    names = load('Quest_Name_en', 498, ['Id', 'Name', 'DescObjective'])
    tasknames = load('QuestTask_Name_en', 502, ['Id', 'TaskName'])
    dialogs = load('TutorialStep_Name_en', 543, ['Id', 'DialogText'])
    by_quest, by_task, by_tutorial = defaultdict(list), defaultdict(list), defaultdict(list)
    control_map, spot_map = {r['Key']: r for r in controls}, {r['Id']: r for r in spots}
    name_map, taskname_map = {r['Id']: r for r in names}, {r['Id']: r for r in tasknames}
    dialog_map = {r['Id']: r for r in dialogs}
    tutorial_map = {r['Id']: r for r in tutorials}
    parse_errors = []

    def parse_param(row, field):
        text = row[field].strip()
        if text.startswith(('{', '[')):
            try:
                row[field + '_decoded'] = json.loads(text)
            except ValueError as error:
                parse_errors.append(dict(provenance=row['provenance'], field=field, error=str(error)))

    for action in actions:
        action['condition_type_name'] = native_name('EActionConditionType', action['ConditionType'], action['provenance'])
        action['action_type_name'] = native_name('EActionType', action['ActionType'], action['provenance'])
        for field in ('ConditionParam', 'ActionParam'):
            parse_param(action, field)
        by_task[action['TaskId']].append(action)
    for step in steps:
        step['ui'] = control_map.get(step['TaskParam'])
        step['dialog_en'] = dialog_map.get(step['Id'])
        by_tutorial[step['TutorialId']].append(step)
    for row in tutorials:
        row['steps'] = sorted(by_tutorial[row['Id']], key=lambda s: int(s['Step']))
    for task in tasks:
        task['type_name'] = native_name('EQuestTaskType', task['Type'], task['provenance'])
        parse_param(task, 'Param')
        task['name_en'] = taskname_map.get(task['Id'])
        task['world_spot'] = spot_map.get(task['TargetSpotInfoId'])
        task['actions'] = by_task[task['Id']]
        # Exact explicit field; other numeric task types are left uninterpreted.
        param = task.get('Param_decoded')
        if isinstance(param, dict) and 'tutorialInfoId' in param:
            task['tutorial'] = tutorial_map.get(str(param['tutorialInfoId']))
        by_quest[task['QuestInfoId']].append(task)
    quest_ids = {r['Id'] for r in quests}
    unresolved = []
    for quest in quests:
        quest['type_name'] = native_name('EQuestType', quest['Type'], quest['provenance'])
        quest['name_en'] = name_map.get(quest['Id'])
        quest['tasks'] = by_quest[quest['Id']]  # Preserve file order, not assumed ID order.
        quest['previous_id_tokens'] = [v for v in re.findall(r'\d+', quest['PreQuestId']) if v != '0']
        for previous in quest['previous_id_tokens']:
            if previous not in quest_ids:
                unresolved.append(dict(quest=quest['Id'], previous=previous))

    widgets = json.loads((ROOT / 'ui-layout-study/index.json').read_text(encoding='utf-8'))
    for control in controls:
        candidates = [w for w in widgets if any(p.rsplit('/', 1)[-1] == control['WBPName'] for p in w['paths']) and 'file' in w]
        control['wbp_assets'] = [w['file'] for w in candidates]
        control['control_exports_in_root'] = []
        for candidate in candidates:
            widget = json.loads((ROOT / 'ui-layout-study' / candidate['file']).read_text(encoding='utf-8'))
            control['control_exports_in_root'] += [dict(file=candidate['file'], index=e['index'], name=e['name'], type=e['type'])
                                                   for e in widget['exports'] if control['ControlName'] and e['name'] == control['ControlName']]

    dest = ROOT / 'quest-graph'
    dest.mkdir(exist_ok=True)
    summary = dict(quests=len(quests), tasks=len(tasks), actions=len(actions), tutorials=len(tutorials),
                   tutorial_steps=len(steps), ui_keys=len(controls), world_spots=len(spots),
                   steps_with_ui=sum(s['ui'] is not None for s in steps),
                   steps_with_dialog=sum(s['dialog_en'] is not None for s in steps),
                   ui_keys_with_wbp=sum(bool(c['wbp_assets']) for c in controls),
                   ui_keys_with_root_control=sum(bool(c['control_exports_in_root']) for c in controls))
    report = dict(summary=summary, sources=sources, quests=quests, tutorials=tutorials, controls=controls,
                  native_enum_source=dict(source=native['source'], sha256=native['sha256']), unknown_native_types=unknown_types,
                  json_parse_errors=parse_errors, unresolved_previous_ids=unresolved,
                  limitations=['PC data version not verified against Android', 'Current character quest/task not read',
                               'CSV record is a logical record including header, not a physical line',
                               'Task file order retained; runtime branches and completion conditions not simulated',
                               'Missing root export may belong to a child widget; geometry not decoded'])
    (dest / 'index.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    examples = [q for q in quests if q['Id'] in ('110110', '110130', '110150')]
    (dest / 'early-quests.json').write_text(json.dumps(examples, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(summary=summary, param_errors=len(parse_errors), unresolved_previous=len(unresolved))))


if __name__ == '__main__':
    main()
