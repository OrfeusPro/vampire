"""Compile the entire extracted chain as phone-local reference data.

Game-side actions are retained for interpretation, never replayed as commands.
"""
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'


def attach_reference_data(catalog, rewards, locks, shops):
    """Attach raw conditions and receipts; never evaluate unknown lock semantics."""
    if rewards['missingRewardGroups'] or rewards['unresolvedRequiredQuests'] or locks['missingLocks'] or locks['missingConditionGroups'] or shops['issues']:
        raise ValueError('Unresolved source references')
    by_quest = {}
    for row in rewards['quests']:
        qid = row['questId']
        if qid in by_quest:
            raise ValueError('Duplicate reward quest')
        by_quest[qid] = row
    if set(by_quest) != set(catalog['quests']):
        raise ValueError('Reward/quest catalogs differ')
    for qid, row in by_quest.items():
        quest = catalog['quests'][qid]
        if any(row['source'][key] != quest['source'][key] for key in ('entry', 'csv_record')) or row['requiredLevel'] != quest['requiredLevel']:
            raise ValueError('Quest requirement source mismatch')
        quest.update(contentsLock=row['contentsLockId'], rewardGroups=row['rewardGroups'],
                     requiredCompletedQuests=row['requiredCompletedQuests'], retryable=row['retryable'],
                     serverServiceGroup=row['serverServiceGroup'])
        if row['contentsLockId'] not in ('', '0') and row['contentsLockId'] not in locks['locks']:
            raise ValueError('Missing quest contents lock')
        if any(gid not in rewards['rewardGroups'] for gid in row['rewardGroups']):
            raise ValueError('Missing reward group')
    shop_tasks = {}
    for shop in shops['tasks']:
        tid = shop['task']['Id']
        if tid in shop_tasks:
            raise ValueError('Duplicate shop task')
        task = catalog['tasks'].get(tid)
        if not task or task['typeName'] != shop['typeName'] or task['param'] != shop['param'] or task['quest'] != shop['task']['QuestInfoId']:
            raise ValueError('Shop task source mismatch')
        shop_tasks[tid] = shop
    catalog.update(referenceRevision=2, rewardGroups=rewards['rewardGroups'], contentsLocks=locks['locks'], shopTasks=shop_tasks,
        unresolvedLockQuestCandidates=locks['unmatchedType1QuestCandidates'],
        sourceInterpretations=dict(contentsLocks=locks['interpretations'], lockEvaluator='not_implemented',
                                  shopTabLockKeywords=shops['unresolvedTabLockKeywords']))


def attach_condition_types(catalog, report):
    """Attach proven names only; do not turn raw conditions into a predicate."""
    expected = catalog['nativeEnumSource']
    if any(report[key] != expected[key] for key in ('source', 'sha256')):
        raise ValueError('Condition native source mismatch')
    meta = report['condition_source']
    table = catalog['sources'].get('locks:70')
    if meta['entry'] != 70 or not table or any(meta[key] != table[key] for key in ('entry', 'file', 'offset', 'sha256')):
        raise ValueError('Condition CSV source mismatch')
    symbols = {}
    for row in report['types']:
        key = str(row['value'])
        if key in symbols or row['name'] in symbols.values():
            raise ValueError('Duplicate condition native type')
        symbols[key] = row['name']
    if set(symbols) != {str(value) for value in range(11)}:
        raise ValueError('Incomplete condition native types')
    rows = {}
    for item in report['conditions']:
        row = item['row']
        if row['Id'] in rows or item['type_name'] != symbols.get(row['ConditionType']) or item['evaluation'] != 'not_evaluated':
            raise ValueError('Invalid condition source row/type')
        rows[row['Id']] = item
    for lock in catalog['contentsLocks'].values():
        if lock['evaluation'] != 'not_evaluated' or lock['combination'] != 'unknown_do_not_assume_AND_OR':
            raise ValueError('Unexpected condition evaluation')
        for condition in lock['conditions']:
            item = rows.get(condition['Id'])
            raw = {key: value for key, value in condition.items() if key != 'source'}
            if not item or item['row'] != raw or condition['source'] != dict(entry=70, csv_record=item['csv_record']):
                raise ValueError('Condition record mismatch')
    # Mutate only after every source join has passed.
    for lock in catalog['contentsLocks'].values():
        for condition in lock['conditions']:
            condition['typeName'] = symbols[condition['ConditionType']]
    catalog.update(referenceRevision=3, contentsLockConditionTypes=symbols,
                   conditionTypeNativeSource={key: report[key] for key in ('source', 'sha256')})
    catalog['sourceInterpretations']['conditionTypeNames'] = 'native_initializer_confirmed_names_only'


def main():
    graph = json.loads((ROOT / 'quest-graph/index.json').read_text(encoding='utf-8'))
    rewards = json.loads((ROOT / 'quest-graph/rewards.json').read_text(encoding='utf-8'))
    locks = json.loads((ROOT / 'quest-graph/contents-locks.json').read_text(encoding='utf-8'))
    shops = json.loads((ROOT / 'quest-graph/shop-tasks.json').read_text(encoding='utf-8'))
    condition_types = json.loads((ROOT / 'quest-graph/condition-types.json').read_text(encoding='utf-8'))
    native_source = graph['native_enum_source']
    enum_file = ROOT / 'code-clues/native-enums.json'
    native_enums = json.loads(enum_file.read_text(encoding='utf-8'))
    if (rewards['nativeEnumSource'] != native_source or shops['nativeEnumSource'] != native_source or graph['unknown_native_types']):
        raise ValueError('Native type source mismatch')
    if hashlib.sha256(Path(native_source['source']).read_bytes()).hexdigest() != native_source['sha256']:
        raise ValueError('Native executable changed')
    if native_enums['sha256'] != native_source['sha256']:
        raise ValueError('Native enum report is from another executable')
    native_symbols = {name: {str(row['value']): row['name'] for row in native_enums['enums'][name]}
        for name in ('EQuestType', 'EQuestTaskType', 'EActionType', 'EActionConditionType',
                     'ERewardType', 'ERewardGroup', 'ECostType', 'EPurchaseCondition')}
    sources = {}
    all_sources = list(graph['sources'].items())
    for prefix, report in [('rewards', rewards), ('locks', locks), ('shops', shops)]:
        all_sources += [(prefix + ':' + name, meta) for name, meta in report['sources'].items()]
    source_entries = {}
    for name, meta in all_sources:
        if hashlib.sha256((ROOT / 'table-study' / meta['file']).read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('Changed source: rebuild graph')
        sources[name] = {k: meta[k] for k in ('file', 'entry', 'offset', 'sha256')}
        if meta['entry'] in source_entries and source_entries[meta['entry']] != sources[name]:
            raise ValueError('Mixed source table versions')
        source_entries[meta['entry']] = sources[name]
    quests, tasks, tutorials, steps, actions, spots = {}, {}, {}, {}, {}, {}
    tutorial_tasks = defaultdict(list)
    for quest in graph['quests']:
        qid = quest['Id']
        quests[qid] = dict(previous=quest['previous_id_tokens'], previousRaw=quest['PreQuestId'], requireComplete=quest['RequireCompleteQuestInfoId'],
                           type=quest['Type'], typeName=quest['type_name'], initParam=quest['QuestInitParam'],
                           instanceFlags={k: quest[k] for k in ('BeforeStartInstance', 'StartRunInInstance', 'HideInstanceExitButton', 'FinishRunInInstance')},
                           name=(quest.get('name_en') or {}).get('Name', ''),
                           objective=(quest.get('name_en') or {}).get('DescObjective', ''),
                           sequence=quest['SequenceId'], recommendLevel=quest['RecommendLevel'],
                           requiredLevel=quest['RequireCharacterLv'],
                           tasksInFileOrder=[t['Id'] for t in quest['tasks']], source=quest['provenance'])
        for task in quest['tasks']:
            tid = task['Id']
            tutorial = task.get('tutorial')
            tasks[tid] = dict(quest=qid, type=task['Type'], typeName=task['type_name'], rawParam=task['Param'], param=task.get('Param_decoded'),
                             flags={k: task[k] for k in ('RunInInstance', 'RemainInstanceWorldEndTask', 'ShowInstanceEffect', 'MapIconGroupId', 'TaskProgressType', 'ServerServiceGroupId')},
                             name=(task.get('name_en') or {}).get('TaskName', ''),
                             tutorial=tutorial['Id'] if tutorial else None, worldSpot=task['TargetSpotInfoId'],
                             area=task['AreaInfoId'], auto=task['AutoQuest'],
                             position=[task[k] for k in ('QuestActionPosX', 'QuestActionPosY', 'QuestActionPosZ')],
                             radius=task['QuestActionRadius'], actions=[a['Id'] for a in task['actions']], source=task['provenance'])
            if task.get('world_spot'):
                row = task['world_spot']
                spots[row['Id']] = dict(world=row['WorldInfoId'], position=[row[k] for k in ('PosX', 'PosY', 'PosZ')],
                                        requiredTask=row['WorldMoveLimitIfNotCompletedQuestTaskInfoId'], source=row['provenance'])
            if tutorial:
                tutorial_tasks[tutorial['Id']].append(tid)
            for action in task['actions']:
                actions[action['Id']] = {k: action[k] for k in ('TaskId', 'ConditionType', 'ConditionParam', 'ActionType', 'ActionParam', 'provenance')}
                actions[action['Id']].update(conditionTypeName=action['condition_type_name'], actionTypeName=action['action_type_name'])
    for tutorial in graph['tutorials']:
        ordered = tutorial['steps']
        tutorials[tutorial['Id']] = dict(steps=[s['Id'] for s in ordered], taskCandidates=tutorial_tasks[tutorial['Id']],
                                         activateType=tutorial['ActivateType'], activateParam=tutorial['ActivateParam'])
        for i, step in enumerate(ordered):
            steps[step['Id']] = dict(tutorial=tutorial['Id'], ordinal=int(step['Step']), type=step['TaskType'],
                                     param=step['TaskParam'], dialog=(step.get('dialog_en') or {}).get('DialogText', ''),
                                     uiKey=step['ui']['Key'] if step['ui'] else None,
                                     nextInTable=ordered[i + 1]['Id'] if i + 1 < len(ordered) else None,
                                     flags={k: step[k] for k in ('ServerProcessRequest', 'SkipButtonMove', 'SkipButtonHide', 'ArrowHide', 'CloseAllPopUp')},
                                     source=step['provenance'])
    controls = {c['Key']: {k: c[k] for k in ('WBPName', 'WidgetName', 'ControlName', 'ControlIndex', 'TargetId', 'BlockType', 'DisableDim')} for c in graph['controls']}
    for tid, task in tasks.items():
        if task['quest'] not in quests:
            raise ValueError('Unresolved quest: ' + tid)
    for sid, step in steps.items():
        if step['tutorial'] not in tutorials or step['uiKey'] and step['uiKey'] not in controls:
            raise ValueError('Unresolved tutorial/UI: ' + sid)
    catalog = dict(schemaVersion=1, nativeEnumSource=native_source, sources=sources, quests=quests, tasks=tasks, actions=actions,
                   tutorials=tutorials, steps=steps, controls=controls, referencedWorldSpots=spots,
                   limitations=['PC source version not proven equal to Android',
                                'File order is retained; runtime branches are not simulated',
                                'Game action rows are reference only, never executable by this bot',
                                'Only registered fresh visual matches confirm a step; no blind replay'])
    attach_reference_data(catalog, rewards, locks, shops)
    attach_condition_types(catalog, condition_types)
    catalog.update(nativeValueSymbols=native_symbols, nativeEnumReportHash=hashlib.sha256(enum_file.read_bytes()).hexdigest())
    for quest in quests.values():
        if quest['typeName'] != native_symbols['EQuestType'].get(quest['type']):
            raise ValueError('Quest numeric/native type mismatch')
    for task in tasks.values():
        if task['typeName'] != native_symbols['EQuestTaskType'].get(task['type']):
            raise ValueError('Task numeric/native type mismatch')
    for action in actions.values():
        if action['actionTypeName'] != native_symbols['EActionType'].get(action['ActionType']) or action['conditionTypeName'] != native_symbols['EActionConditionType'].get(action['ConditionType']):
            raise ValueError('Action numeric/native type mismatch')
    for group in catalog['rewardGroups'].values():
        if any(row['typeName'] != native_symbols['ERewardType'].get(row['Type']) or row['groupName'] != native_symbols['ERewardGroup'].get(row['RewardGroup']) for row in group):
            raise ValueError('Reward numeric/native type mismatch')
    catalog['sourceReports'] = {file: hashlib.sha256((ROOT / 'quest-graph' / file).read_bytes()).hexdigest()
                              for file in ('index.json', 'rewards.json', 'contents-locks.json', 'shop-tasks.json', 'condition-types.json')}
    path = MODULE / 'quest-runtime.json'
    path.write_text(json.dumps(catalog, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    config_path = MODULE / 'vision.json'
    config = json.loads(config_path.read_text(encoding='utf-8'))
    config.update(chain_catalog='quest-runtime.json', interaction=dict(delay_jitter_sec=[0.15, 0.65], tap_jitter_px=3, retry_wait_sec=8))
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(bytes=path.stat().st_size, quests=len(quests), tasks=len(tasks), actions=len(actions), steps=len(steps), controls=len(controls))))


if __name__ == '__main__':
    main()
