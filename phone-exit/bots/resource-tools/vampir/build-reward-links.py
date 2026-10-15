"""Connect all quest prerequisites and reward groups to source Reward rows."""
import csv
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def connect_locks(locks, conditions):
    groups = defaultdict(list)
    seen = set()
    for condition in conditions:
        if condition['Id'] in seen:
            raise ValueError('Duplicate ContentsLockCondition ID: ' + condition['Id'])
        seen.add(condition['Id'])
        groups[condition['GroupId']].append(condition)
    result = {}
    for lock in locks:
        if lock['Id'] in result:
            raise ValueError('Duplicate ContentsLock ID: ' + lock['Id'])
        group = lock['ContentsLockConditionGroupId']
        rows = groups.get(group, [])
        result[lock['Id']] = dict(lock, conditions=rows,
            groupResolution='none_declared' if group in ('', '0') else 'resolved' if rows else 'missing',
            evaluation='not_evaluated', combination='unknown_do_not_assume_AND_OR')
    return result


def main():
    folder = ROOT / 'table-study'
    metadata = {m['entry']: m for m in json.loads((folder / 'index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables']}

    def load(entry):
        meta = metadata[entry]
        file = folder / meta['file']
        if hashlib.sha256(file.read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('CSV changed: ' + meta['file'])
        with file.open(encoding='utf-8-sig', newline='') as stream:
            return [dict(row, source=dict(entry=entry, csv_record=i + 2)) for i, row in enumerate(csv.DictReader(stream))]

    quests = load(1448)
    rewards = load(1475)
    tasks = load(1454)
    contents_locks = connect_locks(load(69), load(70))
    native = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    with Path(native['source']).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != native['sha256']:
            raise ValueError('Native executable changed; rebuild enum evidence')
    reward_types = {str(r['value']): r['name'] for r in native['enums']['ERewardType']}
    group_types = {str(r['value']): r['name'] for r in native['enums']['ERewardGroup']}
    quest_ids = {q['Id'] for q in quests}
    reward_groups = defaultdict(list)
    by_quest = defaultdict(list)
    for row in rewards:
        row['typeName'] = reward_types.get(row['Type'])
        row['groupName'] = group_types.get(row['RewardGroup'])
        reward_groups[row['GroupId']].append(row)
    for row in tasks:
        by_quest[row['QuestInfoId']].append(row)
    links, missing = [], []
    needed_groups = set()
    for quest in quests:
        groups = [quest['RewardGroupId' + str(n)] for n in range(1, 6) if quest['RewardGroupId' + str(n)] not in ('', '0')]
        needed_groups.update(groups)
        required = [x.strip() for x in quest['RequireCompleteQuestInfoId'].split(',') if x.strip() not in ('', '0')]
        for group in groups:
            if group not in reward_groups:
                missing.append(dict(quest=quest['Id'], rewardGroup=group))
        links.append(dict(questId=quest['Id'], preQuestRaw=quest['PreQuestId'], requiredCompletedQuests=required,
                          requiredLevel=quest['RequireCharacterLv'], contentsLockId=quest['ContentsLockInfoId'],
                          retryable=quest['Retryable'], serverServiceGroup=quest['ServerServiceGroupId'],
                          rewardGroups=groups, source=quest['source'], tasks=by_quest[quest['Id']]))
    report = dict(sources={str(n): metadata[n] for n in (69, 70, 1448, 1454, 1475)}, quests=links,
                  nativeEnumSource=dict(source=native['source'], sha256=native['sha256']),
                  contentsLocks=contents_locks,
                  rewardGroups={g: reward_groups[g] for g in sorted(needed_groups)},
                  missingRewardGroups=missing,
                  unresolvedRequiredQuests=[dict(quest=q['questId'], required=r) for q in links for r in q['requiredCompletedQuests'] if r not in quest_ids],
                  limitations=['Declared availability/task conditions are data, not proof of character completion',
                               'ContentsLock groups joined; numeric condition semantics and AND/OR not established',
                               'Reward Type, Rate, RewardGroup and flags retained raw; no probability normalization guessed',
                               'Do not claim received items from a click alone; UI/inventory verification remains required'])
    dest = ROOT / 'quest-graph/rewards.json'
    dest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    lock_links = [dict(questId=q['questId'], contentsLockId=q['contentsLockId'], source=q['source']) for q in links if q['contentsLockId'] not in ('', '0')]
    missing_locks = [q for q in lock_links if q['contentsLockId'] not in contents_locks]
    missing_groups = [dict(id=k, group=v['ContentsLockConditionGroupId']) for k, v in contents_locks.items() if v['groupResolution'] == 'missing']
    type_counts = defaultdict(int)
    unresolved_candidates = []
    for lock in contents_locks.values():
        for condition in lock['conditions']:
            type_counts[condition['ConditionType']] += 1
            if condition['ConditionType'] == '1' and condition['ConditionTypeValue1'] not in quest_ids:
                unresolved_candidates.append(dict(lockId=lock['Id'], condition=condition))
    locks_report = dict(schemaVersion=1, sources={str(n): metadata[n] for n in (69, 70, 1448, 1454)},
                        locks=contents_locks, questLinks=lock_links, missingLocks=missing_locks,
                        missingConditionGroups=missing_groups, linkedConditionTypeCounts=dict(type_counts),
                        unmatchedType1QuestCandidates=unresolved_candidates,
                        interpretations={'1': 'Quest reference candidate from data correspondence; native check not decoded'},
                        limitations=['No player state evaluated', 'AND/OR and numeric comparators unknown',
                                     'Unmatched type-1 values are research findings, not confirmed corrupt game data'])
    (ROOT / 'quest-graph/contents-locks.json').write_text(json.dumps(locks_report, ensure_ascii=False, indent=2), encoding='utf-8')
    example_ids = {'110190', '110520', '110530', '110540', '901010', '901030'}
    example = dict(quests=[q for q in links if q['questId'] in example_ids],
                   locks={q['contentsLockId']: contents_locks[q['contentsLockId']] for q in links
                          if q['questId'] in example_ids and q['contentsLockId'] not in ('', '0')},
                   explanation='Explicit quest requirements and raw lock conditions; type-1 target interpretation remains unconfirmed')
    (ROOT / 'quest-graph/early-unlock-chain.json').write_text(json.dumps(example, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(quests=len(links), groups=len(needed_groups), reward_rows=sum(len(v) for v in report['rewardGroups'].values()),
                         missing_groups=len(missing), unresolved_required=len(report['unresolvedRequiredQuests']),
                         contents_locks=len(contents_locks), quest_locks=len(lock_links), missing_locks=len(missing_locks),
                         missing_condition_groups=len(missing_groups))))


if __name__ == '__main__':
    main()
