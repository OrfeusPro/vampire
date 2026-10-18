"""Keep box reward branches separate; list definitions, not guaranteed outcomes."""
from collections import defaultdict


def boxes(items, definitions, rewards, max_paths=10000, max_depth=32, mode_types=None):
    item_ids = {r['Id'] for r in items}
    groups = defaultdict(list)
    for row in rewards:
        groups[row['GroupId']].append(row)
    result = {}
    for box in definitions:
        item_id = box['ItemId']
        if item_id in result:
            raise ValueError('Duplicate ItemBox.ItemId')
        paths, issues = [], []
        row_count = 0

        def visit(group_id, chain, seen):
            nonlocal row_count
            if len(chain) >= max_depth:
                issues.append(dict(kind='depth_limit', group_id=group_id))
                return
            if group_id in seen:
                issues.append(dict(kind='cycle', group_id=group_id))
                return
            if group_id not in groups:
                issues.append(dict(kind='missing_group', group_id=group_id))
                return
            for reward in groups[group_id]:
                row_count += 1
                if row_count > max_paths:
                    raise ValueError('ItemBox reward expansion exceeds explicit bound')
                path = chain + [reward]
                if reward['Type'] == '12':
                    visit(reward['Param'], path, seen | {group_id})
                else:
                    target = reward['Param'] if reward['Type'] == '1' else None
                    paths.append(dict(reward_chain=path, item_id=target,
                                      item_present=target in item_ids if target is not None else None,
                                      relation_verified=True, chance_percent=None, runtime_available_verified=False))
                    if target is not None and target not in item_ids:
                        issues.append(dict(kind='missing_item', item_id=target, reward_id=reward['Id']))
        if item_id not in item_ids:
            issues.append(dict(kind='missing_box_item', item_id=item_id))
        if box['RewardGroupId']:
            visit(box['RewardGroupId'], [], set())
        else:
            issues.append(dict(kind='empty_reward_group'))
        key_id = box.get('KeyItemInfoId', '')
        if key_id and key_id not in item_ids:
            issues.append(dict(kind='missing_key_item', item_id=key_id))
        mode = (mode_types or {}).get(box['RewardGroupType'])
        # Max/fallback and unknown codes must not become selection modes.
        if mode and mode['name']=='Max':
            mode = None
        result[item_id] = dict(item_id=item_id, record=box, paths=paths, issues=issues,
                               key_item_id=key_id or None, key_count=box.get('KeyItemCount', ''),
                               reward_group_type_raw=box['RewardGroupType'],
                               reward_group_mode=mode,
                               reward_group_mode_verified=mode is not None,
                               runtime_selection_verified=False, runtime_opening_verified=False)
    return result


def sources(boxes):
    """Reverse only terminal Item rewards; group by box without adding quantities."""
    result = defaultdict(dict)
    for box_id, box in boxes.items():
        for path in box['paths']:
            if path['item_id'] is None or not path['item_present']:
                continue
            entry = result[path['item_id']].setdefault(box_id, dict(box_item_id=box_id, path_count=0))
            entry['path_count'] += 1
    return {iid: list(boxes.values()) for iid, boxes in result.items()}
