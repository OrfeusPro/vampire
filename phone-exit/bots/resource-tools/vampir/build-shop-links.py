"""Resolve native NpcShopBuy tasks through category/tab/product/reward tables."""
import csv
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def main():
    folder = ROOT / 'table-study'
    metadata = {m['entry']: m for m in json.loads((folder / 'index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables']}
    sources = {}

    def load(entry):
        meta = metadata[entry]
        path = folder / meta['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('Source changed: ' + path.name)
        sources[str(entry)] = meta
        with path.open(encoding='utf-8-sig', newline='') as stream:
            return [dict(row, source=dict(entry=entry, csv_record=i + 2)) for i, row in enumerate(csv.DictReader(stream))]

    native = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    with Path(native['source']).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != native['sha256']:
            raise ValueError('Native executable changed; rebuild enum evidence')

    def symbol(enum, value):
        return next((row['name'] for row in native['enums'][enum] if str(row['value']) == str(value)), None)

    npc_buy = next(row['value'] for row in native['enums']['EQuestTaskType'] if row['name'] == 'EQuestTaskType::NpcShopBuy')
    tasks = [row for row in load(1454) if row['Type'] == str(npc_buy)]
    categories = {r['Id']: r for r in load(1500)}
    tabs = defaultdict(list)
    for row in load(1503):
        tabs[row['ShopCategoryInfoId']].append(row)
    products = defaultdict(list)
    for row in load(1499):
        products[row['ShopTabInfoId']].append(row)
    rewards = defaultdict(list)
    for row in load(1475):
        rewards[row['GroupId']].append(row)
    items = {r['Id']: r for r in load(462)}
    npc_spawns = {r['Id']: r for r in load(1546)}
    results, issues = [], []
    for task in tasks:
        try:
            param = json.loads(task['Param'])
        except ValueError:
            issues.append(dict(task=task['Id'], reason='invalid JSON parameter'))
            continue
        category_id, spawn_id = str(param.get('shopCategoryInfoId', '')), str(param.get('npcSpawnInfoId', ''))
        selected = []
        for tab in tabs.get(category_id, []):
            for product in products.get(tab['Id'], []):
                expanded = []
                for reward in rewards.get(product['BaseRewardGroupId'], []):
                    expanded.append(dict(row=reward, typeName=symbol('ERewardType', reward['Type']),
                                         groupName=symbol('ERewardGroup', reward['RewardGroup']),
                                         item=items.get(reward['Param']) if symbol('ERewardType', reward['Type']) == 'ERewardType::Item' else None))
                selected.append(dict(row=product, tab=tab, costTypeName=symbol('ECostType', product['CostType']),
                                     conditionTypeName=symbol('EPurchaseCondition', product['NeedConditionType']),
                                     condition2TypeName=symbol('EPurchaseCondition', product['NeedConditionType02']),
                                     rewards=expanded, eligibility='not_evaluated'))
        if category_id not in categories:
            issues.append(dict(task=task['Id'], reason='category missing', category=category_id))
        results.append(dict(task=task, typeName='EQuestTaskType::NpcShopBuy', param=param,
                            category=categories.get(category_id),
                            shopTypeName=symbol('EShopType', categories[category_id]['ShopType']) if category_id in categories else None,
                            npcSpawn=npc_spawns.get(spawn_id), products=selected))
    lock_rows = load(69)
    tab_keywords = {product['tab']['ContentsLockKeyword'] for task in results for product in task['products']}
    unresolved_tab_keywords = sorted(k for k in tab_keywords if k and not any(r['Keyword'] == k for r in lock_rows))
    report = dict(sources=sources, nativeEnumSource=dict(source=native['source'], sha256=native['sha256']),
                  unresolvedTabLockKeywords=unresolved_tab_keywords,
                  tasks=results, issues=issues,
                  limitations=['Product list is source data, not current server stock',
                               'Price modifiers, limits, eligibility and character assets not evaluated',
                               'No automatic selection or purchase is performed',
                               'Unknown native function semantics are not inferred from table names'])
    (ROOT / 'quest-graph/shop-tasks.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(tasks=len(results), issues=len(issues))))
    example = next(r for r in results if r['task']['Id'] == '901030010')
    for row in example['products']:
        print(row['row']['Id'], row['row']['CostParam'], row['row']['CostValue'], row['conditionTypeName'],
              row['row']['NeedConditionParam01'], [(r['row']['Param'], (r['item'] or {}).get('Name', '')) for r in row['rewards']])


if __name__ == '__main__':
    main()
