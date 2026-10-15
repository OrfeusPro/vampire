"""Bind one reviewed NPC purchase to hashed table rows and observed controls.

Does not enable arbitrary purchases from a catalog or infer lock semantics.
"""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'


def reference(report):
    task = next(t for t in report['tasks'] if t['task']['Id'] == '901030010')
    product = next(p for p in task['products'] if p['row']['Id'] == '10500003')
    row = product['row']
    if (task['typeName'] != 'EQuestTaskType::NpcShopBuy' or task['param'] !=
            dict(npcSpawnInfoId=1101101, interactionType='MoveContents', shopCategoryInfoId=3, count=1)):
        raise ValueError('Shop task changed')
    if (row['CostParam'], row['CostValue'], product['costTypeName'], product['conditionTypeName']) != (
            'Gold', '75', 'ECostType::Asset', 'EPurchaseCondition::Max'):
        raise ValueError('Reviewed product cost/condition changed')
    if len(product['rewards']) != 1 or product['rewards'][0]['row']['Param'] != '91100005':
        raise ValueError('Reviewed item changed')
    return dict(schemaVersion=1, questId='901030', taskId='901030010', productId='10500003',
                count=1, asset='Gold', amount=75, itemId='91100005',
                task=task['task'], category=task['category'], npcSpawn=task['npcSpawn'],
                product=product, sources=report['sources'], nativeEnumSource=report['nativeEnumSource'],
                eligibility='Observed enabled small potion on Pixel 5; not a general Max evaluator',
                unresolvedTabLockKeywords=report['unresolvedTabLockKeywords'])


def main():
    report = json.loads((ROOT / 'quest-graph/shop-tasks.json').read_text(encoding='utf-8'))
    for source in report['sources'].values():
        if hashlib.sha256((ROOT / 'table-study' / source['file']).read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Source table changed')
    binding = reference(report)
    (MODULE / 'shop-reference.json').write_text(json.dumps(binding, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    draft = ROOT / 'phone-tests/shop-901030/vision-shop-draft.json'
    config = json.loads((MODULE / 'vision.json').read_text(encoding='utf-8'))
    observed = json.loads(draft.read_text(encoding='utf-8'))
    provenance = json.loads((draft.parent / 'template-provenance.json').read_text(encoding='utf-8'))
    for template in provenance['templates']:
        name = template['name']
        spec = observed['templates'][name]
        if hashlib.sha256((MODULE / 'templates' / spec['file']).read_bytes()).hexdigest() != template['template_sha256']:
            raise ValueError('Observed template changed: ' + name)
        config['templates'][name] = spec
    config.setdefault('match_alternatives', {}).update(observed.get('match_alternatives', {}))
    config['shop_flow'] = dict(reference='shop-reference.json', timeout_sec=20,
        guide=['shop_guide_title', 'shop_guide_task'], open='shop_guide_task',
        listing=['shop_merchant_header', 'shop_small_row', 'shop_row_gold75'], select='shop_small_row',
        confirmation=['shop_small_popup', 'shop_quantity_one', 'shop_amount_label', 'shop_amount75'], buy='shop_buy_button',
        merchant=['shop_merchant_header', 'shop_exit'], close='shop_exit',
        completed=['shop_guide_title', 'claim_rewards_text', 'guide_complete_check'])
    if 'connection_terminated_inspect' not in config['manual_screens']:
        config['manual_screens'].append('connection_terminated_inspect')
    (MODULE / 'vision.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Bound Quest 901030 / task 901030010 / product 10500003 / one item / 75 Gold')


if __name__ == '__main__':
    main()
