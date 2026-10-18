"""Source-linked item stat groups; preserve enchant levels and conditional rows."""
import csv
import hashlib
import io
import importlib.util
import json
import os
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def passive_groups(items, sets, skills, names, operations):
    wanted = {r['PassiveSkillGroupId'] for r in items if r['PassiveSkillGroupId']}
    result = {gid:dict(group_id=gid,skills=[],runtime_activation_verified=False) for gid in wanted}
    by_id = {r['Id']:r for r in skills}
    by_name, by_operation = defaultdict(list), defaultdict(list)
    for row in names:
        by_name[row['Id']].append(row)
    for row in operations:
        by_operation[row['SkillId']].append(row)
    for row in sets:
        if row['GroupId'] in result:
            sid = row['SkillInfoId']
            result[row['GroupId']]['skills'].append(dict(id=sid,set_record=row,
                record=by_id.get(sid),names_en=by_name.get(sid,[]),operations=by_operation.get(sid,[])))
    return result


def skill_books(items, skills, names, item_types, binding=None):
    """Promote only the verified native branch and complete int32 target IDs."""
    skill_by_id = {row['Id']: row for row in skills}
    labels = defaultdict(list)
    for row in names:
        labels[row['Id']].append(row)
    result = {}
    for row in items:
        enum = item_types.get(row['Type'])
        if not enum or enum['name'] != 'EItemType::SkillBook':
            continue
        candidate = skill_by_id.get(row['EffectParams'])
        param = row['EffectParams']
        linked = bool(binding and binding.get('relation_verified') is True
            and row.get('EffectType') == str(binding['effect_type'])
            and int(row['Type']) not in binding['excluded_item_types']
            and re.fullmatch(r'[0-9]+',param) and 0 < int(param) <= 2147483647)
        skill_id = str(int(param)) if linked else None
        skill = skill_by_id.get(skill_id) if linked else None
        result[row['Id']] = dict(record=row, type_enum=enum,
            candidate_skill=candidate,
            candidate_names=labels.get(row['EffectParams'],[]) if candidate else [],
            relation_verified=linked, candidate_basis='Item.EffectParams equals Skill.Id',
            skill_id=skill_id, skill=skill, skill_names_en=labels.get(skill_id,[]) if skill else [],
            acquisition_verified=False)
    return result


def craft_origins(wanted_items, crafts, rewards, names, max_depth=32, max_paths=10000):
    """Keep outcome paths separate; never turn client rates into percentages."""
    groups = defaultdict(list)
    labels = defaultdict(list)
    for row in rewards:
        groups[row['GroupId']].append(row)
    for row in names:
        labels[row['Id']].append(row)
    result = {item_id: [] for item_id in wanted_items}
    issues = []
    visited=0
    def visit(craft, outcome, group_id, path, seen):
        nonlocal visited
        if len(path)>=max_depth:
            issues.append(dict(kind='depth_limit',craft_id=craft['Id'],group_id=group_id,outcome=outcome))
            return
        if group_id in seen:
            issues.append(dict(kind='cycle',craft_id=craft['Id'],group_id=group_id,outcome=outcome))
            return
        if group_id not in groups:
            issues.append(dict(kind='missing_group',craft_id=craft['Id'],group_id=group_id,outcome=outcome))
            return
        for row in groups[group_id]:
            visited+=1
            if visited>max_paths:
                raise ValueError('Craft reward expansion exceeds explicit bound')
            chain = path + [row]
            if row['Type'] == '12':
                visit(craft,outcome,row['Param'],chain,seen | {group_id})
            elif row['Type'] == '1' and row['Param'] in result:
                result[row['Param']].append(dict(craft=craft,names_en=labels.get(craft['Id'],[]),
                    outcome=outcome,reward_chain=chain,relation_verified=True,
                    chance_percent=None,runtime_available_verified=False,
                    material_link_verified=False))
    for craft in crafts:
        for field in ['FailRewardGroupId','SuccessRewardGroupId','BigSuccessRewardGroupId']:
            if craft[field]:
                visited=0
                visit(craft,field,craft[field],[],set())
    return result,issues


def restriction_groups(items, limits, use_limits, semantics):
    groups={r['LimitGroupId']:[] for r in items if r['LimitGroupId']}
    uses={r['ItemUseLimitId']:None for r in items if r['ItemUseLimitId']}
    for row in limits:
        if row['GroupId'] in groups:
            groups[row['GroupId']].append(dict(record=row,kind=semantics['item_limits'].get(row['LimitType']) if semantics else None))
    for row in use_limits:
        if row['Id'] in uses:
            if uses[row['Id']] is not None:
                raise ValueError('Duplicate ItemUseLimit.Id')
            uses[row['Id']]=dict(record=row,
                room_mode=semantics['room_limits'].get(row['RoomLimitType']) if semantics else None,
                world_ids=[s.strip() for s in row['WorldIdMultiString'].split(',') if s.strip()],
                room_types=[s.strip() for s in row['RoomTypeList'].split(',') if s.strip()],runtime_rule_verified=False)
    return dict(item_limits=groups,use_limits=uses)


def main(root=ROOT):
    metadata = {t['entry']: t for t in json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    sources = {}
    def load(name, entry):
        meta = metadata[entry]
        path = root/'table-study'/meta['file']
        if sha(path) != meta['sha256']:
            raise ValueError('Changed CSV: '+name)
        reader = csv.DictReader(io.StringIO(path.read_text('utf-8-sig')))
        if reader.fieldnames != meta['header']:
            raise ValueError('Changed schema: '+name)
        rows = [dict(row, provenance=dict(table=name, entry=entry, csv_record=i+2)) for i,row in enumerate(reader)]
        if len(rows) != meta['rows']:
            raise ValueError('Changed row count: '+name)
        sources[name] = meta
        return rows
    items = load('Item',194)
    enchants = load('ItemEnchantOperation',211)
    operations = load('StaticOperation',1521)
    types = {r['OperationType']: r for r in load('OperationType',1427)}
    names = {r['OperationType']: r for r in load('OperationName_en',486)}
    native_path = root/'code-clues/native-enums.json'
    native = json.loads(native_path.read_text('utf-8'))
    executable = Path(native['source']).read_bytes()
    if hashlib.sha256(executable).hexdigest() != native['sha256']:
        raise ValueError('Changed native source')
    deps = json.loads((root/'code-clues/table-dependencies.json').read_text('utf-8'))
    if deps['sha256'] != native['sha256']:
        raise ValueError('Different passive diagnostic source')
    diagnostics = []
    limit_diagnostics = []
    for source,field,target in [('Item','PassiveSkillGroupId','SkillSet'),('SkillSet','SkillInfoId','Skill'),
        ('Item','LimitGroupId','ItemLimit'),('Item','ItemUseLimitId','ItemUseLimit')]:
        diagnostic = next(r for r in deps['references'] if r['source']['sheet']==source and r['field']==field and r['target']['sheet']==target)
        raw = diagnostic['text'].encode('utf-16le'); offset = diagnostic['offset']
        if executable[offset:offset+len(raw)] != raw:
            raise ValueError('Changed passive reference diagnostic')
        (limit_diagnostics if target in ['ItemLimit','ItemUseLimit'] else diagnostics).append(diagnostic)
    limit_path=root/'code-clues/item-limit-semantics.json'
    limit_semantics=None
    if limit_path.is_file():
        limit_semantics=json.loads(limit_path.read_text('utf-8'))
        if limit_semantics['sha256']!=native['sha256']:
            raise ValueError('Different item limit parser source')
        for anchor in limit_semantics['anchors']:
            raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if executable[offset:offset+len(raw)]!=raw:
                raise ValueError('Changed item limit anchor')
        for dictionary in ['item_limits','room_limits']:
            for item in limit_semantics[dictionary].values():
                raw=item['name'].encode()+b'\0';offset=item['name_offset']
                if executable[offset:offset+len(raw)]!=raw:
                    raise ValueError('Changed item limit name')
    craft_diagnostics = []
    box_diagnostics = []
    for field, target in [('ItemId','Item'),('RewardGroupId','Reward'),('KeyItemInfoId','Item'),('InstallGadgetInfoId','Gadget')]:
        matches=[r for r in deps['references'] if r['source']['sheet']=='ItemBox' and r['field']==field and r['target']['sheet']==target]
        if len(matches)!=1:
            raise ValueError('Missing unique ItemBox diagnostic: '+field)
        diagnostic=matches[0];raw=diagnostic['text'].encode('utf-16le');offset=diagnostic['offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed ItemBox diagnostic')
        box_diagnostics.append(diagnostic)
    for field in ['FailRewardGroupId','SuccessRewardGroupId','BigSuccessRewardGroupId']:
        matches=[r for r in deps['references'] if r['source']['sheet']=='ItemCraft' and r['field']==field and r['target']['sheet']=='Reward']
        if len(matches)!=1:
            raise ValueError('Missing unique ItemCraft reward diagnostic: '+field)
        diagnostic=matches[0]
        raw=diagnostic['text'].encode('utf-16le');offset=diagnostic['offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed craft reference diagnostic')
        craft_diagnostics.append(diagnostic)
    effect_type_path=root/'code-clues/item-effect-semantics.json'
    effect_semantics=json.loads(effect_type_path.read_text('utf-8'))
    if effect_semantics['sha256']!=native['sha256']:
        raise ValueError('Different item effect parser source')
    for anchor in effect_semantics['anchors']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed item effect parser anchor')
    for entry in effect_semantics['types'].values():
        raw=entry['name'].encode()+b'\0';offset=entry['name_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed item effect parser name')
    reward_group_path=root/'code-clues/reward-group-semantics.json'
    reward_group_semantics=json.loads(reward_group_path.read_text('utf-8'))
    if reward_group_semantics['sha256']!=native['sha256'] or reward_group_semantics['field']!='Reward.RewardGroup':
        raise ValueError('Different reward group parser source or field')
    for anchor in reward_group_semantics['anchors']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed reward group parser anchor')
    for entry in reward_group_semantics['types'].values():
        raw=entry['name'].encode()+b'\0';offset=entry['name_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed reward group parser name')
    box_mode_path=root/'code-clues/item-box-mode-binding.json'
    box_mode_binding=json.loads(box_mode_path.read_text('utf-8'))
    if (box_mode_binding['sha256']!=native['sha256'] or box_mode_binding['field']!='ItemBox.RewardGroupType'
        or box_mode_binding['enum']!='ERewardGroup' or box_mode_binding['field_binding_verified'] is not True):
        raise ValueError('Different ItemBox mode binding')
    for anchor in box_mode_binding['anchors']+box_mode_binding['data_anchors']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed ItemBox mode binding anchor')
    skill_binding_path=root/'code-clues/item-skill-binding.json'
    skill_binding=json.loads(skill_binding_path.read_text('utf-8'))
    if (skill_binding['sha256']!=native['sha256'] or skill_binding['field']!='Item.EffectParams'
        or skill_binding['target']!='Skill.Id' or skill_binding['relation_verified'] is not True
        or skill_binding['effect_type']!=4 or skill_binding['excluded_item_types']!=[58]):
        raise ValueError('Different item skill binding')
    for anchor in skill_binding['anchors']+skill_binding['data_anchors']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed item skill binding anchor')
    conversion=skill_binding['conversion_import']
    for key in ['descriptor','thunk','dll','name']:
        raw=bytes.fromhex(conversion[key+'_bytes']);offset=conversion[key+'_offset']
        if executable[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed skill ID conversion import')
    del executable
    restrictions=restriction_groups(items,load('ItemLimit',210),load('ItemUseLimit',213),limit_semantics)
    skills = load('Skill',1505)
    skill_names = load('SkillName_en',525)
    passive = passive_groups(items,load('SkillSet',1513),skills,
        skill_names,load('SkillOperation',1512))
    effect_spec=importlib.util.spec_from_file_location('item_effect_links',Path(__file__).with_name('skill-effect-links.py'))
    effect_links=importlib.util.module_from_spec(effect_spec);effect_spec.loader.exec_module(effect_links)
    effects,effect_sources=effect_links.load_effects(root)
    for group in passive.values():
        for skill in group['skills']:
            skill['effect_candidates']=[c for row in skill['operations'] if (c:=effect_links.candidate(row,effects))]
    (root/'maps/skill-effects.js').write_bytes(Path(__file__).with_name('skill-effects.js').read_bytes())
    (root/'maps/skill-effects.css').write_bytes(Path(__file__).with_name('skill-effects.css').read_bytes())
    enums = {key: {str(r['value']): r for r in native['enums'][key]}
             for key in ['EOperationType','EClassType','EEquipmentType','EItemType','ERoomType']}
    grouped = defaultdict(list)
    for row in operations:
        enum = enums['EOperationType'].get(row['Type'])
        key = enum['name'].split('::')[-1] if enum else None
        grouped[row['GroupId']].append(dict(row=row, enum=enum,
            name=names.get(key), display=types.get(row['Type'])))
    wanted = {r['ItemEnchantOperationGroupId'] for r in items if r['ItemEnchantOperationGroupId']}
    by_enchant = defaultdict(list)
    for row in enchants:
        if row['GroupId'] in wanted:
            by_enchant[row['GroupId']].append(dict(row=row, operations=grouped.get(row['OperationGroupId'],[])))
    out = root/'maps/loot/item-details'
    (out/'enchant').mkdir(parents=True,exist_ok=True)
    (out/'blessing').mkdir(parents=True,exist_ok=True)
    (out/'passive').mkdir(parents=True,exist_ok=True)
    def write(path, payload):
        path.write_text(json.dumps(payload,ensure_ascii=False,separators=(',',':')),'utf-8')
        return dict(file=path.relative_to(out.parent).as_posix(),sha256=sha(path))
    enchant_specs = {gid:write(out/'enchant'/f'{gid}.json',dict(group_id=gid,levels=rows))
                     for gid,rows in by_enchant.items()}
    blessings = {r['BlessingOperationGroupId'] for r in items if r['BlessingOperationGroupId']}
    blessing_specs = {gid:write(out/'blessing'/f'{gid}.json',dict(group_id=gid,operations=grouped.get(gid,[]))) for gid in blessings}
    passive_specs = {gid:write(out/'passive'/f'{gid}.json',group) for gid,group in sorted(passive.items())}
    box_spec=importlib.util.spec_from_file_location('item_box_links',Path(__file__).with_name('item-box-links.py'))
    box_links=importlib.util.module_from_spec(box_spec);box_spec.loader.exec_module(box_links)
    box_groups=box_links.boxes(items,load('ItemBox',196),load('Reward',1475),mode_types=reward_group_semantics['types'])
    (out/'boxes').mkdir(exist_ok=True)
    box_specs={iid:write(out/'boxes'/f'{iid}.json',box) for iid,box in sorted(box_groups.items())}
    books = skill_books(items,skills,skill_names,enums['EItemType'],skill_binding)
    all_crafts,craft_issues = craft_origins({row['Id'] for row in items},load('ItemCraft',200),load('Reward',1475),load('ItemCraftName_en',463))
    (out/'crafts').mkdir(exist_ok=True)
    craft_specs={iid:write(out/'crafts'/f'{iid}.json',dict(item_id=iid,origins=origins))
                 for iid,origins in sorted(all_crafts.items()) if origins}
    for item_id,book in books.items():
        book['craft_origins'] = all_crafts[item_id]
    result = dict(schema_version=1,enchant_groups=enchant_specs,blessing_groups=blessing_specs,passive_groups=passive_specs,
        boxes=box_specs,box_sources=box_links.sources(box_groups),box_diagnostics=box_diagnostics,
        reward_group_types=reward_group_semantics['types'],
        reward_group_source=dict(file='code-clues/reward-group-semantics.json',sha256=sha(reward_group_path)),
        box_mode_source=dict(file='code-clues/item-box-mode-binding.json',sha256=sha(box_mode_path)),
        box_summary=dict(boxes=len(box_groups),paths=sum(len(b['paths']) for b in box_groups.values()),
                         issues=sum(len(b['issues']) for b in box_groups.values())),
        effect_types=effect_semantics['types'],effect_type_source=dict(file='code-clues/item-effect-semantics.json',sha256=sha(effect_type_path)),
        skill_books=books,craft_diagnostics=craft_diagnostics,craft_issues=craft_issues,
        item_crafts=craft_specs,craft_summary=dict(items=len(craft_specs),paths=sum(len(rows) for rows in all_crafts.values()),issues=len(craft_issues)),
        item_skill_binding_source=dict(file='code-clues/item-skill-binding.json',sha256=sha(skill_binding_path)),
        item_effect_candidates={row['Id']:candidate for row in items if (candidate:=effect_links.item_candidate(row,effects))},
        passive_diagnostics=diagnostics,
        effect_sources=effect_sources,
        restrictions=restrictions,limit_diagnostics=limit_diagnostics,
        limit_semantics_source=dict(file='code-clues/item-limit-semantics.json',sha256=sha(limit_path)) if limit_semantics else None,
        enums=enums,sources=sources,native_source=dict(source=native['source'],sha256=native['sha256']),
        joins=['Reward.RewardGroup = ERewardGroup.value (native ModifyValue parser)',
               'ItemBox.RewardGroupType = ERewardGroup.value (loader record+28 -> OnItemBoxUpdated reflected enum argument)',
               'SkillBook with EffectType=SkillAcquire: Item.EffectParams -> _wtoi -> Skill.Id (native already-learned UI check; acquisition not verified)',
               'ItemCraft.FailRewardGroupId/SuccessRewardGroupId/BigSuccessRewardGroupId = Reward.GroupId (native reference-validation diagnostics)',
               'ItemBox.ItemId = Item.Id; ItemBox.RewardGroupId = Reward.GroupId; ItemBox.KeyItemInfoId = Item.Id (native reference-validation diagnostics)',
               'Reward.Type=Item -> Reward.Param=Item.Id; Reward.Type=Reward -> Reward.Param=Reward.GroupId',
               'Item.ItemEnchantOperationGroupId = ItemEnchantOperation.GroupId',
               'ItemEnchantOperation.OperationGroupId = StaticOperation.GroupId',
               'Item.BlessingOperationGroupId = StaticOperation.GroupId',
               'Item.LimitGroupId = ItemLimit.GroupId (native reference-validation diagnostic)',
               'Item.ItemUseLimitId = ItemUseLimit.Id (native reference-validation diagnostic)',
               'Item.PassiveSkillGroupId = SkillSet.GroupId (native reference-validation diagnostic)',
               'SkillSet.SkillInfoId = Skill.Id (native reference-validation diagnostic)',
               'Skill.Id = SkillName_en.Id; Skill.Id = SkillOperation.SkillId',
               'StaticOperation.Type = EOperationType.value -> OperationName_en.OperationType'],
        limitations=['Exact field joins of client tables; server changes not verified.',
            'Enchant levels are separate snapshots, never added together.',
            'Extra/category/index rows are kept separate; activation rules not evaluated.',
            'Passive descriptions are client localization text, not a verified server formula or guarantee.',
            'Item restriction parser names verified where evidence exists; World/Room list composition and runtime enforcement not evaluated.',
            'Min/Max and percentage parameters remain in source units.'])
    write(out/'index.json',result)
    print(json.dumps(dict(enchant_groups=len(enchant_specs),blessing_groups=len(blessing_specs),passive_groups=len(passive_specs))))
    return result


if __name__ == '__main__':
    main()
