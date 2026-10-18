"""Source-linked NPC rewards, items and icons. Raw rates are never percentages."""
import csv
import hashlib
import io
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def dump(path,data):
    path.write_text(json.dumps(data,ensure_ascii=False,separators=(',',':')),encoding='utf-8')


def csv_reader(raw):
    return csv.DictReader(io.StringIO(raw.decode('utf-8-sig'),newline=''))


def group(rows,field):
    result=defaultdict(list)
    for row in rows:result[row[field]].append(row)
    return dict(result)


def resolve_icon(key,images):
    candidates=[r for r in images if r['asset_path'].rsplit('/',1)[-1]==key] if key else []
    # Patch selection is per full resource path, never across different paths.
    selected={}
    for row in candidates:
        old=selected.get(row['asset_path'])
        if old is None or row.get('patch',0)>old.get('patch',0):selected[row['asset_path']]=row
    candidates=list(selected.values())
    return dict(key=key,status='not_declared' if not key else 'missing' if not candidates else
        'exact_unique_name' if len(candidates)==1 else 'ambiguous_paths',images=candidates)


def item_rarities(native, icon):
    """Viewer styles from ERarity names and exact client texture basenames.

    Resource suffix association is explicit, not a proven runtime widget binding.
    """
    labels = {'Common':'Обычный','Uncommon':'Необычный','Rare':'Редкий',
        'Epic':'Эпический','Legendary':'Легендарный','Mythic':'Мифический',
        'Unique':'Уникальный','Seasonal':'Сезонный'}
    result = {}
    for row in native['enums']['ERarity']:
        name = row['name'].split('::')[-1]
        if name not in labels:
            continue
        suffix = 'Legend' if name == 'Legendary' else name
        result[str(row['value'])] = dict(id=str(row['value']), name=name,
            label=labels[name], background=icon('TEX_GradeBGItem_' + suffix),
            enum_provenance=row, mapping='enum_name_to_texture_suffix',
            runtime_widget_binding_verified=False)
    return result


def item_origins(npc_rewards,reward_groups):
    """Preserve every distinct source chain; do not merge rolls or derive odds."""
    result=defaultdict(list)
    issues=[]
    def visit(parent,gid,path,seen):
        if gid in seen:
            issues.append(dict(kind='cycle',npc_reward_id=parent['Id'],group_id=gid));return
        if gid not in reward_groups:
            issues.append(dict(kind='missing_group',npc_reward_id=parent['Id'],group_id=gid));return
        for row in reward_groups[gid]:
            chain=path+[dict(group_id=gid,reward_id=row['Id'])]
            if row['Type']=='12':visit(parent,row['Param'],chain,seen|{gid})
            elif row['Type']=='1':
                result[row['Param']].append(dict(npc_id=parent['GroupId'],npc_reward_id=parent['Id'],
                    npc_reward_provenance=parent.get('provenance'),reward_chain=chain,
                    raw_reward_rate=parent['RewardRate'],raw_rate=row['Rate'],
                    reward_group=row['RewardGroup'],min_count=row['MinCount'],max_count=row['MaxCount'],
                    acquisition_group_type=parent['AcquisitionGroupType'],
                    acquisition_method_type=parent['AcquisitionMethodType'],chance_percent=None))
    for row in npc_rewards:
        if row['RewardType']=='12':visit(row,row['RewardParam'],[],set())
        elif row['RewardType']=='1':
            result[row['RewardParam']].append(dict(npc_id=row['GroupId'],npc_reward_id=row['Id'],
                npc_reward_provenance=row.get('provenance'),reward_chain=[],raw_reward_rate=row['RewardRate'],
                min_count=row['MinRewardValue'],max_count=row['MaxRewardValue'],chance_percent=None))
    return dict(result),issues


def main(root=ROOT):
    metadata={t['entry']:t for t in json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    sources={}
    def load(name,entry,required,key='Id',unique=True):
        meta=metadata[entry];path=root/'table-study'/meta['file']
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=meta['sha256']:raise ValueError('Changed CSV: '+meta['file'])
        reader=csv_reader(raw)
        if reader.fieldnames!=meta['header'] or not set(required)<=set(reader.fieldnames):raise ValueError('Changed schema: '+name)
        rows=list(reader)
        if len(rows)!=meta['rows'] or any(None in r or None in r.values() for r in rows):raise ValueError('Invalid rows: '+name)
        if unique and len({r[key] for r in rows})!=len(rows):raise ValueError('Duplicate IDs: '+name)
        sources[name]=meta
        return [dict(r,provenance=dict(table=name,entry=entry,csv_record=i+2)) for i,r in enumerate(rows)]
    npcs=load('Npc',1544,['Id','Blueprint','Img'])
    npc_names=group(load('NpcName_en',481,['Id','Name'],unique=False),'Id')
    npc_rewards=load('NpcReward',1415,['Id','GroupId','RewardType','RewardParam','RewardRate'])
    area_candidates=load('AreaRewardCandidate',11,['Id','GroupId','RewardType','RewardParam','RewardRate'])
    rewards=load('Reward',1475,['Id','GroupId','Type','Param','Rate','RewardGroup'])
    items=load('Item',194,['Id','Img','Type','Rarity'])
    item_names=group(load('ItemName_en',462,['Id','Name'],unique=False),'Id')
    assets=load('Asset',19,['AssetType','Img'],key='AssetType')
    spawns=load('NpcSpawn',1546,['Id','NpcInfoId','WorldInfoId','AreaInfoId'])
    native=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
    dependencies=json.loads((root/'code-clues/table-dependencies.json').read_text('utf-8'))
    if sha(Path(native['source']))!=native['sha256'] or native['sha256']!=dependencies['sha256']:
        raise ValueError('Native evidence source changed')
    declaration=[r for r in dependencies['references'] if r['source']['sheet']=='NpcReward' and
        r['field']=='GroupId' and r['target']['sheet']=='Npc']
    if len(declaration)!=1:raise ValueError('Missing unique NpcReward -> Npc declaration')
    reward_types={str(r['value']):r['name'] for r in native['enums']['ERewardType']}
    group_types={str(r['value']):r['name'] for r in native['enums']['ERewardGroup']}
    allimages=json.loads((root/'archive-image-latest.json').read_text('utf-8'))
    supplemental=root/'item-icons-float/index.json'
    if supplemental.is_file():allimages+=json.loads(supplemental.read_text('utf-8'))['images']
    image_by_name=group([dict(r,basename=r['asset_path'].rsplit('/',1)[-1]) for r in allimages],'basename')
    icons={key:resolve_icon(key,rows) for key,rows in image_by_name.items()}
    checked=set()
    def icon(key):
        result=icons.get(key,dict(key=key,status='missing' if key else 'not_declared',images=[]))
        for row in result['images']:
            if row['file'] not in checked:
                if sha(root/row['file'])!=row['sha256']:raise ValueError('Changed icon PNG: '+row['file'])
                checked.add(row['file'])
        return result
    by_npc=group(npc_rewards,'GroupId');npc_ids={n['Id'] for n in npcs}
    if set(by_npc)-npc_ids:raise ValueError('NpcReward references missing NPC')
    groups=group(rewards,'GroupId')
    wanted={r['RewardParam'] for r in npc_rewards+area_candidates if r['RewardType']=='12'}
    missing_groups=sorted(wanted-groups.keys())
    selected_groups={k:groups[k] for k in sorted(wanted) if k in groups}
    # Expand nested references as data, detecting missing groups; no random draws.
    queue=list(selected_groups)
    for gid in queue:
        for row in selected_groups[gid]:
            if row['Type']=='12' and row['Param'] not in selected_groups:
                if row['Param'] in groups:selected_groups[row['Param']]=groups[row['Param']];queue.append(row['Param'])
                else:missing_groups.append(row['Param'])
    for rows in selected_groups.values():
        for row in rows:
            row['type_name']=reward_types.get(row['Type'])
            row['group_name']=group_types.get(row['RewardGroup'])
            row['chance_percent']=None
    for row in npc_rewards+area_candidates:row['type_name']=reward_types.get(row['RewardType']);row['chance_percent']=None
    origins,origin_issues=item_origins(npc_rewards,selected_groups)
    direct_ids={r['Param'] for rows in selected_groups.values() for r in rows if r['Type']=='1'}
    npc_groupids={r['RewardParam'] for r in npc_rewards if r['RewardType']=='12'}
    npc_item_ids={r['Param'] for gid in npc_groupids for r in groups.get(gid,[]) if r['Type']=='1'}
    rarities=item_rarities(native,icon)
    item_types={str(r['value']):r['name'] for r in native['enums']['EItemType']}
    item_catalog={r['Id']:dict(data=r,type_name=item_types.get(r['Type']),names_en=item_names.get(r['Id'],[]),icon=icon(r['Img']),
        rarity=rarities.get(r['Rarity'],dict(id=r['Rarity'],name=None,label='Редкость не установлена')),
        in_npc_reward=r['Id'] in npc_item_ids,in_area_candidate=r['Id'] in direct_ids-npc_item_ids) for r in items}
    asset_catalog={r['AssetType']:dict(data=r,icon=icon(r['Img'])) for r in assets}
    locations=defaultdict(lambda:defaultdict(set))
    for spawn in spawns:locations[spawn['NpcInfoId']][spawn['WorldInfoId']].add(spawn['AreaInfoId'])
    npc_locations={nid:rows for nid,rows in group(spawns,'NpcInfoId').items() if nid in by_npc}
    out=root/'maps/loot';(out/'npcs').mkdir(parents=True,exist_ok=True)
    summaries=[]
    for npc in npcs:
        nid=npc['Id'];rows=by_npc.get(nid,[]);file=None;file_hash=None
        if rows:
            file='npcs/'+nid+'.json'
            dump(out/file,dict(npc=npc,names_en=npc_names.get(nid,[]),rewards=rows,
                locations={wid:sorted(a) for wid,a in locations[nid].items()},chance_percent=None,
                status='client_reward_rows_available'))
            file_hash=sha(out/file)
        summaries.append(dict(id=nid,name=' / '.join(dict.fromkeys(x['Name'] for x in npc_names.get(nid,[]))) or npc['NameEN'] or npc['Blueprint'],
            level=npc['Level'],reward_rows=len(rows),file=file,sha256=file_hash,
            world_ids=sorted(locations[nid]),status='client_reward_rows_available' if rows else 'no_client_reward_rows_found'))
    dump(out/'items.json',item_catalog);dump(out/'assets.json',asset_catalog)
    dump(out/'item-rarities.json',dict(rarities=rarities,item_source=sources['Item'],
        native_source=dict(source=native['source'],sha256=native['sha256']),
        limitations=['Viewer uses original client textures matched to ERarity names; runtime widget binding and fresh Android appearance not verified.']))
    dump(out/'reward-groups.json',selected_groups);dump(out/'area-reward-candidates.json',area_candidates)
    dump(out/'item-origins.json',origins)
    dump(out/'npc-locations.json',npc_locations)
    referenced_images={r['asset_path']:r for item in item_catalog.values() for r in item['icon']['images']}
    item_images={r['asset_path']:r for r in allimages if '/Texture/Image/Item/' in r['asset_path']}
    for row in item_images.values():
        if row['file'] not in checked and sha(root/row['file'])!=row['sha256']:
            raise ValueError('Changed item image PNG: '+row['file'])
    dump(out/'item-images.json',list(item_images.values()))
    report=dict(schema_version=1,sources=sources,native_source=dict(path=native['source'],sha256=native['sha256'],
        declarations=declaration,reward_types=reward_types,group_types=group_types),npcs=summaries,
        stats=dict(npcs=len(npcs),npcs_with_reward_rows=len(by_npc),npc_reward_rows=len(npc_rewards),
            npc_reward_groups=len(npc_groupids),npc_reward_item_ids=len(npc_item_ids),all_items=len(items),
            all_item_image_paths=len(item_images),linked_image_paths=len(referenced_images),
            npc_item_icon_status=dict(Counter(item_catalog[i]['icon']['status'] for i in npc_item_ids if i in item_catalog))),
        files={name:dict(file=name+'.json',sha256=sha(out/(name+'.json'))) for name in
            ['items','assets','reward-groups','area-reward-candidates','item-images','item-origins','npc-locations','item-rarities']},
        issues=dict(origin_issues=origin_issues,missing_reward_groups=sorted(set(missing_groups)),missing_item_ids=sorted(direct_ids-item_catalog.keys()),
            npc_items_without_images=[dict(id=i,img=item_catalog[i]['data']['Img']) for i in sorted(npc_item_ids)
                                      if i in item_catalog and item_catalog[i]['icon']['status']=='missing']),
        chance_percent_verified=False,android_verified=False,
        limitations=['Rates are raw client values; denominator, roll count, acquisition method and server modifiers unresolved.',
            'No client reward rows is not evidence that an NPC drops nothing.',
            'AreaRewardCandidate entry11 preserved separately; GroupId->Area semantics not yet proven by native evidence.',
            'Images matched by exact resource basename; multiple full paths remain ambiguous. Patch suffix selection is provisional.',
            'FloatRGBA previews preserve raw provenance and two color conversions; Android colors not verified.'])
    evidence_path=root/'code-clues/loot-rate-evidence.json'
    if evidence_path.is_file():
        evidence=json.loads(evidence_path.read_text('utf-8'))
        if evidence['sha256']!=native['sha256']:raise ValueError('Rate evidence has different EXE')
        for t in evidence['tables']:
            if sources['AreaRewardCandidate' if t['name']=='AreaReward' else t['name']]['sha256']!=t['csv_source']['sha256']:
                raise ValueError('Rate evidence has different CSV')
        rate_summary=dict(source=evidence['source'],sha256=evidence['sha256'],conversion=evidence['conversion'],
            tables=[{k:t[k] for k in ['name','entry','field','column_index','object_offset','storage_bits','raw_stats','fractional_rows']} for t in evidence['tables']],
            chance_percent_verified=False,limitations=evidence['limitations'])
        dump(out/'rate-evidence.json',rate_summary)
        report['files']['rate-evidence']=dict(file='rate-evidence.json',sha256=sha(out/'rate-evidence.json'))
        report['native_rate_evidence']=dict(file='code-clues/loot-rate-evidence.json',sha256=sha(evidence_path))
    callbacks_path=root/'code-clues/loot-record-links.json'
    if callbacks_path.is_file():
        callbacks=json.loads(callbacks_path.read_text('utf-8'))
        if callbacks['sha256']!=native['sha256']:raise ValueError('Record evidence has different EXE')
        dump(out/'rate-callbacks.json',{k:callbacks[k] for k in ['source','sha256','links','chance_percent_verified','limitations']})
        report['files']['rate-callbacks']=dict(file='rate-callbacks.json',sha256=sha(out/'rate-callbacks.json'))
    dump(out/'index.json',report)
    (out/'index.html').write_text(Path(__file__).with_name('npc-loot.html').read_text('utf-8'),encoding='utf-8')
    (out.parent/'item-rarity.js').write_text(Path(__file__).with_name('item-rarity.js').read_text('utf-8'),encoding='utf-8')
    import importlib.util
    detail_spec=importlib.util.spec_from_file_location('item_details_builder',Path(__file__).with_name('build-item-details.py'))
    detail_module=importlib.util.module_from_spec(detail_spec);detail_spec.loader.exec_module(detail_module)
    detail_result=detail_module.main(root)
    for item_id,book in detail_result['skill_books'].items():
        item_catalog[item_id]['craft_source_count']=len(book['craft_origins'])
    dump(out/'items.json',item_catalog)
    report['files']['items']['sha256']=sha(out/'items.json')
    report['files']['item-details']=dict(file='item-details/index.json',sha256=sha(out/'item-details/index.json'))
    dump(out/'index.json',report)
    (out/'item-details.js').write_text(Path(__file__).with_name('item-details.js').read_text('utf-8'),encoding='utf-8')
    (out/'item-details.css').write_text(Path(__file__).with_name('item-details.css').read_text('utf-8'),encoding='utf-8')
    (out/'item-stat-model.js').write_text(Path(__file__).with_name('item-stat-model.js').read_text('utf-8'),encoding='utf-8')
    import runpy
    runpy.run_path(str(Path(__file__).with_name('build-catalog-pages.py')))['main'](root)
    print(json.dumps(report['stats'],ensure_ascii=False))
    return report


if __name__=='__main__':main()
