"""Selected-monster details with native-declared Battle join and raw reward chains."""
import csv
import hashlib
import io
import json
import os
import importlib.util
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path, expected):
    if sha(path) != expected:
        raise ValueError('Changed source: ' + str(path))
    return json.loads(path.read_text('utf-8'))


def drops_by_npc(origins):
    result = defaultdict(lambda: defaultdict(list))
    for item, chains in origins.items():
        for chain in chains:
            result[chain['npc_id']][item].append(chain)
    return {npc: dict(items) for npc, items in result.items()}


def group_battles(rows):
    battles = defaultdict(list)
    for n, row in enumerate(rows):
        battles[row['GroupId']].append(dict(row, provenance=dict(table='Battle', entry=1545, csv_record=n + 2)))
    return dict(battles)


def skill_book_index(books, items):
    """Reverse only proved target IDs, preserving missing definitions and all books."""
    result = defaultdict(list)
    for iid, book in books.items():
        if book.get('relation_verified') is not True or not book.get('skill_id'):
            continue
        item = items.get(iid)
        if item is None:
            continue
        result[book['skill_id']].append(dict(item_id=iid,
            label=' / '.join(dict.fromkeys(r['Name'] for r in item.get('names_en',[]) if r.get('Name'))) or 'Книга '+iid,
            icon=item.get('icon'),rarity=item.get('rarity'),
            provenance=book['record'].get('provenance'),relation_verified=True,acquisition_verified=False))
    return dict(result)


def skill_passive_item_index(groups, items):
    """Reverse exact Item group joins; retain every SkillSet row, not activations."""
    result=defaultdict(list)
    for iid,item in items.items():
        gid=item.get('data',{}).get('PassiveSkillGroupId')
        group=groups.get(gid)
        if not group:
            continue
        by_skill=defaultdict(list)
        for skill in group['skills']:
            if skill['id'] and skill['set_record']['GroupId']==gid:
                by_skill[skill['id']].append(skill['set_record'])
        for sid,records in by_skill.items():
            result[sid].append(dict(item_id=iid,group_id=gid,set_records=records,
                label=' / '.join(dict.fromkeys(r['Name'] for r in item.get('names_en',[]) if r.get('Name'))) or 'Предмет '+iid,
                icon=item.get('icon'),rarity=item.get('rarity'),
                provenance=item['data'].get('provenance'),relation_verified=True,
                runtime_activation_verified=False))
    return dict(result)


def condition_detail(record, semantics):
    if not record or not semantics:
        return None
    value = record['FireCondition']
    found = semantics['conditions'].get(value)
    return dict(value=value, name=found['name'] if found else None,
        status='verified_name' if found else 'parser_fallback' if value == str(semantics['unknown_parser_value']) else 'unknown',
        name_offset=found['name_offset'] if found else None,
        parameters=[record.get('FireConditionParam'+str(i),'') for i in range(1,4)],
        runtime_predicate_verified=False)


def target_detail(value, semantics, condition=False):
    if not semantics or value is None or value == '':
        return None
    dictionary = semantics['target_conditions' if condition else 'targets']
    fallback = semantics['unknown_target_condition_value' if condition else 'unknown_target_value']
    found = dictionary.get(value)
    return dict(value=value,name=found['name'] if found else None,
        status='verified_name' if found else 'parser_fallback' if value==str(fallback) else 'unknown',
        name_offset=found['name_offset'] if found else None,runtime_predicate_verified=False)


def skill_display_names(english, korean):
    """English first; preserve Korean source and mark translated basic attacks."""
    def nonempty(rows):
        return [r for r in rows if r.get('Name','').strip()]
    rows = nonempty(english)
    language = 'en'
    if not rows:
        rows = nonempty(korean)
        language = 'ko'
    names, seen = [], set()
    for row in rows:
        original = row['Name'].strip()
        if original in seen:
            continue
        seen.add(original)
        basic = re.fullmatch(r'(?:###)?\s*기본\s*공격\s*(\d+)?', original) if language == 'ko' else None
        text = 'Базовая атака'+(' '+basic[1] if basic[1] else '') if basic else original
        names.append(dict(text=text,original=original,language=language,
            translated=bool(basic),source_marked=original.startswith('###'),
            provenance=row.get('provenance')))
    return names


def skill_npc_index(npcs, battles):
    result=defaultdict(set)
    for nid,npc in npcs.items():
        for battle in battles.get(npc['BattleGroupId'],[]):
            for sid in battle.get('SkillIdList','').split(','):
                if sid.strip():result[sid.strip()].add(nid)
    return {sid:sorted(ids) for sid,ids in sorted(result.items())}


def npc_portraits(npc, profiles, icons):
    """Only explicit Img fields and exact NpcProfile.NpcInfoId joins; no name-family fallback."""
    sources, images = [], {}
    declarations = [(npc.get('Img', ''), dict(table='Npc', field='Img', provenance=npc.get('provenance')))]
    declarations += [(row.get('Img', ''), dict(table='NpcProfile', field='Img', provenance=row.get('provenance'),
        group_id=row['GroupId'], record=row)) for row in profiles if row['NpcInfoId'] == npc['Id']]
    for key, source in declarations:
        if not key:
            continue
        resolved = icons.get(key, dict(status='missing', images=[]))
        sources.append(dict(source, key=key, status=resolved['status']))
        for image in resolved['images']:
            identity = (image['asset_path'], image['file'])
            if identity not in images:
                images[identity] = dict(image, field_sources=[])
            images[identity]['field_sources'].append(len(sources) - 1)
    return dict(status='found' if images else 'missing' if sources else 'not_declared',
                images=list(images.values()), sources=sources, family_match_used=False,
                runtime_appearance_verified=False)


def main(root=ROOT):
    out, loot = root / 'maps/atlas', root / 'maps/loot'
    manifest = json.loads((out / 'nocturne-manifest.json').read_text('utf-8'))
    scene = read(out / manifest['file'], manifest['sha256'])
    atlas = json.loads((out / 'index.json').read_text('utf-8'))
    tables = read(out / 'tables.json', atlas['tables_sha256'])
    metadata = {m['entry']: m for m in json.loads((root / 'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    meta = metadata[1545]
    raw = (root / 'table-study' / meta['file']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta['sha256']:
        raise ValueError('Changed Battle CSV')
    reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
    if reader.fieldnames != meta['header'] or not {'GroupId', 'HP', 'AttackPower', 'DefensePower'} <= set(reader.fieldnames):
        raise ValueError('Changed Battle schema')
    rows = list(reader)
    if len(rows) != meta['rows'] or any(None in r or None in r.values() for r in rows):
        raise ValueError('Changed Battle records')
    battles = group_battles(rows)
    deps = json.loads((root / 'code-clues/table-dependencies.json').read_text('utf-8'))
    data = Path(deps['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != deps['sha256']:
        raise ValueError('Changed client executable')
    diagnostic = next(r for r in deps['references'] if r['source']['sheet'] == 'Npc' and r['field'] == 'BattleGroupId' and r['target']['sheet'] == 'Battle')
    encoded = diagnostic['text'].encode('utf-16le')
    if data[diagnostic['offset']:diagnostic['offset'] + len(encoded)] != encoded:
        raise ValueError('Changed native Battle reference diagnostic')
    profile_diagnostic = next(r for r in deps['references'] if r['source']['sheet'] == 'NpcProfile'
                              and r['field'] == 'NpcInfoId' and r['target']['sheet'] == 'Npc')
    encoded = profile_diagnostic['text'].encode('utf-16le')
    if data[profile_diagnostic['offset']:profile_diagnostic['offset'] + len(encoded)] != encoded:
        raise ValueError('Changed native NPC profile reference diagnostic')
    selection_path=root/'code-clues/drop-selection-code.json'
    selection=None
    if selection_path.is_file():
        selection=json.loads(selection_path.read_text('utf-8'))
        if selection['sha256']!=deps['sha256'] or not selection['client_ui_selection_verified']:
            raise ValueError('Changed drop selection evidence')
        for anchor in selection['anchors']:
            raw_anchor=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if data[offset:offset+len(raw_anchor)]!=raw_anchor:
                raise ValueError('Changed drop selection anchor')
    semantics_path = root/'code-clues/skill-semantics.json'
    semantics = None
    if semantics_path.is_file():
        semantics = json.loads(semantics_path.read_text('utf-8'))
        if semantics['sha256'] != deps['sha256']:
            raise ValueError('Different skill semantics source')
        evidence = semantics['anchors']+[semantics['parser_thunk']]
        for condition in semantics['conditions'].values():
            evidence.extend(condition[k] for k in ['literal_anchor','byte_anchor','name_pointer_anchor','value_pointer_anchor'])
            literal = condition['name'].encode()+b'\0'; offset = condition['name_offset']
            if data[offset:offset+len(literal)] != literal:
                raise ValueError('Changed condition name')
        for anchor in evidence:
            raw_anchor = bytes.fromhex(anchor['bytes']); offset = anchor['file_offset']
            if data[offset:offset+len(raw_anchor)] != raw_anchor:
                raise ValueError('Changed skill semantics anchor')
    targets_path = root/'code-clues/skill-target-semantics.json'
    target_semantics = None
    if targets_path.is_file():
        target_semantics = json.loads(targets_path.read_text('utf-8'))
        if target_semantics['sha256'] != deps['sha256']:
            raise ValueError('Different target semantics source')
        evidence = target_semantics['anchors']+target_semantics['parser_thunks']
        for key in ['targets','target_conditions']:
            for item in target_semantics[key].values():
                evidence.extend(item[k] for k in ['literal_anchor','byte_anchor','name_pointer_anchor','value_pointer_anchor'])
                literal=item['name'].encode()+b'\0';offset=item['name_offset']
                if data[offset:offset+len(literal)] != literal:
                    raise ValueError('Changed target name')
        for anchor in evidence:
            raw_anchor=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if data[offset:offset+len(raw_anchor)] != raw_anchor:
                raise ValueError('Changed target semantics anchor')
    tick_path = root/'code-clues/skill-tick-code.json'
    tick = None
    if tick_path.is_file():
        tick = json.loads(tick_path.read_text('utf-8'))
        if tick['sha256'] != deps['sha256'] or tick['verified'] != dict(
                cooldown_counter_unit='seconds',table_fields=['MinCoolTime','MaxCoolTime'],
                table_unit='milliseconds',seconds_divisor=1000,static_client_path=True):
            raise ValueError('Changed skill cooldown units evidence')
        for anchor in tick['anchors']+tick['literals']+tick['vtable_slots']:
            offset=anchor['file_offset']; raw_anchor=bytes.fromhex(anchor['bytes'])
            if data[offset:offset+len(raw_anchor)] != raw_anchor:
                raise ValueError('Changed cooldown tick bytes')
        for dependency in tick['dependencies']:
            read(root/dependency['file'],dependency['sha256'])
    native = json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
    if native['sha256'] != deps['sha256']:
        raise ValueError('Different native enum source')
    skill_sources = {}
    def load_skill_table(name, entry):
        source = metadata[entry]
        raw = (root/'table-study'/source['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('Changed skill CSV: '+name)
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
        if reader.fieldnames != source['header']:
            raise ValueError('Changed skill schema')
        rows = [dict(r,provenance=dict(table=name,entry=entry,csv_record=i+2)) for i,r in enumerate(reader)]
        if len(rows) != source['rows']:
            raise ValueError('Changed skill records')
        skill_sources[name] = source
        return rows
    skills = {r['Id']:r for r in load_skill_table('Skill',1505)}
    level_changes=defaultdict(list)
    for row in load_skill_table('SkillLevel',1511):
        level_changes[row['SkillInfoId']].append(row)
    level_path=root/'code-clues/skill-level-code.json'
    level_code=json.loads(level_path.read_text('utf-8'))
    if level_code['sha256']!=deps['sha256'] or level_code['verified']!=dict(
        skill_id_join=True,inclusive_level_range=True,nonzero_replacement=True):
        raise ValueError('Changed SkillLevel semantics')
    if level_code['sources']['SkillLevel']['sha256']!=skill_sources['SkillLevel']['sha256']:
        raise ValueError('Different SkillLevel source')
    for anchor in level_code['anchors']+level_code['literals']+level_code['vtable_slots']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if data[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed SkillLevel anchor')
    level_extra_path=root/'code-clues/skill-level-extra-code.json'
    level_extra=json.loads(level_extra_path.read_text('utf-8'))
    if level_extra['sha256']!=deps['sha256'] or level_extra['verified']!=dict(
        resource_replacement=True,stack_count_replacement=True,first_inclusive_range=True):
        raise ValueError('Changed extra SkillLevel semantics')
    for anchor in level_extra['anchors']+level_extra['literals']+level_extra['vtable_slots']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if data[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed extra SkillLevel anchor')
    level_mp_path=root/'code-clues/skill-level-mp-code.json'
    level_mp=json.loads(level_mp_path.read_text('utf-8'))
    if level_mp['sha256']!=deps['sha256'] or level_mp['verified']!=dict(
        mp_min_replacement=True,mp_max_replacement=True,first_inclusive_range=True):
        raise ValueError('Changed MP SkillLevel semantics')
    for anchor in level_mp['anchors']+level_mp['literals']+level_mp['vtable_slots']:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if data[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed MP SkillLevel anchor')
    del data
    effect_spec=importlib.util.spec_from_file_location('monster_effect_links',Path(__file__).with_name('skill-effect-links.py'))
    effect_links=importlib.util.module_from_spec(effect_spec);effect_spec.loader.exec_module(effect_links)
    effects,effect_sources=effect_links.load_effects(root)
    (root/'maps/skill-effects.js').write_bytes(Path(__file__).with_name('skill-effects.js').read_bytes())
    (root/'maps/skill-effects.css').write_bytes(Path(__file__).with_name('skill-effects.css').read_bytes())
    skill_names, skill_operations = defaultdict(list), defaultdict(list)
    for row in load_skill_table('SkillName_en',525):
        skill_names[row['Id']].append(row)
    skill_names_ko = defaultdict(list)
    for row in load_skill_table('SkillName_ko',1020):
        skill_names_ko[row['Id']].append(row)
    operation_enums = {str(r['value']):r for r in native['enums']['EOperationType']}
    for row in load_skill_table('SkillOperation',1512):
        skill_operations[row['SkillId']].append(dict(record=row,operation_enum=operation_enums.get(row['OperationType']),
            effect_candidate=effect_links.candidate(row,effects),
            target=target_detail(row['TargetType'],target_semantics),
            target_condition=target_detail(row['TargetConditionType'],target_semantics,condition=True)))
    battle_enums = {key:{str(r['value']):r for r in native['enums'][key]}
                    for key in ['EAttackApplyType','EAttributeType']}
    li = json.loads((loot / 'index.json').read_text('utf-8'))
    item_details_spec=li['files']['item-details']
    item_details=read(loot/item_details_spec['file'],item_details_spec['sha256'])
    item_catalog=read(loot/li['files']['items']['file'],li['files']['items']['sha256'])
    book_index=skill_book_index(item_details['skill_books'],item_catalog)
    passive_groups={gid:read(loot/spec['file'],spec['sha256']) for gid,spec in item_details['passive_groups'].items()}
    passive_item_index=skill_passive_item_index(passive_groups,item_catalog)
    image_path=root/'archive-image-latest.json'
    image_rows=json.loads(image_path.read_text('utf-8'))
    image_spec=importlib.util.spec_from_file_location('skill_icon_resolver',Path(__file__).with_name('build-npc-loot.py'))
    image_resolver=importlib.util.module_from_spec(image_spec);image_spec.loader.exec_module(image_resolver)
    profile_rows=load_skill_table('NpcProfile',1414)
    profile_source=skill_sources.pop('NpcProfile')
    if any(row['NpcInfoId'] not in {npc['Id'] for npc in tables['Npc']} for row in profile_rows):
        raise ValueError('NPC profile references missing NPC')
    profiles_by_npc=defaultdict(list)
    for row in profile_rows:
        profiles_by_npc[row['NpcInfoId']].append(row)
    image_fields=['Img','ImgBg','ImgSmall','ImgBgSmall']
    skill_image_keys={row[field] for row in skills.values() for field in image_fields if row[field]}
    npc_image_keys={row['Img'] for row in tables['Npc'] if row['Img']}|{row['Img'] for row in profile_rows if row['Img']}
    image_keys=skill_image_keys|npc_image_keys
    image_by_name=defaultdict(list)
    for image in image_rows:
        key=image['asset_path'].rsplit('/',1)[-1]
        if key in image_keys:
            image_by_name[key].append(image)
    skill_icons={key:image_resolver.resolve_icon(key,image_by_name.get(key,[])) for key in image_keys}
    checked_images=set()
    for resolved in skill_icons.values():
        for image in resolved['images']:
            if image['file'] not in checked_images:
                if sha(root/image['file'])!=image['sha256']:
                    raise ValueError('Changed skill icon: '+image['file'])
                checked_images.add(image['file'])
    def skill_image_fields(sid):
        return {field:skill_icons.get(skills[sid][field],dict(key='',status='not_declared',images=[]))
                for field in image_fields} if sid in skills else {}
    def skill_record(sid):
        return dict(id=sid,record=skills.get(sid),names_en=skill_names.get(sid,[]),
            display_names=skill_display_names(skill_names.get(sid,[]),skill_names_ko.get(sid,[])),
            cooldown_time_unit='milliseconds' if tick else None,
            fire_condition=condition_detail(skills.get(sid),semantics),
            target=target_detail(skills[sid]['TargetType'],target_semantics) if sid in skills else None,
            operations=skill_operations.get(sid,[]),books=book_index.get(sid,[]),
            passive_items=passive_item_index.get(sid,[]),images=skill_image_fields(sid),
            level_overrides=dict(records=level_changes[sid],cooldown_replacement_verified=True,
                resource_replacement_verified=True,stack_count_replacement_verified=True,
                mp_min_replacement_verified=True,mp_max_replacement_verified=True,
                other_replacements_verified=False,runtime_cooldown_verified=False) if sid in level_changes else None)
    def skill_details(battle):
        ids = list(dict.fromkeys(sid.strip() for row in battle for sid in row['SkillIdList'].split(',') if sid.strip()))
        return {sid:skill_record(sid) for sid in ids}
    origins = read(loot / li['files']['item-origins']['file'], li['files']['item-origins']['sha256'])
    drops = drops_by_npc(origins)
    area_rows = read(loot / li['files']['area-reward-candidates']['file'], li['files']['area-reward-candidates']['sha256'])
    reward_groups = read(loot / li['files']['reward-groups']['file'], li['files']['reward-groups']['sha256'])
    spec = importlib.util.spec_from_file_location('monster_loot_builder', Path(__file__).with_name('build-npc-loot.py'))
    loot_builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loot_builder)
    area_origins, area_issues = loot_builder.item_origins(area_rows, reward_groups)
    area_drops = drops_by_npc(area_origins)
    # The shared reward expander uses NPC-shaped keys; rename them for area evidence.
    for area_items in area_drops.values():
        for chains in area_items.values():
            for chain in chains:
                chain['area_id'] = chain.pop('npc_id')
                chain['area_reward_id'] = chain.pop('npc_reward_id')
                chain['area_reward_provenance'] = chain.pop('npc_reward_provenance')
    area_rewards = defaultdict(list)
    for row in area_rows:
        area_rewards[row['GroupId']].append(row)
    area_payload = dict(areas={aid: dict(area_id=aid, rewards=rows, drops=area_drops.get(aid, {}),
        status='client_reward_ui_area_link_verified' if selection else 'candidate_group_id_match_only') for aid, rows in area_rewards.items()},
        item_areas={iid: sorted({chain['area_id'] for chain in chains}) for iid, chains in area_origins.items()},
        sources=dict(area_rewards=li['files']['area-reward-candidates'], reward_groups=li['files']['reward-groups']),
        client_ui_selection_verified=bool(selection),application_to_kills_verified=False)
    area_path = out / 'area-rewards.json'
    area_path.write_text(json.dumps(area_payload, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    npc_areas, npc_spawns = defaultdict(set), defaultdict(list)
    for row in tables['NpcSpawn']:
        npc_spawns[row['NpcInfoId']].append(row)
        if row['AreaInfoId'] not in ('', '0'):
            npc_areas[row['NpcInfoId']].add(row['AreaInfoId'])
    npc_index = {n['id']: n for n in li['npcs']}
    definitions = {n['Id']: n for n in tables['Npc']}
    folder = out / 'monsters'
    folder.mkdir(exist_ok=True)
    files, catalog_entries, linked = {}, {}, 0
    if set(npc_index) - definitions.keys():
        raise ValueError('NPC catalogue references missing definitions')
    for nid in sorted(npc_index, key=int):
        npc = definitions[nid]
        battle = battles.get(npc['BattleGroupId'], [])
        if battle:
            linked += 1
        source = npc_index.get(nid, {})
        rewards = read(loot / source['file'], source['sha256'])['rewards'] if source.get('file') else []
        portrait=npc_portraits(npc,profiles_by_npc.get(nid,[]),skill_icons)
        payload = dict(npc_id=nid, npc=npc, battle=battle, placements=npc_spawns.get(nid, []), portraits=portrait,
            drop_ui_selection_verified=bool(selection),
            skills=skill_details(battle),battle_enums=battle_enums,
            battle_relation='Npc.BattleGroupId→Battle.GroupId (client reference-validation diagnostic)',
            rewards=rewards, drops=drops.get(nid, {}), chance_percent=None,
            area_candidates={aid: dict(area_id=aid, rewards=area_rewards[aid], drops=area_drops.get(aid, {}),
                status='client_reward_ui_area_link_verified' if selection else 'candidate_group_id_match_only',
                relation='NpcSpawn.AreaInfoId = AreaReward.GroupId; client reward UI selection verified' if selection else 'NpcSpawn.AreaInfoId = AreaReward.GroupId; application to individual kills not yet proved')
                for aid in sorted(npc_areas[nid]) if aid in area_rewards},
            limitations=['Client base parameters; live server modifiers unverified.',
                'Reward amounts belong to their source rows. Nested group multipliers and activation conditions are not evaluated.',
                'Raw RewardRate/Rate are not percentages.'])
        path = folder / (nid + '.json')
        path.write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), 'utf-8')
        files[nid] = dict(file='monsters/' + path.name, sha256=sha(path))
        catalog_entries[nid] = dict(source, detail=files[nid], drop_item_count=len(drops.get(nid, {})),
                                    battle_variants=len(battle), placement_count=len(npc_spawns.get(nid, [])), on_nocturne=nid in scene['npcs'], portraits=portrait)
    catalog_path = out / 'npc-catalog.json'
    catalog_path.write_text(json.dumps(dict(npcs=catalog_entries,
        sources=dict(npcs=li['sources'].get('Npc') if 'sources' in li else None,
                     loot_index_sha256=sha(loot/'index.json'), scene_sha256=manifest['sha256']),
        limitations=['All NPC definitions include non-combat and technical records.',
                     'Listed rewards and spawns do not prove current runtime availability.']),
        ensure_ascii=False, separators=(',', ':')), 'utf-8')
    result = dict(schema_version=1, files=files, npc_catalog=dict(file=catalog_path.name,sha256=sha(catalog_path)), area_file=dict(file='area-rewards.json', sha256=sha(area_path)), stats=dict(npcs=len(files), linked_battle=linked, nocturne_npcs=len(scene['npcs'])),
        sources=dict(battle=meta, atlas_tables_sha256=atlas['tables_sha256'],
            npc_reward=li['sources'].get('NpcReward') if 'sources' in li else None,
            item_origins=li['files']['item-origins'], scene_sha256=manifest['sha256'],
            area_rewards=li['files']['area-reward-candidates'], reward_groups=li['files']['reward-groups'], area_issues=area_issues,
            executable=dict(source=deps['source'], sha256=deps['sha256']), battle_diagnostic=diagnostic))
    result['sources']['skills'] = skill_sources
    result['sources']['skill_images']=dict(file='archive-image-latest.json',sha256=sha(image_path),
        matched_files=len({image['file'] for key in skill_image_keys for image in skill_icons[key]['images']}),relation='Skill image field equals exact texture basename; distinct full paths retained')
    result['sources']['npc_images']=dict(file='archive-image-latest.json',sha256=sha(image_path),
        profile_table=profile_source, profile_diagnostic=profile_diagnostic,
        matched_files=len({image['file'] for key in npc_image_keys for image in skill_icons[key]['images']}),
        npc_statuses={status:sum(row['portraits']['status']==status for row in catalog_entries.values()) for status in ['found','missing','not_declared']},
        relation='Npc.Img; NpcProfile.NpcInfoId → Npc.Id; Img equals exact texture basename, no Blueprint name fallback',
        runtime_appearance_verified=False)
    result['sources']['skill_level_overrides']=dict(file='code-clues/skill-level-code.json',sha256=sha(level_path))
    result['sources']['skill_level_extra']=dict(file='code-clues/skill-level-extra-code.json',sha256=sha(level_extra_path))
    result['sources']['skill_level_mp']=dict(file='code-clues/skill-level-mp-code.json',sha256=sha(level_mp_path))
    used_skill_ids = {sid for nid in scene['npcs'] for battle in battles.get(definitions[nid]['BattleGroupId'], [])
                      for sid in battle['SkillIdList'].split(',') if sid}
    display_names = {sid:skill_display_names(skill_names.get(sid,[]),skill_names_ko.get(sid,[]))
                     for sid in sorted(used_skill_ids)}
    reverse_skills=skill_npc_index({nid:definitions[nid] for nid in scene['npcs']},battles)
    skill_folder=out/'skills';skill_folder.mkdir(exist_ok=True)
    skill_entries={}
    for sid in sorted(set(skills)|set(reverse_skills)|set(book_index)|set(passive_item_index)):
        payload=skill_record(sid)
        path=skill_folder/(sid+'.json')
        path.write_text(json.dumps(payload,ensure_ascii=False,separators=(',',':')),'utf-8')
        skill_entries[sid]=dict(id=sid,npc_ids=reverse_skills.get(sid,[]),
            display_names=payload['display_names'],images=payload['images'],book_count=len(payload['books']),passive_item_count=len(payload['passive_items']),
            detail=dict(file='skills/'+path.name,sha256=sha(path)))
    skill_index=dict(skills=skill_entries,
        relation='Npc.BattleGroupId → Battle.GroupId; Battle.SkillIdList → Skill.Id; verified SkillBook target IDs reversed from item-details',
        sources=dict(battle=meta,skill=skill_sources['Skill'],scene_sha256=manifest['sha256'],
                     names_en=skill_sources['SkillName_en'],names_ko=skill_sources['SkillName_ko'],
                     skill_level=skill_sources['SkillLevel'],
                     skill_level_semantics=dict(file='code-clues/skill-level-code.json',sha256=sha(level_path)),
                     skill_level_extra=dict(file='code-clues/skill-level-extra-code.json',sha256=sha(level_extra_path)),
                     skill_level_mp=dict(file='code-clues/skill-level-mp-code.json',sha256=sha(level_mp_path)),
                     skill_images=result['sources']['skill_images'],
                     item_details=item_details_spec,items=li['files']['items'],
                     passive_groups=item_details['passive_groups'],passive_diagnostics=item_details['passive_diagnostics'],
                     item_skill_binding=item_details['item_skill_binding_source']),
        limitations=['All client Battle variants retained; runtime skill use and current NPC visibility unverified.',
                     'NPC reverse links cover Nocturne only; standalone definitions cover all Skill rows.',
                     'Book target IDs verified in client UI; acquisition and server restrictions unverified.'])
    skill_index_path=out/'skill-npcs.json'
    skill_index_path.write_text(json.dumps(skill_index,ensure_ascii=False,separators=(',',':')),'utf-8')
    result['skill_index']=dict(file=skill_index_path.name,sha256=sha(skill_index_path))
    name_coverage = {language:sum((names[0]['language'] if names else 'missing')==language
                                for names in display_names.values()) for language in ['en','ko','missing']}
    (out/'skill-names-verification.json').write_text(json.dumps(dict(
        sources={key:skill_sources[key] for key in ['Skill','SkillName_en','SkillName_ko']},
        stats=dict(npcs=len(scene['npcs']),unique_skills=len(used_skill_ids),coverage=name_coverage),
        display_names=display_names,
        limitations=['Exact ID join; PAK internal CSV path unavailable. Korean locale identified from content and matching SkillMessage schema.',
            'Only basic-attack labels translated to Russian; original source and translation flag preserved.',
            'English preferred; empty names do not generate guessed names from Resource.']),ensure_ascii=False,indent=2),'utf-8')
    result['sources']['effects'] = effect_sources
    if tick:
        result['sources']['skill_cooldown_units'] = dict(file='code-clues/skill-tick-code.json',
            sha256=sha(tick_path),fields=tick['verified']['table_fields'],
            table_unit='milliseconds',seconds_divisor=1000,runtime_cooldown_verified=False)
    if semantics:
        result['sources']['skill_semantics'] = dict(file='code-clues/skill-semantics.json',sha256=sha(semantics_path),
            relation=semantics['relation'],runtime_predicates_verified=False,time_unit=None,damage_formula_verified=False)
    if target_semantics:
        result['sources']['skill_target_semantics'] = dict(file='code-clues/skill-target-semantics.json',sha256=sha(targets_path),
            relations=target_semantics['relations'],runtime_predicates_verified=False)
    if selection:
        result['sources']['drop_selection']=dict(file='code-clues/drop-selection-code.json',sha256=sha(selection_path),
            rule=selection['rule'],client_ui_selection_verified=True,server_kill_application_verified=False)
    result['sources']['skill_relations'] = ['Battle.SkillIdList → Skill.Id (comma-separated exact IDs)',
        'Skill.Id → SkillName_en.Id', 'Skill.Id → SkillOperation.SkillId',
        'SkillOperation.OperationType → EOperationType.value; parameter meanings not fully reconstructed']
    result['sources']['skill_relations'].append('Skill.Id → SkillName_ko.Id (CSV1020); English preferred, Korean fallback preserves source/translation marker')
    (out / 'monster-manifest.json').write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    print(json.dumps(result['stats']))


if __name__ == '__main__':
    main()
