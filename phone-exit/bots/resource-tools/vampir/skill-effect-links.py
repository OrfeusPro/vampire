"""Effect definitions with verified EffectOperation join; Skill param links are candidates."""
import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from pathlib import Path


def describe_action(value, semantics):
    found=semantics['actions'].get(value) if semantics else None
    return dict(value=value,name=found['name'] if found else None,
        status='verified_name' if found else 'parser_fallback' if semantics and value==str(semantics['unknown_parser_value']) else 'unknown',
        runtime_behavior_verified=False)


def describe_rule(value, semantics, kind):
    if kind not in ('buff','overlay'):
        raise ValueError('Unknown effect rule domain')
    found=semantics[kind+'_types'].get(value) if semantics else None
    return dict(value=value,name=found['name'] if found else None,
        status='verified_name' if found else 'parser_fallback' if semantics and value==str(semantics['unknown_'+kind+'_value']) else 'unknown',
        runtime_rule_verified=False)


def timing_fields(record):
    """Describe source fields without deciding their unit or precedence."""
    raw={key:record.get(key,'') for key in ['Duration','MinDuration','MaxDuration','DurationGrowthRate','Period']}
    values=[raw[key] for key in ['Duration','MinDuration','MaxDuration']]
    comparable=all(value and value.isdecimal() for value in values)
    outside=not int(values[1])<=int(values[0])<=int(values[2]) if comparable else None
    return dict(raw=raw,duration_outside_bounds=outside,unit=None,field_precedence_verified=False)


def verified_semantics(root,filename,native,data,dictionaries,value_anchor):
    path=root/'code-clues'/filename
    if not path.is_file():
        return None
    result=json.loads(path.read_text('utf-8'))
    if result['sha256']!=native['sha256']:
        raise ValueError('Different effect semantics source')
    anchors=result['anchors']+[result['parser_thunk']]
    for dictionary in dictionaries:
        for value in result[dictionary].values():
            anchors.extend(value[key]for key in ['literal_anchor',value_anchor,'name_pointer_anchor','value_pointer_anchor'])
            raw=value['name'].encode()+b'\0';offset=value['name_offset']
            if data[offset:offset+len(raw)]!=raw:
                raise ValueError('Changed effect semantics name')
    for anchor in anchors:
        raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
        if data[offset:offset+len(raw)]!=raw:
            raise ValueError('Changed effect semantics anchor')
    return result


def index_effects(effects, operations, enums, action_semantics=None, rule_semantics=None):
    grouped=defaultdict(list)
    for row in operations:
        grouped[row['EffectInfoId']].append(dict(record=row,operation_enum=enums['EOperationType'].get(row['OperationType'])))
    result={}
    for row in effects:
        if row['Id'] in result:
            raise ValueError('Duplicate Effect.Id')
        result[row['Id']]=dict(record=row,type_enum=enums['EEffectType'].get(row['Type']),
            timing=timing_fields(row),
            buff_type=describe_rule(row.get('BuffType',''),rule_semantics,'buff'),
            overlay_type=describe_rule(row.get('OverlayType',''),rule_semantics,'overlay'),
            action=describe_action(row.get('ActionType',''),action_semantics),operations=grouped.get(row['Id'],[]))
    return result


def candidate(operation, effects):
    if operation['OperationType']!='2001' or operation['OperationParam1'] in ('','0'):
        return None
    eid=operation['OperationParam1']
    return dict(effect_id=eid,status='candidate_param1_id_match_only' if eid in effects else 'candidate_definition_missing',
        skill_operation_id=operation['Id'],skill_operation_provenance=operation.get('provenance'),
        relation_verified=False,runtime_application_verified=False,effect=effects.get(eid))


def item_candidate(item, effects):
    """Exact ID comparison only; no proof that an item applies this definition."""
    if item.get('EffectType') != '1' or item.get('EffectParams', '') in ('', '0'):
        return None
    eid = item['EffectParams']
    return dict(origin='item',item_id=item['Id'],item_provenance=item.get('provenance'),
        source_field='Item.EffectParams',effect_id=eid,
        status='candidate_item_param_id_match_only' if eid in effects else 'candidate_definition_missing',
        relation_verified=False,runtime_application_verified=False,effect=effects.get(eid))


def load_effects(root):
    metadata={t['entry']:t for t in json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    sources={}
    def load(name,entry):
        source=metadata[entry];raw=(root/'table-study'/source['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=source['sha256']:
            raise ValueError('Changed effect CSV')
        reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
        if reader.fieldnames!=source['header']:
            raise ValueError('Changed effect schema')
        rows=[dict(r,provenance=dict(table=name,entry=entry,csv_record=i+2))for i,r in enumerate(reader)]
        if len(rows)!=source['rows'] or any(None in r or None in r.values()for r in rows):
            raise ValueError('Changed effect rows')
        sources[name]=source
        return rows
    native=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
    deps=json.loads((root/'code-clues/table-dependencies.json').read_text('utf-8'))
    data=Path(native['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=native['sha256'] or deps['sha256']!=native['sha256']:
        raise ValueError('Changed effect native source')
    diagnostic=next(r for r in deps['references']if r['source']['sheet']=='EffectOperation' and r['field']=='EffectInfoId' and r['target']['sheet']=='Effect')
    raw=diagnostic['text'].encode('utf-16le');offset=diagnostic['offset']
    if data[offset:offset+len(raw)]!=raw:
        raise ValueError('Changed EffectOperation diagnostic')
    action_path=root/'code-clues/effect-action-semantics.json'
    action_semantics=verified_semantics(root,action_path.name,native,data,['actions'],'value_anchor')
    rule_path=root/'code-clues/effect-rule-semantics.json'
    rule_semantics=verified_semantics(root,rule_path.name,native,data,['buff_types','overlay_types'],'byte_anchor')
    time_path=root/'code-clues/effect-time-code.json'
    time_source=None
    if time_path.is_file():
        time_code=json.loads(time_path.read_text('utf-8'))
        if time_code['sha256']!=native['sha256'] or time_code['unit'] is not None or time_code['field_precedence_verified']:
            raise ValueError('Changed effect time evidence')
        for anchor in time_code['anchors']+time_code['literals']+time_code['leaf_code']:
            raw=bytes.fromhex(anchor['bytes']);offset=anchor['file_offset']
            if data[offset:offset+len(raw)]!=raw:raise ValueError('Changed effect time bytes')
        time_source=dict(file='code-clues/effect-time-code.json',sha256=hashlib.sha256(time_path.read_bytes()).hexdigest(),
                         unit=None,field_precedence_verified=False)
    enums={key:{str(r['value']):r for r in native['enums'][key]}for key in ['EOperationType','EEffectType']}
    effects=index_effects(load('Effect',92),load('EffectOperation',93),enums,action_semantics,rule_semantics)
    report=dict(sources=sources,native_source=dict(source=native['source'],sha256=native['sha256']),
        time_storage_source=time_source,
        effect_operation_diagnostic=diagnostic,verified_relation='EffectOperation.EffectInfoId = Effect.Id',
        action_semantics_source=dict(file='code-clues/effect-action-semantics.json',sha256=hashlib.sha256(action_path.read_bytes()).hexdigest(),
            relation=action_semantics['relation']) if action_semantics else None,
        rule_semantics_source=dict(file='code-clues/effect-rule-semantics.json',sha256=hashlib.sha256(rule_path.read_bytes()).hexdigest(),
            relations=rule_semantics['relations']) if rule_semantics else None,
        expiration_source_keys=dict(Counter(e['record'].get('ApplyEffectOnExpiration','')for e in effects.values())),
        candidate_relation='SkillOperation.OperationType=2001 and OperationParam1 = Effect.Id; native parameter role NOT verified',
        limitations=['Candidate matches are not established skill links.',
            'Duration, rates and operation parameters stay in source units.',
            'Expiration/nested actions are not traversed; server application unknown.'])
    return effects,report
