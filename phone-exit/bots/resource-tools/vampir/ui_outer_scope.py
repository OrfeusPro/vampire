"""Partition serialized exports by their Outer owner, without selecting a runtime root."""
import copy


def compile_ownership(exports):
    rows={row['index']:row for row in exports}
    if len(rows)!=len(exports):raise ValueError('Duplicate export identity')
    roots={i for i,row in rows.items() if row['type']=='WidgetBlueprintGeneratedClass'}
    ownership,issues={},[]
    for index,row in sorted(rows.items()):
        chain,seen,current=[],set(),index
        owner=None;state='unowned'
        while current:
            if current in seen:
                state='outer_cycle';break
            seen.add(current)
            if current not in rows:
                state='dangling_outer';break
            chain.append(current)
            if current in roots:
                owner=current;state='source_root_owned';break
            current=rows[current]['outer']
        ownership[str(index)]=dict(export=index,name=row['name'],kind=row['type'],sha256=row['sha256'],
            outer=row['outer'],chain=chain,owner_root=owner,state=state)
        if state in ('outer_cycle','dangling_outer'):
            issues.append(dict(export=index,code=state,chain=chain,unresolved_reference=current))
    return dict(schema=1,kind='serialized_outer_ownership',roots={str(i):dict(export=i,name=rows[i]['name'],
        sha256=rows[i]['sha256'],members=[j for j in sorted(rows) if ownership[str(j)]['owner_root']==i]) for i in sorted(roots)},
        exports=ownership,issues=issues,runtime_visible_root=None,
        limits=['Outer ownership is source containment, not widget parent geometry or runtime visibility.',
            'Unowned exports are not assigned by name, class pointer, CDO prefix or a single available root.'])


def partition(catalog,ownership):
    root=catalog['root_export'];selected=root['index']
    if str(selected) not in ownership['roots'] or ownership['roots'][str(selected)]['sha256']!=root['sha256']:
        raise ValueError('Selected catalog root differs from source')
    groups={kind:{state:[] for state in ('selected','foreign','unowned','unresolved')} for kind in ('controls','decoded_slots','excluded_slots')}
    cross=[]
    for kind in groups:
        for row in catalog[kind]:
            index=row['export'] if kind=='controls' else row['provenance']['slot_export']
            source=ownership['exports'][str(index)]
            expected=row['sha256'] if kind=='controls' else row['provenance']['sha256']
            if source['sha256']!=expected:raise ValueError('Catalog export differs from Outer source')
            state='unresolved' if source['state'] in ('outer_cycle','dangling_outer') else 'unowned' if source['owner_root'] is None else 'selected' if source['owner_root']==selected else 'foreign'
            groups[kind][state].append(index)
            if kind=='decoded_slots':
                d=row['decoded'];endpoints={}
                for role in ('parent','content'):
                    target=d[role+'_export'];target_scope=ownership['exports'].get(str(target))
                    endpoints[role]=dict(export=target,owner_root=target_scope['owner_root'] if target_scope else None,
                        state=target_scope['state'] if target_scope else 'missing_export')
                endpoint_roots={e['owner_root'] for e in endpoints.values()}
                if endpoint_roots!={source['owner_root']} or any(e['state']!='source_root_owned' for e in endpoints.values()):
                    cross.append(dict(slot=index,slot_owner_root=source['owner_root'],endpoints=endpoints,
                        status='requires_scope_review_not_invalidated_automatically'))
    for group in groups.values():
        for state in group:group[state].sort()
    return dict(schema=1,kind='catalog_source_root_partition',selected_source_root=selected,
        source_root_name=root['name'],groups=groups,cross_scope_relations=cross,
        ownership_issues=copy.deepcopy(ownership['issues']),runtime_visible_root=None,
        geometry_verified=False,implementation_verified=False,
        unknowns=['runtime_visible_root','archetype_and_inheritance','widget_parent_slot_semantics',
            'dynamic_creation_and_binding','visibility_and_geometry'],
        limits=['This partition does not mutate the whole-package catalog or select an active runtime branch.',
            'Outer, decoded Parent/Content and runtime widget attachment are separate relations.'])


def project_variant(variant,view):
    """Explicit source-root projection; quarantine remains visible and runtime use stays unverified."""
    result=copy.deepcopy(variant)
    for field,category in [('controls','controls'),('slots','decoded_slots'),('excluded_slots','excluded_slots')]:
        selected=set(view['groups'][category]['selected'])
        result[field]=[row for row in variant[field] if
            (row['export'] if field=='controls' else row['provenance']['slot_export']) in selected]
    quarantine={kind:{state:values for state,values in groups.items() if state!='selected' and values}
        for kind,groups in view['groups'].items()}
    quarantine={k:v for k,v in quarantine.items() if v}
    return result,dict(selected_source_root=view['selected_source_root'],quarantine=quarantine,
        cross_scope_relations=copy.deepcopy(view['cross_scope_relations']),
        runtime_visible_root=None,geometry_verified=False,implementation_verified=False,
        requires_review=bool(quarantine or view['cross_scope_relations'] or view['ownership_issues']))
