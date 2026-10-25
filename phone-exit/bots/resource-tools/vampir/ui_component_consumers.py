"""Index source-scoped nested class candidates and reverse consumers; never resolve runtime variants."""
from collections import defaultdict


def compile_consumers(graph):
    nodes=graph['nodes'];classes=defaultdict(lambda:dict(candidates=set(),consumers=set(),edges=[]))
    reverse=defaultdict(list)
    for key,node in sorted(nodes.items()):
        for edge in node['dependencies']:
            kind=edge['control']['type'];entry=classes[kind]
            entry['consumers'].add(node['resource_path'])
            ref=dict(consumer=key,resource_path=node['resource_path'],resource_id=node['resource_id'],
                control=edge['control'],candidates=edge['candidates'],status=edge['status'])
            entry['edges'].append(ref)
            for candidate in edge['candidates']:
                if candidate not in nodes:raise ValueError('Unknown component candidate: '+candidate)
                entry['candidates'].add(candidate)
                reverse[candidate].append(dict(consumer=key,control_export=edge['control']['export'],
                    control_sha256=edge['control']['sha256']))
    result={}
    for kind,entry in sorted(classes.items()):
        result[kind]=dict(candidate_variants=sorted(entry['candidates']),consumer_resources=sorted(entry['consumers']),
            consumer_resource_count=len(entry['consumers']),edges=entry['edges'],edge_count=len(entry['edges']),
            unresolved=not entry['candidates'],runtime_binding_verified=False)
    priority=sorted(result,key=lambda kind:(-result[kind]['consumer_resource_count'],-result[kind]['edge_count'],kind))
    return dict(schema=1,kind='source_scoped_component_consumers',classes=result,reverse_variants=dict(reverse),
        priority=priority,statistics=dict(classes=len(result),edges=sum(v['edge_count'] for v in result.values()),
            missing_classes=sum(v['unresolved'] for v in result.values())),
        limits=['Class matches and consumer priority are structural candidates, not active runtime bindings.',
            'Resources are counted once per class; historical variants and repeated controls remain separate edges.'])
