"""Read source-linked NPC rewards, without rolling loot or deriving percentages."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))


def filter_item_locations(source_rows,npcs,locations,world=None):
    npc_ids={r['npc_id'] for r in source_rows}
    if world is not None:
        npc_ids={nid for nid in npc_ids if any(s['WorldInfoId']==world for s in locations.get(nid,[]))}
    return dict(npc_sources=[r for r in source_rows if r['npc_id'] in npc_ids],
        npcs=[n for n in npcs if n['id'] in npc_ids],
        spawn_records={nid:[s for s in locations.get(nid,[]) if world is None or s['WorldInfoId']==world]
                       for nid in sorted(npc_ids)},world_filter=world,
        positions_status='Static client base coordinates; PositionGroupId and live spawn availability not resolved.',
        navigation_ready=False)


def query(root,npc=None,item=None,world=None):
    folder=root/'maps/loot';index=json.loads((folder/'index.json').read_text('utf-8'))
    def load(file,expected):
        data=(folder/file).read_bytes()
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Changed loot JSON: '+file)
        return json.loads(data)
    if world is not None and item is None and npc is None:return [n for n in index['npcs'] if world in n['world_ids']]
    catalog=index['files']['items'];items=load(catalog['file'],catalog['sha256'])
    if item is not None:
        spec=index['files']['item-origins'];origins=load(spec['file'],spec['sha256'])
        spec=index['files']['npc-locations'];locations=load(spec['file'],spec['sha256'])
        return dict(items[item],**filter_item_locations(origins.get(item,[]),index['npcs'],locations,world))
    if npc is not None:
        summary=next(n for n in index['npcs'] if n['id']==npc)
        if not summary['file']:return summary
        data=load(summary['file'],summary['sha256'])
        spec=index['files']['npc-locations'];locations=load(spec['file'],spec['sha256'])
        data['spawn_records']=[s for s in locations.get(npc,[]) if world is None or s['WorldInfoId']==world]
        data['world_filter']=world
        spec=index['files']['reward-groups'];groups=load(spec['file'],spec['sha256'])
        wanted={r['RewardParam'] for r in data['rewards'] if r['RewardType']=='12'}
        data['reward_groups']={g:groups.get(g,[]) for g in wanted}
        item_ids={r['Param'] for rows in data['reward_groups'].values() for r in rows if r['Type']=='1'}
        data['items']={i:items.get(i) for i in item_ids}
        return data
    return index['stats']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    choice=parser.add_mutually_exclusive_group();choice.add_argument('--npc');choice.add_argument('--item')
    parser.add_argument('--world',help='Filter NPC/item source locations by exact World.Id')
    args=parser.parse_args()
    try:print(json.dumps(query(args.root,args.npc,args.item,args.world),ensure_ascii=False,indent=2))
    except (KeyError,StopIteration,ValueError,OSError) as error:parser.exit(1,'Loot query failed: '+(str(error) or 'ID not found')+'\n')
