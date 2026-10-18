"""Query the offline atlas; output source rows, never click coordinates."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def query(root, world_id=None, spot_id=None, quest_id=None):
    root = root / 'maps/atlas'
    index = json.loads((root / 'index.json').read_text('utf-8'))
    if world_id is not None:
        item = next(w for w in index['worlds'] if w['id'] == world_id)
        data = (root / item['file']).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('World JSON hash mismatch')
        return json.loads(data)
    if spot_id is None and quest_id is None:
        return {k: index[k] for k in ['counts', 'worlds', 'issues', 'navigation_ready', 'limitations']}
    raw = (root / 'tables.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != index['tables_sha256']:
        raise ValueError('Tables JSON hash mismatch')
    tables = json.loads(raw)
    if spot_id is not None:
        spot = next(s for s in tables['WorldSpot'] if s['Id'] == spot_id)
        return dict(spot=spot, world=query(root.parent.parent, world_id=spot['WorldInfoId'])['world'],
                    tasks=[t for t in tables['QuestTask'] if t['TargetSpotInfoId'] == spot_id])
    if quest_id is not None:
        spots = {s['Id']: s for s in tables['WorldSpot']}
        areas = {s['Id']: s for s in tables['Area']}
        return dict(quest_id=quest_id, tasks=[dict(t, target_spot=spots.get(t['TargetSpotInfoId']),
            target_area=areas.get(t['AreaInfoId'])) for t in tables['QuestTask'] if t['QuestInfoId'] == quest_id])
    return {k: index[k] for k in ['counts', 'worlds', 'issues', 'navigation_ready', 'limitations']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--world')
    choice.add_argument('--spot')
    choice.add_argument('--quest')
    args = parser.parse_args()
    try:
        print(json.dumps(query(args.root, args.world, args.spot, args.quest), ensure_ascii=False, indent=2))
    except (StopIteration, ValueError, OSError) as error:
        parser.exit(1, 'Atlas query failed: ' + (str(error) or 'ID not found') + '\n')
