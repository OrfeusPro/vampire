"""Build separate map workspace from verified extracted game HUD resources.

Original WBP controls/hierarchy/assets are evidenced; web layout is an adaptation,
not an execution of UMG bindings or a verified pixel-perfect runtime frame.
"""
import hashlib,importlib.util,json,shutil,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
COMPONENTS={'hud':1685,'menu':1709,'status':1749,'side':1789,'quick':1765,'minimap':2475}
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main(root=ROOT):
    reader=load('game_workspace_reader',HERE.parent/'rfnext/scan-pak.py')
    core=load('game_hud_core',HERE/'recover-pak-game-config.py')
    identity='b8ee52f76aecb1ecb7544de13a59e2355b7a32b44d1da1fb6426e650f17f9a04'
    directory_path=root/'resource-config-snapshots'/identity
    manifest_raw=(directory_path/'manifest.json').read_bytes();manifest=json.loads(manifest_raw)
    if sha(manifest_raw)!=identity:raise ValueError('HUD directory manifest changed')
    directory_raw=(directory_path/'directory.json').read_bytes();encoded=(directory_path/'encoded-entries.bin').read_bytes()
    if sha(directory_raw)!=manifest['directory_paths_file_sha256'] or sha(encoded)!=manifest['encoded_entries_file_sha256']:raise ValueError('HUD directory material changed')
    entries={r['path']:r for r in json.loads(directory_raw)['entries']}
    inspector=load('game_hud_exports',HERE/'inspect-ui.py')
    components={};archive=None;before=None
    for kind,entry in COMPONENTS.items():
        file=f'pakchunk500-Windows-{entry}.json';catalog_raw=(root/'ui-catalog'/file).read_bytes();catalog=json.loads(catalog_raw)
        package_raw=(root/'ui-layout-study'/file).read_bytes();package=json.loads(package_raw)
        path=Path(package['source']['path'])
        if archive is None:
            archive=path;before=(path.stat().st_size,path.stat().st_mtime_ns);archive_sha=sha(path.read_bytes())
            if archive_sha!=manifest['archive_sha256']:raise ValueError('HUD archive changed')
        if path!=archive:raise ValueError('Mixed HUD archives')
        actual=[];parts=[]
        with path.open('rb') as stream:
            resources=[p[:-7] for p in entries if p.endswith('/'+catalog['name']+'.uasset')]
            if len(resources)!=1:raise ValueError('Ambiguous named HUD resource '+catalog['name'])
            resource=resources[0]
            for suffix,expected in [('.uasset',package['asset_sha256']),('.uexp',package['body_sha256'])]:
                name=resource+suffix;position=entries[name]['encoded_entry_offset'];bits=struct.unpack_from('<I',encoded,position)[0]
                offset=struct.unpack_from('<I' if bits&(1<<31) else '<Q',encoded,position+4)[0]
                header=reader.header(stream,offset,manifest['main_index']['offset'])
                if not header or header['encrypted'] or header['usize']>4*1024*1024:raise ValueError('Unsupported HUD record')
                payload=reader.decode(stream,header);parts.append(payload)
                actual.append(dict(path=name,offset=offset,sha256=sha(payload),previous_sha256=expected,unchanged=sha(payload)==expected))
        current=inspector.exports(*parts,max_exports=10000);exports={r['index']:r for r in current['exports']}
        # Reuse slot geometry only when every serialized slot is identical.
        verified_slots=[];changed_slots=[]
        for slot in catalog['decoded_slots']:
            provenance=slot['provenance'];new=exports[provenance['slot_export']]
            if new['sha256']!=provenance['sha256']:changed_slots.append(dict(export=new['index'],sha256=new['sha256'],previous_sha256=provenance['sha256']))
            else:verified_slots.append(slot)
        verified_controls=[];missing_controls=[]
        for old in catalog['controls']:
            matches=[new for new in exports.values() if new['name']==old['name'] and new['type']==old['type']]
            if len(matches)!=1:missing_controls.append(dict(name=old['name'],type=old['type']));continue
            new=matches[0]
            verified_controls.append(dict(old,export=new['index'],sha256=new['sha256'],offset=new['offset'],size=new['size'],previous_sha256=old['sha256'],parent_chain_historical_only=True))
        components[kind]=dict(name=catalog['name'],catalog_file=file,catalog_sha256=sha(catalog_raw),
            package_sha256=sha(package_raw),resource_paths=catalog['resource_paths'],root=catalog['root_export'],
            controls=verified_controls,slots=verified_slots,missing_controls=missing_controls,changed_slots_not_reused=changed_slots,current_package_checks=actual)
    if (archive.stat().st_size,archive.stat().st_mtime_ns)!=before or sha(archive.read_bytes())!=archive_sha:raise ValueError('HUD archive changed during build')
    images_raw=(root/'archive-image-latest.json').read_bytes();images=json.loads(images_raw);menu_package=json.loads((root/'ui-layout-study'/components['menu']['catalog_file']).read_bytes())
    names=set(menu_package['names']);buttons=[]
    # Association is an explicit viewer mapping; package dependency proves only
    # that the resource belongs to this menu, not the runtime brush binding.
    for control,label,icon,target in [('ButtonCharacter','Персонаж','IMG_Flat_Character','../attributes/index.html'),
        ('ButtonSkill','Навыки','IMG_Flat_Skill','skills.html'),('ButtonCollection','Коллекции','IMG_Flat_ItemCollection','../collections/index.html'),
        ('ButtonQuest','Задания','IMG_Flat_Quest',None),('ButtonCraft','Создание','IMG_Flat_ItemCraft','../loot/items.html'),
        ('ButtonPet','Питомцы','IMG_Flat_Pet',None),('ButtonMail','Почта','IMG_Flat_Post',None),
        ('ButtonOptionSetting','Настройки','IMG_Flat_Setting',None)]:
        c=next(c for c in components['menu']['controls'] if c['name']==control)
        matches=[i for i in images if i['asset_path'].rsplit('/',1)[-1]==icon and i['asset_path'] in names]
        if len(matches)!=1:raise ValueError('Ambiguous or missing menu texture '+icon)
        image=matches[0]
        if sha((root/image['file']).read_bytes())!=image['sha256']:raise ValueError('Menu image changed')
        buttons.append(dict(control=control,export=c['export'],label=label,image=image,target=target,brush_binding_verified=False))
    out=root/'maps/atlas';out.mkdir(parents=True,exist_ok=True)
    proof=dict(source_archive=str(archive),source_archive_sha256=archive_sha,components=components,menu_buttons=buttons,
        image_catalog_sha256=sha(images_raw),builder_sha256=sha(Path(__file__).read_bytes()),
        source_directory_sha256=identity,
        limits=['Named current PAK exports checked against extracted controls. All reused slot bytes match; changed control bytes retained as current. Runtime visibility/DPI/animation not replayed.',
            'Web layout adapts WBP hierarchy/anchor regions; final pixel geometry and original brush bindings not proved.',
            'Catalogue links and map controls work locally. No game movement, purchases, combat, mail or settings commands sent.'])
    raw=json.dumps(proof,ensure_ascii=False,separators=(',',':')).encode();(out/'game-ui-resources.json').write_bytes(raw)
    (out/'game-ui-manifest.json').write_text(json.dumps(dict(file='game-ui-resources.json',sha256=sha(raw)),indent=2),'utf-8')
    template=(HERE/'world-map.html').read_text('utf-8')
    template=template.replace('<title>Vampir · большая карта Nocturne</title>','<title>Vampir · карта и интерфейс игры</title>')
    template=template.replace('</style>','</style><link rel="stylesheet" href="game-map-workspace.css">',1)
    template=template.replace('<script src="../catalog-nav.js"></script>','')
    template=template.replace('<main><aside>','<main><aside id="workspaceTools" aria-label="Инструменты карты" hidden>')
    template=template.replace('<script src="world-map.js?', '<script src="game-map-workspace.js"></script><script src="world-map.js?')
    (out/'workspace.html').write_text(template,'utf-8')
    for name in ['game-map-workspace.css','game-map-workspace.js']:shutil.copyfile(HERE/name,out/name)
    print(json.dumps(dict(output=str(out/'workspace.html'),components=len(components),buttons=len(buttons),source_archive_sha256=archive_sha,proof_sha256=sha(raw))))
    return proof
if __name__=='__main__':main()
