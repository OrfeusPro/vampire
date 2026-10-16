"""Reproduce reviewed Tutorial4007 observations, retaining source-frame hashes."""
import cv2,hashlib,json,shutil
from pathlib import Path
MODULE=Path(__file__).resolve().parents[2]/'vampir'
LIB=Path('F:/PhoneExit Resources/Vampir')
FOLDER=LIB/'phone-tests/tutorial4007-2026-10-16'
FOLDER.mkdir(parents=True,exist_ok=True)
CONFIG=MODULE/'vision.json'
v=json.loads(CONFIG.read_text('utf-8'))
records=[]
specs=[
 ('equipment','vampir-enhance-next.jpg','tutorial_enhance_select',[601,274,896,295],[.4,.25,.8,.5],'enhance_selected_corner',[955,138,973,156],[.65,.1,.95,.35],'4007007','Inventory_EnchantItem',{'width':18,'offset':[29,29],'point_region':[.68,.1,.95,.35]}),
 ('info','vampir-enhance-info.jpg','tutorial_enhance_open',[311,374,609,469],[.15,.4,.55,.75],'enhance_info_button',[677,548,746,575],[.45,.65,.7,.9],'4007009','ItemInfoPopup_Enchant',{}),
 ('material','vampir-enhance-material.jpg','tutorial_enhance_material',[206,435,520,503],[.1,.5,.5,.8],'enhance_material_corner',[90,570,109,589],[.04,.7,.2,.9],'4007011','ItemEnchant_MaterialSlot',{'width':19,'offset':[17,17],'point_region':[.04,.7,.2,.9]}),
 ('attempt','vampir-enhance-attempt.jpg','tutorial_enhance_attempt',[512,485,853,577],[.3,.55,.75,.88],'enhance_attempt_button',[214,651,446,695],[.1,.85,.4,1],'4007012','ItemEnchant_Enchant',{'max_attempts':1,'required_templates':['enhance_safe_range','enhance_plus_one']})]
for label,filename,prompt,pcrop,pregion,target,tcrop,tregion,step,key,extra in specs:
 source=FOLDER/(label+'.jpg')
 if not source.exists():shutil.copyfile(Path('phone-exit/.tools')/filename,source)
 image=cv2.imread(str(source));record={'step':step,'source':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'templates':[]}
 for name,crop,region in [(prompt,pcrop,pregion),(target,tcrop,tregion)]:
  for suffix,f in [('',1),('_compact',.75),('_large',1.25)]:
   scaled=cv2.resize(image,None,fx=f,fy=f);box=[round(n*f) for n in crop];l,t,r,b=box;full=name+suffix;file=MODULE/'templates'/(full+'.png');cv2.imwrite(str(file),scaled[t:b,l:r]);v['templates'][full]={'file':file.name,'threshold':.94,'region':region,'scales':[.95,1,1.05],'reference_size':[scaled.shape[1],scaled.shape[0]]};record['templates'].append({'name':full,'crop':box,'factor':f,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
  v['match_alternatives'][name]=[name+'_compact',name+'_large']
 action={'prompt':prompt,'target':target,'step':'quest_'+prompt,**extra}
 v['tutorial_actions']=[a for a in v['tutorial_actions'] if a['prompt']!=prompt]+[action];records.append(record)
# Irreversible attempt additionally requires the observed safe +1 configuration.
image=cv2.imread(str(FOLDER/'attempt.jpg'))
for name,crop,region in [('enhance_safe_range',[156,600,353,619],[.05,.75,.4,.9]),('enhance_plus_one',[91,462,142,498],[.04,.55,.2,.75])]:
 for suffix,f in [('',1),('_compact',.75),('_large',1.25)]:
  scaled=cv2.resize(image,None,fx=f,fy=f);l,t,r,b=[round(n*f) for n in crop];full=name+suffix;file=MODULE/'templates'/(full+'.png');cv2.imwrite(str(file),scaled[t:b,l:r]);v['templates'][full]={'file':file.name,'threshold':.94,'region':region,'scales':[.95,1,1.05],'reference_size':[scaled.shape[1],scaled.shape[0]]}
 v['match_alternatives'][name]=[name+'_compact',name+'_large']
CONFIG.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n','utf-8')
(MODULE/'enhancement-observations.json').write_text(json.dumps({'records':records,'scope':'Observed tutorial prompts and controls; no character or item image detector'},ensure_ascii=False,indent=2)+'\n','utf-8')
print('4 source-linked tutorial observations rebuilt')
