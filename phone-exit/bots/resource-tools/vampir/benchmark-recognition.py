"""Compare real bot match calls on saved frames; no device commands."""
import importlib.util,json,time
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('replay',HERE/'replay-shop.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
BASE=HERE.parents[2]/'.tools/vampir-recognition-before'
frames=Path('F:/PhoneExit Resources/Vampir/phone-tests/tutorial4007-2026-10-16')
results=[]
for label in ('equipment','info','material','attempt'):
 image=r.cv2.imread(str(frames/(label+'.jpg')))
 for version,directory in [('before',BASE),('after',r.MODULE)]:
  bot=r.load('bench_'+label+version,directory/'bot.py');host=r.ReplayHost(directory);state={};observed=[]
  original=host.call;counts={'match':0}
  def call(command,**args):
   if command=='match':counts['match']+=1
   return original(command,**args)
  host.call=call
  for n in range(2):
   host.capture(image,label);counts['match']=0;start=time.perf_counter()
   with patch.object(bot.time,'monotonic',return_value=1000+n*9):
    result=bot.tick(host,{'quest_enabled':True,'autostart_enabled':True,'quest_shop_enabled':False},state,str(directory))
   observed.append({'match_calls':counts['match'],'ms':round((time.perf_counter()-start)*1000),'step':result['step'],'error':result.get('error')})
  results.append({'frame':label,'version':version,'observations':observed})
report={'scope':'Desktop OpenCV; wall time is not Android measurement','results':results}
(frames/'recognition-benchmark.json').write_text(json.dumps(report,indent=2)+'\n','utf-8')
print(json.dumps(report))
