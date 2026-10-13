// The private signing key is supplied through stdin by build-bot-package.ps1.
import {createHash,createPrivateKey,sign} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import path from 'node:path';
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){
  const config=JSON.parse(line.replace(/^\uFEFF/,''));lines.close();
  const root=path.resolve(import.meta.dirname,'..'),dir=path.join(root,'bots',config.bot);
  if(!/^[a-z][a-z0-9_-]{0,40}$/.test(config.bot))throw Error('Invalid bot');
  const manifest=JSON.parse(await readFile(path.join(dir,'manifest.json'),'utf8'));
  const dest=path.join(root,'.tools','bot-release');await mkdir(dest,{recursive:true});
  const zip=path.join(dest,`${manifest.id}-${manifest.version}.zip`);
  const result=spawnSync('python',['-c',`import sys,zipfile,pathlib
src=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2])
with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p in sorted(src.rglob('*')):
  if p.is_file() and '__pycache__' not in p.parts:
   i=zipfile.ZipInfo(p.relative_to(src).as_posix(),(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED
   z.writestr(i,p.read_bytes())
`,dir,zip],{encoding:'utf8'});
  if(result.status!==0)throw Error('Package build failed');
  const bytes=await readFile(zip),sha256=createHash('sha256').update(bytes).digest('hex');
  if(bytes.length>60000000)throw Error('Package too large');
  const payload=JSON.stringify({id:manifest.id,version:manifest.version,engineVersion:manifest.engineVersion,
    settingsVersion:manifest.settingsVersion,sha256,size:bytes.length});
  const signature=sign('sha256',Buffer.from(payload),createPrivateKey({key:Buffer.from(config.privateKey,'base64'),format:'der',type:'pkcs8'})).toString('base64');
  await writeFile(zip+'.json',JSON.stringify({payload,signature},null,2));
  console.log(`Built signed ${manifest.id} ${manifest.version}: ${bytes.length} bytes`);break;
}
