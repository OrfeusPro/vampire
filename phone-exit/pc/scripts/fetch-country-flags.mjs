import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const revision='b6b55fef1e8636b540a6d016a4729ca8cdf2e60b'; // Twemoji v17.0.3
const root=fileURLToPath(new URL('../assets/flags/',import.meta.url));
await fs.mkdir(root,{recursive:true});
const response=await fetch(`https://api.github.com/repos/jdecked/twemoji/git/trees/${revision}?recursive=1`,{headers:{'User-Agent':'PhoneExit-build'}});
if(!response.ok)throw Error('Flag catalog unavailable');
const tree=await response.json();if(tree.truncated)throw Error('Incomplete flag catalog');
const files=tree.tree.filter(f=>/^assets\/72x72\/1f1[e-f][0-9a-f]-1f1[e-f][0-9a-f]\.png$/.test(f.path));
const names={},display=new Intl.DisplayNames(['ru'],{type:'region'});
const tasks=files.map(f=>{
 const code=f.path.split('/').at(-1).slice(0,-4).split('-').map(h=>String.fromCharCode(65+parseInt(h,16)-0x1f1e6)).join('');
 if(!/^[A-Z]{2}$/.test(code))throw Error('Unexpected region code');
 names[code]=display.of(code);return {source:f.path,name:code+'.png'};
});
tasks.push({source:'assets/72x72/1f310.png',name:'unknown.png'},{source:'LICENSE-GRAPHICS',name:'LICENSE-GRAPHICS'});
let index=0;
await Promise.all(Array.from({length:8},async()=>{
 while(index<tasks.length){
  const task=tasks[index++];const result=await fetch(`https://raw.githubusercontent.com/jdecked/twemoji/${revision}/${task.source}`);
  if(!result.ok)throw Error('Flag asset unavailable: '+task.name);
  const bytes=Buffer.from(await result.arrayBuffer());
  if(task.name.endsWith('.png') && bytes.subarray(0,8).toString('hex')!=='89504e470d0a1a0a')throw Error('Invalid flag asset');
  await fs.writeFile(root+task.name,bytes);
 }
}));
await fs.writeFile(root+'countries-ru.json',JSON.stringify(names,null,2)+'\n');
await fs.writeFile(root+'README.md',`Country flags: Twemoji v17.0.3, unmodified PNG artwork.\nCopyright Twitter, Inc. and other contributors.\nGraphics license: CC-BY 4.0, see LICENSE-GRAPHICS.\nSource: https://github.com/jdecked/twemoji/tree/${revision}/assets/72x72\nLicense: https://creativecommons.org/licenses/by/4.0/\nLocal assets are used offline; the running app makes no flag-download requests.\n`);
console.log(`Downloaded ${files.length} region flags and Russian country names.`);
