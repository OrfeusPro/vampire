import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readdir,rm} from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';
import {createBotErrors,ERROR_TTL} from '../src/bot-errors.js';

test('diagnostics store only selected fields and prune expired records without deleting unrelated files',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'bot-errors-'));const a=createBotErrors(root);
  try{
    await a.save({name:'phone',country:'HK'}, {error:'test_error',step:'test',settings:{secret:'never'},token:'never'},Buffer.from([255,216,255,217]).toString('base64'));
    const result=await a.list();assert.equal(result.records.length,1);assert.equal(result.records[0].error,'test_error');assert.equal(result.records[0].token,undefined);assert.equal(result.records[0].settings,undefined);
    const old=String(Date.now()-ERROR_TTL-1000)+'-'+'a'.repeat(16);await mkdir(path.join(a.directory,old));await writeFile(path.join(a.directory,'unrelated.txt'),'keep');
    const pending=String(Date.now())+'-'+'b'.repeat(16)+'.tmp';await mkdir(path.join(a.directory,pending));await a.prune(true);
    const names=await readdir(a.directory);assert(!names.includes(old));assert(names.includes('unrelated.txt'));assert(names.includes(pending));
    await assert.rejects(a.save({name:'phone'},{error:'bad'},Buffer.from('not a jpeg').toString('base64')));
  }finally{await rm(root,{recursive:true,force:true});}
});
test('diagnostic archive is capped at 100 newest records',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'bot-errors-cap-'));const a=createBotErrors(root);
  try{await mkdir(a.directory,{recursive:true});for(let i=0;i<103;i++){const dir=path.join(a.directory,String(Date.now()-i*10)+'-'+i.toString(16).padStart(16,'0'));await mkdir(dir);await writeFile(path.join(dir,'report.json'),'{}');}await a.prune(true);assert.equal((await readdir(a.directory)).length,100);}finally{await rm(root,{recursive:true,force:true});}
});
