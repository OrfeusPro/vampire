import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {DiagnosticCapture,captureFilters} from '../src/diagnostic-capture.js';
import {readCapture,exportCapture} from '../src/capture-inspect.js';

async function fixture(t,limits={}){
  const root=await mkdtemp(join(tmpdir(),'phone-exit-capture-')),events=[];
  const capture=new DiagnosticCapture({root,onStatus:e=>events.push(e),limits});
  t.after(async()=>{await capture.stop();await rm(root,{recursive:true,force:true});});
  return {root,capture,events};
}
const filters=[{host:'game.example',port:12001}];
test('capture is off by default; exact host/port, offsets, export and no secret stdout metadata',async t=>{
  const {root,capture,events}=await fixture(t);
  assert.equal(capture.open('game.example',12001),null);assert.deepEqual(await readdir(root),[]);
  const id=await capture.start(filters);
  assert.equal(capture.open('other.example',12001),null);assert.equal(capture.open('game.example',443),null);
  const flow=capture.open('GAME.EXAMPLE.',12001),secret=Buffer.from('private-token-fixture\x00\xff','latin1');
  flow.record('c2s',secret.subarray(0,8));flow.record('c2s',secret.subarray(8));flow.record('s2c',Buffer.from([0,255,3]));flow.close();
  await capture.stop();flow.record('c2s',secret);
  const path=join(root,id,'traffic.jsonl'),result=await readCapture(path);
  assert.deepEqual(Buffer.concat(result.flows.get(1).c2s),secret);assert.equal(result.summary.bytes,secret.length+3);
  assert.equal(result.summary.finalized,true);assert.equal(result.summary.flows[0].closed,true);
  assert.ok(!JSON.stringify(events).includes('private-token'));assert.ok(!JSON.stringify(result.summary).includes('game.example'));
  await exportCapture(path);assert.deepEqual(await readFile(join(root,id,'streams','flow-01-c2s.bin')),secret);
  await assert.rejects(exportCapture(path));assert.equal(capture.open('game.example',12001),null);
  const next=await capture.start(filters);assert.notEqual(next,id);await capture.stop();
  assert.equal((await readCapture(join(root,next,'traffic.jsonl'))).summary.bytes,0);
});
test('byte, record, flow, file, queue and time limits stop observation and finalize bounded output',async t=>{
  for(const [limits,reason,action] of [
    [{maxBytes:2},'byte_limit',f=>f.record('c2s',Buffer.from('three'))],
    [{maxRecords:2},'record_limit',f=>f.record('c2s',Buffer.from('a'))],
    [{maxFlows:1},'flow_limit',(f,c)=>c.open('game.example',12001)],
    [{maxFileBytes:3000},'file_limit',f=>f.record('c2s',Buffer.alloc(1000))],
    [{maxPendingBytes:3000},'queue_limit',f=>f.record('c2s',Buffer.alloc(4000))],
    [{durationMs:20},'time_limit',async()=>new Promise(r=>setTimeout(r,40))]
  ])await t.test(reason,async t=>{
    const {root,capture}=await fixture(t,limits),id=await capture.start(filters),flow=capture.open('game.example',12001);
    await action(flow,capture);await capture.stop();assert.equal(capture.status().reason,reason);
    const result=await readCapture(join(root,id,'traffic.jsonl'));assert.equal(result.summary.reason,reason);
    assert.ok(result.summary.fileBytes<=limits.maxFileBytes||!limits.maxFileBytes);
  });
});
test('invalid filters and disk failure never enable recording or expose filesystem exception',async t=>{
  const {root,capture}=await fixture(t);
  for(const value of [[],null,[{host:'*',port:1}],[{host:'https://game.example',port:443}],[{host:'game.example',port:0}]])
    assert.throws(()=>captureFilters(value));
  await writeFile(join(root,'blocker'),'x');const broken=new DiagnosticCapture({root:join(root,'blocker','child')});
  await assert.rejects(broken.start(filters),/^Error: Cannot start local capture$/);
  assert.equal(broken.open('game.example',12001),null);assert.equal(broken.status().state,'failed');
  await assert.rejects(capture.start([]));assert.deepEqual(await readdir(root),['blocker']);
});
test('offline reader rejects altered offsets and truncated files',async t=>{
  const {root,capture}=await fixture(t),id=await capture.start(filters),f=capture.open('game.example',12001);
  f.record('c2s',Buffer.from([1,2,3]));await capture.stop();
  const path=join(root,id,'traffic.jsonl'),text=await readFile(path,'utf8');
  await writeFile(path,text.replace('"offset":0','"offset":1'));await assert.rejects(readCapture(path));
  await writeFile(path,text.slice(0,-1));await assert.rejects(readCapture(path));
});
test('write failure disables observation without exposing the raw disk error',async t=>{
  const {capture,events}=await fixture(t);await capture.start(filters);
  const flow=capture.open('game.example',12001),session=capture.current;
  session.stream.destroy(Error('private-filesystem-error-fixture'));
  await session.done.catch(()=>{});await capture.stop();
  assert.equal(capture.status().state,'failed');assert.equal(capture.status().reason,'io_error');
  assert.doesNotThrow(()=>flow.record('c2s',Buffer.from('still-forwardable')));
  assert.ok(!JSON.stringify(events).includes('private-filesystem'));
});


test('all TCP requires explicit mode, includes unknown hosts and ports, and reads beyond legacy caps',async t=>{
  const {root,capture,events}=await fixture(t);
  await assert.rejects(capture.start());
  await assert.rejects(capture.start([], {mode:'invalid'}));
  await assert.rejects(capture.start(filters, {mode:'all-tcp'}));
  assert.deepEqual(await readdir(root),[]);
  const id=await capture.start(undefined,{mode:'all-tcp'});
  assert.equal(capture.status().mode,'all-tcp');
  assert.ok(capture.status().remainingMs<=180000&&capture.status().remainingMs>179000);
  for(let i=1;i<=20;i++){
    const flow=capture.open(`unknown-${i}.example`,i%2?443:12000);
    assert.ok(flow);flow.record('c2s',Buffer.from([i]));flow.close();
  }
  const flow=capture.open('192.0.2.1',80),chunk=Buffer.alloc(65536,7);
  for(let i=0;i<129;i++){
    flow.record('s2c',chunk);
    // Keep this test about total volume rather than the independent disk queue limit.
    if(capture.current.stream.writableNeedDrain)await new Promise(r=>capture.current.stream.once('drain',r));
  }
  flow.close();await capture.stop();
  const path=join(root,id,'traffic.jsonl'),result=await readCapture(path);
  assert.equal(result.summary.mode,'all-tcp');assert.equal(result.flows.size,21);
  assert.equal(result.summary.bytes,129*chunk.length+20);
  assert.equal(result.summary.finalized,true);
  assert.ok(!JSON.stringify(events).includes('unknown-'));
  const header=JSON.parse((await readFile(path,'utf8')).split('\n')[0]);
  assert.deepEqual(header.filters,[]);assert.equal(header.limits.maxBytes,33554432);
  assert.equal(header.limits.maxFlows,1024);assert.equal(header.limits.durationMs,180000);
  // A larger file cannot masquerade as a legacy capture.
  const raw=await readFile(path,'utf8');await writeFile(path,raw.replace('"mode":"all-tcp"','"mode":"endpoints"'));
  await assert.rejects(readCapture(path));
  await capture.start(filters);assert.equal(capture.open('unknown-1.example',443),null);
});

test('all TCP auto-stops on deadline and cannot resume recording through an old observer',async t=>{
  const {root,capture}=await fixture(t,{durationMs:20});
  const id=await capture.start(undefined,{mode:'all-tcp'}),flow=capture.open('auth.example',443);
  flow.record('c2s',Buffer.from([1]));
  await new Promise(r=>setTimeout(r,50));await capture.stop();
  flow.record('c2s',Buffer.from([2]));assert.equal(capture.open('auth.example',443),null);
  const result=await readCapture(join(root,id,'traffic.jsonl'));
  assert.equal(result.summary.reason,'time_limit');assert.equal(result.summary.bytes,1);
  await capture.start(undefined,{mode:'all-tcp'});flow.record('c2s',Buffer.from([3]));
  await capture.stop();assert.equal(capture.status().bytes,0);
});


test('launcher burst beyond 128 flows stays captured; hard limit stops the 1025th flow',async t=>{
  const {root,capture}=await fixture(t);
  const id=await capture.start(undefined,{mode:'all-tcp'});
  for(let i=0;i<1024;i++){
    const flow=capture.open('launcher.example',443);assert.ok(flow);flow.close();
  }
  assert.equal(capture.status().state,'active');
  assert.equal(capture.open('launcher.example',443),null);await capture.stop();
  const result=await readCapture(join(root,id,'traffic.jsonl'));
  assert.equal(result.summary.reason,'flow_limit');assert.equal(result.flows.size,1024);
});
