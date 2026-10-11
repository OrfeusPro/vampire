import test from 'node:test';
import assert from 'node:assert/strict';
import {downloadProbeResult} from '../src/download-probe.js';
test('phone benchmark accepts only correlated bounded aggregate results',()=>{
  const id='0123456789abcdef',valid={type:'download-probe',id,bytes:5000000,elapsedMs:1000,success:true};
  assert.equal(downloadProbeResult(valid,id).bytesPerSecond,5000000);
  for(const patch of [{id:'other'},{bytes:5000001},{bytes:-1},{bytes:0},{elapsedMs:0},{elapsedMs:65001},{elapsedMs:NaN},{success:'true'}])assert.equal(downloadProbeResult({...valid,...patch},id),null);
  assert.equal(downloadProbeResult({...valid,bytes:123,success:false},id).success,false);
  assert.equal(downloadProbeResult({...valid,type:'upload-probe'},id,'upload-probe').bytesPerSecond,5000000);
  assert.equal(downloadProbeResult({...valid,type:'upload-probe'},id),null);
});
