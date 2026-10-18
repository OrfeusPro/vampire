const {test}=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/nav-overlay-model.js');
const tile={bounds:[0,0,1000,1000],vertices:[[0,0],[1000,0],[0,1000]],polygons:[[0,1,2]]};
test('viewport clipping follows the same world axes at different zooms',()=>{
  const far={...tile,bounds:[2000,2000,3000,3000]};
  assert.deepEqual(model.visible([tile,far],{x:500,y:500,s:1},1000,1000),[tile]);
  assert.equal(model.visible([tile,far],{x:1500,y:1500,s:.1},1000,1000).length,2);
  assert.equal(model.detailed(tile,.001),false);assert.equal(model.detailed(tile,.01),true);
});
test('geometry validation rejects bad indices and nonfinite coordinates',()=>{
  const data={schema_version:1,coordinate_space:'world_xy',navigation_ready:false,tiles:[tile]};
  assert.equal(model.validate(data),data);
  for(const change of [{...tile,polygons:[[0,1,3]]},{...tile,vertices:[[NaN,0]]},{...tile,bounds:[1000,0,0,1000]}])assert.throws(()=>model.validate({...data,tiles:[change]}));
});
test('the research layer cannot silently declare navigation ready',()=>{
  assert.throws(()=>model.validate({schema_version:1,coordinate_space:'world_xy',navigation_ready:true,tiles:[tile]}));
});
test('special-link hit testing follows the displayed segment at zoom and handles vertical-only links',()=>{
  const a={start:[0,0,0],end:[100,0,100]},b={start:[0,100,0],end:[0,100,200]};
  const view={x:0,y:0,s:2};assert.equal(model.nearestSpecial([a,b],view,200,200,200,105),a);
  assert.equal(model.nearestSpecial([a,b],view,200,200,100,300),b);
  assert.equal(model.nearestSpecial([a,b],view,200,200,50,150),null);
});
test('special endpoint validation rejects invalid coordinates and unproven readiness',()=>{
  const p={id:'one',start:[0,0,0],end:[1,2,3],baked_start:[0,0,0],baked_end:[1,2,3],attachment_verified:false};
  const data={schema_version:1,coordinate_space:'world_xy',navigation_ready:false,tiles:[tile],special_links:[p]};
  assert.equal(model.validate(data),data);
  assert.throws(()=>model.validate({...data,special_links:[{...p,attachment_verified:true}]}));
  assert.throws(()=>model.validate({...data,special_links:[{...p,end:[1,2,NaN]}]}));
});
test('surface candidates cannot claim attachment or matched points without a candidate',()=>{
  const check={start_found:true,start_matches_baked:true,end_candidate_count:1,end_matches_baked:true,attachment_verified:false,bv_disabled:true};
  const p={id:'one',start:[0,0,0],end:[1,2,3],baked_start:[0,0,0],baked_end:[1,2,3],attachment_verified:false,surface_candidate_check:check};
  const data={schema_version:1,coordinate_space:'world_xy',navigation_ready:false,tiles:[tile],special_links:[p]};
  assert.equal(model.validate(data),data);
  for(const change of [{attachment_verified:true},{start_found:false},{end_candidate_count:0},{end_candidate_count:-1},{bv_disabled:false}])assert.throws(()=>model.validate({...data,special_links:[{...p,surface_candidate_check:{...check,...change}}]}));
});
test('native attachment scenarios do not become runtime evidence',()=>{
  const check={connected:true,matches_baked:true,runtime_verified:false};
  const p={id:'one',start:[0,0,0],end:[1,2,3],baked_start:[0,0,0],baked_end:[1,2,3],attachment_verified:false,native_attachment_scenario:check};
  const data={schema_version:1,coordinate_space:'world_xy',navigation_ready:false,tiles:[tile],special_links:[p]};
  assert.equal(model.validate(data),data);
  for(const change of [{runtime_verified:true},{connected:false}])assert.throws(()=>model.validate({...data,special_links:[{...p,native_attachment_scenario:{...check,...change}}]}));
});
test('filter application cannot claim active selection or costs ignored by exclusion',()=>{
  const data={schema_version:1,coordinate_space:'world_xy',navigation_ready:false,tiles:[tile],navigation_filter_application_evidence:{runtime_selection_verified:false}};
  const preset={runtime_verified:false,areas:[{}],application_check:[{area_id:12,travel_written:1}]};
  assert.equal(model.validate({...data,navigation_filter_presets:[preset]}).navigation_ready,false);
  assert.throws(()=>model.validate({...data,navigation_filter_application_evidence:{runtime_selection_verified:true}}));
  for(const effect of [{travel_written:.5},{entering_written:-1},{excluded:true,travel_written:1}])assert.throws(()=>model.validate({...data,navigation_filter_presets:[{...preset,application_check:[effect]}]}));
});
