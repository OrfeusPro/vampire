const assert=require('node:assert/strict');
const layers=require('./atlas-map-layers.js');
const requested=[];
class ImageFixture{
 constructor(){this.complete=false;this.naturalWidth=0;this.onload=null;this.onerror=null;}
 set src(value){this.value=value;if(value)requested.push(this);}
 get src(){return this.value;}
 ready(){this.complete=true;this.naturalWidth=2048;this.onload?.();}
}
function canvas(){
 const operations=[];
 return {operations,drawImage:(...values)=>operations.push(['image',...values]),
  save:()=>operations.push(['save']),restore:()=>operations.push(['restore']),
  fillRect:(...values)=>operations.push(['cell',...values]),beginPath:()=>operations.push(['begin']),
  arc:(...values)=>operations.push(['arc',...values]),fillText:(...values)=>operations.push(['text',...values]),
  moveTo:(...values)=>operations.push(['move',...values]),lineTo:(...values)=>operations.push(['line',...values]),
  closePath:()=>operations.push(['close']),fill:()=>operations.push(['fill']),stroke:()=>operations.push(['stroke'])};
}
const projection={size:[10240,10240],world_bounds:[0,0,10240,10240]};
const source={tiles:Array.from({length:25},(_,i)=>({file:'tile-'+i+'.png',
 atlas_rect:[(i%5)*2048,Math.floor(i/5)*2048,(i%5+1)*2048,(Math.floor(i/5)+1)*2048]}))};
const preview={complete:true,naturalWidth:1024};
(async()=>{
 let draws=0;const painter=layers.create({requestDraw:()=>draws++,resolveUrl:file=>'/reference/'+file,ImageCtor:ImageFixture});
 let ctx=canvas();const view={x:5120,y:5120,s:.05},retained=JSON.stringify(view);
 let result=painter.background(ctx,preview,source,projection,view,1000,1000,1);
 assert.equal(result.detailed,false);assert.equal(requested.length,0);assert.equal(ctx.operations.length,1);
 result=painter.background(ctx,preview,source,projection,{...view,s:1},1000,1000,1);
 assert.equal(result.visible,1);assert.equal(result.loaded,0);assert.equal(requested.length,1);
 assert.equal(requested[0].src,'/reference/tile-12.png');assert.equal(draws,0);
 requested[0].ready();await Promise.resolve();assert.equal(draws,1);
 ctx=canvas();result=painter.background(ctx,preview,source,projection,{...view,s:1},1000,1000,1);
 assert.equal(result.loaded,1);assert.equal(requested.length,1);
 const tileImage=ctx.operations.at(-1);assert.equal(tileImage[0],'image');
 assert.deepEqual(tileImage.slice(2),[-524,-524,2048,2048]);
 assert.equal(JSON.stringify(view),retained); // Rendering never moves the camera.

 // Nonzero tile offsets are LTRB, not x/y/width/height.
 ctx=canvas();painter.background(ctx,preview,source,projection,{x:3072,y:5120,s:1},1000,1000,1);
 requested.at(-1).ready();await Promise.resolve();
 ctx=canvas();painter.background(ctx,preview,source,projection,{x:3072,y:5120,s:1},1000,1000,1);
 assert.deepEqual(ctx.operations.at(-1).slice(2),[-524,-524,2048,2048]);

 // Multiple synchronous image completions schedule one redraw.
 const start=requested.length;
 painter.background(canvas(),preview,source,projection,{x:4096,y:4096,s:1},200,200,1);
 const beforeDraws=draws;for(const image of requested.slice(start))image.ready();await Promise.resolve();
 assert.equal(draws,beforeDraws+1);

 // Sweep independent cells. Offscreen cached images are released at the soft limit.
 for(let i=0;i<20;i++)painter.background(canvas(),preview,source,projection,
  {x:(i%5+.5)*2048,y:(Math.floor(i/5)+.5)*2048,s:1},100,100,1);
 result=painter.background(canvas(),preview,source,projection,{x:9216,y:7168,s:1},100,100,1);
 assert.ok(result.cached<=10);assert.equal(requested[0].onload,null);

 // Failed files remain a known failure even when their offscreen image is evicted.
 let failures=0;const failing=layers.create({requestDraw:()=>failures++,ImageCtor:ImageFixture});
 const failureStart=requested.length;
 failing.background(canvas(),preview,source,projection,{x:1024,y:1024,s:1},100,100,1);
 requested.at(-1).onerror();await Promise.resolve();assert.equal(failures,1);
 for(let i=1;i<20;i++)failing.background(canvas(),preview,source,projection,
  {x:(i%5+.5)*2048,y:(Math.floor(i/5)+.5)*2048,s:1},100,100,1);
 const failureEnd=requested.length;
 failing.background(canvas(),preview,source,projection,{x:1024,y:1024,s:1},100,100,1);
 assert.equal(requested.length,failureEnd);assert.ok(failureEnd>failureStart);

 // Navigation retains old world-space culling and switches cells to polygons with zoom.
 const overlay={tiles:[{bounds:[-1,-1,1,1],vertices:[[-1,-1],[1,-1],[1,1]],polygons:[[0,1,2]]},
  {bounds:[-10,-10,10,10],vertices:[[-10,-10],[10,-10],[10,10]],polygons:[[0,1,2]]},
  {bounds:[1000,1000,1010,1010],vertices:[[1000,1000],[1010,1000],[1010,1010]],polygons:[[0,1,2]]}]};
 ctx=canvas();const navView={x:0,y:0,s:1},navCopy=JSON.stringify(navView);
 assert.equal(painter.navigation(ctx,overlay,navView,200,200),2);
 assert.equal(ctx.operations.filter(row=>row[0]==='cell').length,1);
 assert.equal(ctx.operations.filter(row=>row[0]==='fill').length,1);
 assert.equal(ctx.operations.at(0)[0],'save');assert.equal(ctx.operations.at(-1)[0],'restore');
 assert.equal(JSON.stringify(navView),navCopy);

 // Static NPC records are scoped to the selected world, culled and clustered.
 const npcData={schema:1,kind:'reference_atlas_points',runtime_visibility_verified:false,points:[
  {id:'a',type:'NpcSpawn',world_id:'10010',x:-10,y:-10,label:'Первый NPC'},
  {id:'b',type:'NpcSpawn',world_id:10010,x:-9,y:-9,label:'Второй NPC'},
  {id:'c',type:'NpcSpawn',world_id:'10010',x:50,y:50,label:'Одинокий NPC'},
  {id:'other',type:'NpcSpawn',world_id:'10011',x:50,y:50,label:'Другой мир'},
  {id:'far',type:'NpcSpawn',world_id:'10010',x:10000,y:10000,label:'Вне окна'}]};
 const npcBefore=JSON.stringify(npcData),npcView={x:0,y:0,s:1},npcViewBefore=JSON.stringify(npcView);
 ctx=canvas();assert.deepEqual(painter.points(ctx,npcData,npcView,200,200,{worldId:'10010'}),{visible:3,clusters:2});
 assert.equal(ctx.operations.filter(row=>row[0]==='arc').length,2);
 assert.deepEqual(ctx.operations.filter(row=>row[0]==='text').map(row=>row[1]),['2']);
 ctx=canvas();assert.deepEqual(painter.points(ctx,npcData,npcView,200,200,{worldId:10010,labels:true}),{visible:3,clusters:2});
 assert.deepEqual(ctx.operations.filter(row=>row[0]==='text').map(row=>row[1]),['2','Одинокий NPC']);
 ctx=canvas();assert.deepEqual(painter.points(ctx,npcData,npcView,200,200,{worldId:'10011',labels:true}),{visible:1,clusters:1});
 assert.equal(ctx.operations.find(row=>row[0]==='text')[1],'Другой мир');
 assert.equal(JSON.stringify(npcData),npcBefore);assert.equal(JSON.stringify(npcView),npcViewBefore);
 // Different semantic types never collapse into one NPC cluster; Areas retain individual keys.
 const allTypes=['NpcSpawn','Area','Waypoint','GadgetSpawn','WorldSpot','QuestTask'];
 const allPoints={schema:1,kind:'reference_atlas_points',runtime_visibility_verified:false,
  points:allTypes.map((type,index)=>({key:type+':'+index,id:String(index),type,world_id:'10010',x:0,y:0,label:type}))};
 allPoints.points.push({...allPoints.points[1],key:'Area:other',id:'other'});
 ctx=canvas();assert.deepEqual(painter.points(ctx,allPoints,npcView,200,200,{worldId:10010}),{visible:7,clusters:7});
 assert.equal(ctx.operations.filter(row=>row[0]==='arc').length,7);
 ctx=canvas();assert.deepEqual(painter.points(ctx,allPoints,npcView,200,200,{worldId:10010,types:new Set(['Area','QuestTask']),labels:new Set(['Area'])}),{visible:3,clusters:3});
 assert.deepEqual(ctx.operations.filter(row=>row[0]==='text').map(row=>row[1]),['Area','Area']);
 assert.deepEqual(painter.points(canvas(),allPoints,npcView,200,200,{worldId:10010,types:new Set()}),{visible:0,clusters:0});
 assert.throws(()=>painter.points(canvas(),allPoints,npcView,200,200,{worldId:10010,types:new Set(['Unknown'])}),/справочные слои/);
 assert.throws(()=>painter.points(canvas(),{...allPoints,points:Array(32769).fill(allPoints.points[0])},npcView,200,200,{worldId:10010}),/справочные слои/);
 for(const bad of [{...npcData,runtime_visibility_verified:true},{...npcData,kind:'live_npcs'},{...npcData,schema:2}]){
  assert.throws(()=>painter.points(canvas(),bad,npcView,200,200,{worldId:10010}),/справочные слои/);
 }

 // dispose detaches callbacks and ignores already queued completions.
 const pending=requested.find(image=>image.onload);assert.ok(pending);const callback=pending.onload;
 const finalDraws=draws;callback();painter.dispose();await Promise.resolve();assert.equal(draws,finalDraws);
 assert.equal(pending.onload,null);assert.equal(pending.onerror,null);callback();await Promise.resolve();assert.equal(draws,finalDraws);
 ctx=canvas();assert.equal(painter.navigation(ctx,overlay,navView,200,200),0);assert.equal(ctx.operations.length,0);
 assert.deepEqual(painter.points(ctx,npcData,npcView,200,200,{worldId:10010}),{visible:0,clusters:0});assert.equal(ctx.operations.length,0);
 failing.dispose();
 console.log('Shared atlas layers: visible detail tiles, LTRB, cache, errors, redraw isolation, navigation, six static point layers and disposal passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
