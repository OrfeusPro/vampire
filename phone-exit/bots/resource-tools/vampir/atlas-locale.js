/* Presentation localization. Source bytes are verified by each data loader first. */
(function(root){
  'use strict';
  const displayKey=/^(?:name|names?|label|title|text|description|desc.*|.*(?:Name|Names|Label|Text|Description|Desc))$/i;
  const rawKeys=new Set(['data','record','row','raw','source','sources','provenance','fragments','instructions']);
  function translator(texts){
    const templateRules=Object.entries(texts).filter(([key])=>/\{ReplaceString[12]\}/.test(key)).map(([key,value])=>{
      const tokens=[];const escaped=key.split(/(\{ReplaceString[12]\})/).map(part=>{
        if(/^\{ReplaceString[12]\}$/.test(part)){tokens.push(part);return '(.*?)';}
        return part.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      }).join('');return {pattern:new RegExp('^'+escaped+'$'),tokens,value};
    });
    function text(value){
      if(Object.hasOwn(texts,value))return texts[value];
      if(!value||/^\d+$/.test(value))return value;
      for(const rule of templateRules){const match=rule.pattern.exec(value);if(match){let out=rule.value;rule.tokens.forEach((token,i)=>{out=out.split(token).join(match[i+1]);});return out;}}
      for(const separator of [' / ',' · ',' — '])if(value.includes(separator))return value.split(separator).map(part=>Object.hasOwn(texts,part)?texts[part]:part).join(separator);
      return value;
    }
    function visit(value,key='',blocked=false){
      if(blocked)return value;
      if(typeof value==='string')return displayKey.test(key)?text(value):value;
      if(Array.isArray(value))return value.map(item=>visit(item,key));
      if(value&&typeof value==='object'){
        const out={};for(const [child,item]of Object.entries(value))out[child]=visit(item,child,rawKeys.has(child)||child.endsWith('_source'));return out;
      }
      return value;
    }
    return {text,localize:visit};
  }
  if(typeof module!=='undefined'&&module.exports){module.exports={translator};return;}
  const base=new URL('./',document.currentScript.src);let ready;
  async function load(){
    if(!ready)ready=(async()=>{
      const manifestResponse=await fetch(new URL('locale-ru-manifest.json',base),{cache:'no-cache'});
      if(!manifestResponse.ok)throw Error('Не загружен манифест русского языка');
      const spec=await manifestResponse.json();
      if(spec.language!=='ru'||spec.file!=='locale-ru.json'||!/^[a-f0-9]{64}$/.test(spec.sha256))throw Error('Неверный манифест русского языка');
      const response=await fetch(new URL(spec.file,base),{cache:'no-cache'});if(!response.ok)throw Error('Не загружен русский словарь');
      const bytes=await response.arrayBuffer();const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
      if(actual!==spec.sha256)throw Error('Изменился SHA256 русского словаря');
      const data=JSON.parse(new TextDecoder().decode(bytes));if(data.language!=='ru')throw Error('Неверный язык словаря');
      document.documentElement.lang='ru';return translator(data.texts);
    })().catch(error=>{console.error(error);const warning=document.createElement('p');warning.setAttribute('role','status');warning.textContent=error.message+' — показаны исходные названия.';document.querySelector('header')?.append(warning);return translator({});});
    return ready;
  }
  root.AtlasLocale={async localize(value){return (await load()).localize(value);}};
})(typeof window==='undefined'?globalThis:window);
