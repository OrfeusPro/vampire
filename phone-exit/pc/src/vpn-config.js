import net from 'node:net';
import path from 'node:path';
// Control-plane host routes preserve the already-established WebRTC transport.
export function vpnConfig({mode='all',applications=[],applicationRuleFile,physicalInterface,transportAddresses=[],nodePath=process.execPath}={}) {
  if(!['all','apps'].includes(mode))throw Error('Invalid mode');
  if(mode==='apps'&&(!applications.length||applications.length>64))throw Error('Select applications');
  if(applications.some(p=>typeof p!=='string'||!path.win32.isAbsolute(p)||!p.toLowerCase().endsWith('.exe')))throw Error('Invalid application');
  const addresses=[...new Set(transportAddresses)].filter(ip=>net.isIP(ip)).map(ip=>ip+(net.isIP(ip)===4?'/32':'/128'));
  const bootstrapDns={domain:['demochko.com','stun.l.google.com','stun.cloudflare.com'],action:'route',server:'direct-dns'};
  if(physicalInterface!==undefined&&(typeof physicalInterface!=='string'||!physicalInterface.length||physicalInterface.length>256))throw Error('Invalid physical interface');
  const directDns={type:'https',tag:'direct-dns',server:'1.1.1.1',tls:{enabled:true,server_name:'cloudflare-dns.com'},...(physicalInterface?{detour:'direct'}:{})};
  const rules=[
    {process_path_regex:['(?i)^'+nodePath.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'$'],action:'route',outbound:'direct'},
    {port:53,action:'hijack-dns'},
    ...(mode==='all'?[{network:'icmp',action:'reject'},{ip_is_private:true,action:'reject'}]:[]),
  ];
  if(applicationRuleFile&&(!path.win32.isAbsolute(applicationRuleFile)||!applicationRuleFile.endsWith('.json')))throw Error('Invalid rule file');
  if(mode==='apps')rules.push({...(applicationRuleFile?{rule_set:['selected-applications']}:{process_path_regex:applications.map(p=>'(?i)^'+p.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'$')}),action:'route',outbound:'phone'});
  return {
    log:{disabled:true},
    dns:mode==='all'?{servers:[{type:'https',tag:'phone-dns',server:'1.1.1.1',tls:{enabled:true,server_name:'cloudflare-dns.com'},detour:'phone'},directDns],rules:[bootstrapDns],final:'phone-dns'}:{servers:[directDns,{type:'fakeip',tag:'app-names',inet4_range:'198.18.0.0/15',inet6_range:'fc00::/18'}],rules:[bootstrapDns,{query_type:['A','AAAA'],action:'route',server:'app-names'}],final:'direct-dns'},
    inbounds:[{type:'tun',tag:'vpn',interface_name:'PhoneExit',address:['172.28.251.1/30','fd91:ee51:1701::1/126'],mtu:1280,auto_route:true,strict_route:true,stack:'gvisor',route_exclude_address:addresses}],
    outbounds:[{type:'socks',tag:'phone',server:'127.0.0.1',server_port:1080,version:'5',bind_interface:'Loopback Pseudo-Interface 1',inet4_bind_address:'127.0.0.1'},{type:'direct',tag:'direct',...(physicalInterface?{bind_interface:physicalInterface}:{})}],
    route:{auto_detect_interface:true,...(mode==='apps'&&applicationRuleFile?{rule_set:[{type:'local',tag:'selected-applications',format:'source',path:applicationRuleFile}]}:{}),rules,final:mode==='all'?'phone':'direct',default_domain_resolver:mode==='all'?'phone-dns':'direct-dns'}
  };
}
