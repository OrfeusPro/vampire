import {readFileSync} from 'node:fs';
import {vpnConfig} from './vpn-config.js';
console.log(JSON.stringify(vpnConfig(JSON.parse(readFileSync(0,'utf8').replace(/^\uFEFF/,'')))));
