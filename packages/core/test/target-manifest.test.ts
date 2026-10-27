import assert from 'node:assert/strict';
import {test} from 'node:test';
import {isLabIPv4,validTargetManifest,normalizeTargetManifest,targetManifestAllows,type TargetManifest} from '../src/index.js';

const first='10000000-0000-4000-8000-00000000000a',second='20000000-0000-4000-8000-00000000000b';
const manifest:TargetManifest={version:1,targets:[{assetId:first,address:'10.0.0.1',ports:[443,22]},{assetId:second,address:'10.0.0.1',ports:[80]},{assetId:first,address:'127.0.0.1',ports:[22]}],exclusions:[{address:'127.0.0.1'}]};

test('manifest enforces exact asset/address/port identity and exclusion precedence',()=>{
 assert.equal(validTargetManifest(manifest,[first,second],[22,80,443]),true);
 assert.equal(targetManifestAllows(manifest,first,'10.0.0.1',[22]),true);
 assert.equal(targetManifestAllows(manifest,second,'10.0.0.1',[80]),true);
 for(const [asset,address,ports] of [[first,'10.0.0.1',[80]],[first,'10.0.0.2',[22]],[first,'127.0.0.1',[22]],[second,'127.0.0.1',[22]],[first,'10.0.0.1',[]],[first,'10.0.0.1',[22,22]]] as const){
  assert.equal(targetManifestAllows(manifest,asset,address,ports),false);
 }
 assert.equal(targetManifestAllows(manifest,first,'127.0.0.1'),false);
});

test('canonical normalization is independent of input order, idempotent and leaves source unchanged',()=>{
 const input=structuredClone(manifest),before=structuredClone(input);
 const reordered={...input,targets:[...input.targets].reverse().map(target=>({...target,assetId:target.assetId.toUpperCase(),ports:[...target.ports].reverse()})),exclusions:[...input.exclusions].reverse()};
 assert.deepEqual(normalizeTargetManifest(input),normalizeTargetManifest(reordered));
 assert.deepEqual(normalizeTargetManifest(normalizeTargetManifest(input)),normalizeTargetManifest(input));
 assert.deepEqual(input,before);
});

test('untrusted manifests fail closed on unknown structure, cross-asset data and resource limits',()=>{
 for(const value of [null,[],{}, {...manifest,extra:true},{...manifest,version:2},{...manifest,targets:[]},{...manifest,targets:[...manifest.targets,...manifest.targets]},
  {...manifest,exclusions:[{address:'127.0.0.1'},{address:'127.0.0.1'}]}, {...manifest,targets:Array(101).fill(manifest.targets[0])},
  {...manifest,targets:[{...manifest.targets[0],ports:[22,'443']}]}, {...manifest,targets:[{...manifest.targets[0],address:'10.0.0.1/32'}]}])assert.equal(validTargetManifest(value),false);
 assert.equal(validTargetManifest(manifest,[first],[22,80,443]),false);
 assert.equal(validTargetManifest(manifest,[first,second],[22,443]),false);
});

test('literal address validator rejects coercion and alternate representations',()=>{
 for(const value of ['10.255.255.255','172.16.0.1','172.31.255.255','192.168.0.1','127.0.0.1'])assert.equal(isLabIPv4(value),true);
 for(const value of [null,127001,{},'127.1','0x7f000001','2130706433','127.0.0.01','127.0.0.1\n','127.0.0.1\r','10.0.0.256','8.8.8.8','169.254.169.254','::ffff:127.0.0.1','localhost',' 10.0.0.1'])assert.equal(isLabIPv4(value),false);
});
