import {test} from 'node:test';
import assert from 'node:assert/strict';
import {normalizeAssessmentSteps} from '../src/assessment-plan.js';

const assetId='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const staticStep={id:'read-config',name:'Revisar configuração',assetId,profile:'static.scan'};
const inventory={id:'inventory',name:'Inventário autorizado',assetId,profile:'lab.inventory',address:'127.0.0.1',ports:[443,80]};

test('assessment normalization preserves execution order and does not share mutable target inputs',()=>{
 const input=[structuredClone(inventory),{...staticStep,assetId:assetId.toUpperCase()}];
 const before=structuredClone(input),normalized=normalizeAssessmentSteps(input);
 assert.ok(normalized);
 assert.deepEqual(input,before);
 assert.deepEqual(normalized.map(step=>step.id),['inventory','read-config']);
 assert.deepEqual(normalized[0].ports,[80,443]);
 assert.equal(normalized[1].assetId,assetId);
 assert.deepEqual(normalizeAssessmentSteps(normalized),normalized);
 (input[0] as typeof inventory).ports[0]=22;
 assert.deepEqual(normalized[0].ports,[80,443]);
});

test('assessment contract rejects executable content, ambiguous targets and duplicate step identities',()=>{
 const hostile:unknown[]=[
  [{...staticStep,command:'whoami'}], [{...staticStep,profile:'shell.execute'}],
  [{...staticStep,profile:'static.scan',address:'127.0.0.1',ports:[80]}],
  [{...inventory,address:'127.0.0.1;whoami'}], [{...inventory,address:'localhost'}],
  [{...inventory,address:'2130706433'}], [{...inventory,address:'127.1'}],
  [{...inventory,address:'8.8.8.8'}], [{...inventory,ports:[80,80]}],
  [{...inventory,ports:[80,'443']}], [{...inventory,ports:[0]}],
  [staticStep,{...staticStep,assetId:'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'}],
  [{...staticStep,id:'../outside'}], [{...staticStep,name:'log\nforged-event'}],
  [{...staticStep,assetId:'not-an-asset'}],
 ];
 for(const input of hostile)assert.equal(normalizeAssessmentSteps(input),null,JSON.stringify(input));
});

test('assessment contract bounds the work accepted before any database or executor access',()=>{
 const steps=Array.from({length:25},(_,index)=>({...staticStep,id:`step-${index}`}));
 assert.equal(normalizeAssessmentSteps(steps)?.length,25);
 for(const value of [[],[...steps,{...staticStep,id:'overflow'}],null,{steps},
  [{...staticStep,name:'x'.repeat(161)}],
  [{...inventory,ports:Array.from({length:17},(_,index)=>80+index)}],
  [{...staticStep,name:'\u0000'}],
 ])assert.equal(normalizeAssessmentSteps(value),null);
});
