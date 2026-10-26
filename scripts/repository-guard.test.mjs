import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectContent,inspectPath,inspectRepository} from './repository-guard.mjs';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
test('guard reports location and category without printing the matched secret',()=>{
 const token='ghp_'+'A'.repeat(36),results=inspectContent('example.txt',`first line\n${token}`);
 assert.equal(results[0].line,2);assert.equal(results[0].code,'GITHUB_TOKEN');assert.ok(!JSON.stringify(results).includes(token));
 assert.equal(inspectContent('fixture','AKIAIOSFODNN7EXAMPLE').length,0);
 assert.equal(inspectContent('credential.json',JSON.stringify({secret:'b'.repeat(64)}))[0].code,'AGENT_CREDENTIAL');
});
test('guard distinguishes documentation from operational credential and database paths',()=>{
 for(const p of ['.env','.env.production','a/database.sqlite','a/auth.json','.sentinel/qa/session.json','x/master.key','a/agent-credential.json','a/__pycache__/module.pyc'])assert.equal(inspectPath(p),true,p);
 for(const p of ['.env.example','apps/api/src/security.ts','docs/SECURITY.md','package-lock.json'])assert.equal(inspectPath(p),false,p);
});
test('guard detects a staged secret even after the working copy was cleaned',()=>{
 const root=mkdtempSync(join(tmpdir(),'sentinel-guard-test-'));try{
  const git=args=>execFileSync('git',args,{cwd:root,windowsHide:true,stdio:'ignore'});
  git(['init']);const token='ghp_'+'X'.repeat(36);writeFileSync(join(root,'sample.txt'),token);git(['add','sample.txt']);writeFileSync(join(root,'sample.txt'),'clean working copy');
  const result=inspectRepository(root);assert.equal(result.indexBlobs,1);assert.ok(result.failures.some(f=>f.source==='index'&&f.code==='GITHUB_TOKEN'));assert.ok(!JSON.stringify(result).includes(token));
 }finally{assert.equal(dirname(realpathSync(root)),realpathSync(tmpdir()));assert.ok(root.includes('sentinel-guard-test-'));rmSync(root,{recursive:true,force:true});}
});
