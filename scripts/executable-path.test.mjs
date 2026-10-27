import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {findExecutable} from './executable-path.mjs';

function fixture(t){const root=mkdtempSync(join(tmpdir(),'sentinel-probe-'));t.after(()=>rmSync(root,{recursive:true,force:true}));return root;}
test('search respects PATH order and ignores directories with executable names',t=>{
  const root=fixture(t),first=join(root,'first'),second=join(root,'second');mkdirSync(first);mkdirSync(second);
  mkdirSync(join(first,'probe.exe'));writeFileSync(join(second,'probe.exe'),'fixture');
  assert.equal(findExecutable('probe',{searchPath:`"${first}";"${second}"`,platform:'win32'}),join(second,'probe.exe'));
  writeFileSync(join(first,'probe.cmd'),'fixture');
  assert.equal(findExecutable('probe',{searchPath:`${first};${second}`,platform:'win32'}),join(first,'probe.cmd'));
});
test('missing or empty PATH entries never select the working directory',t=>{
  const root=fixture(t);assert.equal(findExecutable('missing',{searchPath:root}),null);
  assert.equal(findExecutable('package.json',{searchPath:'',platform:'linux'}),null);
});
test('POSIX dispatcher receives the original symlink filename, not its resolved target',{skip:process.platform==='win32'?'POSIX symlink dispatch is exercised by Ubuntu CI':false},t=>{
  const root=fixture(t),dispatcher=join(root,'dispatcher'),proxy=join(root,'rustc');
  writeFileSync(dispatcher,'#!/bin/sh\ncase "$0" in */rustc) printf "rustc 1.98.1\\n" ;; *) printf "rustup 1.29.1\\n" ;; esac\n',{mode:0o700});
  symlinkSync(dispatcher,proxy);
  const selected=findExecutable('rustc',{searchPath:root,platform:'linux'});assert.equal(selected,proxy);
  const result=spawnSync(selected,['--version'],{encoding:'utf8',shell:false});assert.equal(result.status,0);assert.equal(result.stdout.trim(),'rustc 1.98.1');
});
