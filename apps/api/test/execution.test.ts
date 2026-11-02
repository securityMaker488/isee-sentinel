import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,unlink,rmdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {runSupervisedImport,type ExecutionReceipt} from '../src/execution.ts';
import {digest} from '../src/security.ts';

const native=process.env.SENTINEL_TEST_EXECUTION_PATH,python=process.env.SENTINEL_TEST_PYTHON_PATH;
const skip=!native||!python;let folder:string,file:string,worker:string;
before(async()=>{folder=await mkdtemp(join(tmpdir(),'sentinel-supervisor-'));file=join(folder,'input.archive');worker=join(folder,'worker.py');await writeFile(file,'synthetic');});
after(async()=>{for(const name of ['input.archive','worker.py','worker.pid'])await unlink(join(folder,name)).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(folder);});
const options=()=>({executionPath:native!,pythonPath:python!,workerPath:worker,file,format:'zip' as const,jobId:randomUUID(),inputSha256:digest('synthetic')});
const delay=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const pidPath=()=>join(folder,'worker.pid');
async function waitPid(){for(let i=0;i<100;i++){try{return Number(await readFile(pidPath(),'utf8'));}catch{await delay(20);}}throw new Error('Synthetic worker did not start');}
function stopped(pid:number){assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});}
const sleeper="import os,time\nfrom pathlib import Path\nPath(__file__).with_name('worker.pid').write_text(str(os.getpid()))\nwhile True: time.sleep(0.02)\n";

test('native supervisor returns real status, hashes and bounded receipt without inherited secrets',{skip},async()=>{
 await writeFile(worker,"import os,json\nprint(json.dumps({'secretInherited':'SENTINEL_TEST_PARENT_SECRET' in os.environ}))\n");
 process.env.SENTINEL_TEST_PARENT_SECRET='synthetic-parent-only';let receipt:ExecutionReceipt|undefined;
 try{const result=await runSupervisedImport({...options(),onReceipt:r=>{receipt=r;}});assert.equal(JSON.parse(result.toString()).secretInherited,false);assert.equal(receipt?.status,'completed');assert.equal(receipt?.exitCode,0);assert.equal(receipt?.stdoutSha256,digest(result));assert.equal(receipt?.workerSha256,digest(await readFile(worker)));}
 finally{delete process.env.SENTINEL_TEST_PARENT_SECRET;}
});
test('nonzero exit cannot become success even if stdout claims completion; stderr is redacted',{skip},async()=>{
 await writeFile(worker,"import sys\nprint('{\"status\":\"completed\"}')\nprint('SYNTHETIC_PRIVATE_DIAGNOSTIC',file=sys.stderr)\nsys.exit(7)\n");let receipt:ExecutionReceipt|undefined;
 await assert.rejects(runSupervisedImport({...options(),onReceipt:r=>{receipt=r;}}),{code:'IMPORT_REJECTED'});assert.equal(receipt?.exitCode,7);assert.equal(receipt?.status,'failed');assert.ok(!JSON.stringify(receipt).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'));
});
test('abort closes control lease and reaps the real Python child',{skip},async()=>{
 await writeFile(worker,sleeper);const controller=new AbortController();let receipt:ExecutionReceipt|undefined;
 const running=runSupervisedImport({...options(),signal:controller.signal,onReceipt:r=>{receipt=r;}});const rejected=assert.rejects(running,{code:'IMPORT_CANCELLED'});
 const pid=await waitPid(),start=performance.now();controller.abort();await rejected;stopped(pid);assert.equal(receipt?.status,'cancelled');assert.ok(performance.now()-start<3000);await unlink(pidPath());
});
test('native output budgets reject flood instead of buffering it indefinitely',{skip},async()=>{
 for(const stream of ['stdout','stderr']){
  await writeFile(worker,`import sys\nsys.${stream}.write('X'*3000000)\nsys.${stream}.flush()\n`);
  let receipt:ExecutionReceipt|undefined;await assert.rejects(runSupervisedImport({...options(),onReceipt:r=>{receipt=r;}}),{code:'IMPORT_OUTPUT_LIMIT'});assert.equal(receipt?.outputTruncated,true);assert.ok(receipt!.stdoutBytes<=2097153);assert.ok(receipt!.stderrBytes<=65537);
 }
});
test('changed original and invalid UTF-8 output are never accepted as completed',{skip},async()=>{
 await writeFile(worker,"import sys\nfrom pathlib import Path\nPath(sys.argv[sys.argv.index('--file')+1]).write_text('changed')\nprint('{}')\n");
 await assert.rejects(runSupervisedImport(options()),{code:'IMPORT_REJECTED'});await writeFile(file,'synthetic');
 await writeFile(worker,"import sys\nsys.stdout.buffer.write(b'\\xff')\n");await assert.rejects(runSupervisedImport(options()),{code:'IMPORT_REJECTED'});
});
async function raw(request:object,closeLease=false){
 const child=spawn(native!,['--python',python!,'--worker',worker],{windowsHide:true,stdio:['pipe','pipe','pipe']});let out='',err='';
 child.stdout.on('data',b=>{out+=b;});child.stderr.on('data',b=>{err+=b;});
 const finished=new Promise<{code:number|null;out:string;err:string}>((accept,reject)=>{child.on('error',reject);child.on('close',code=>accept({code,out,err}));});
 child.stdin.write(JSON.stringify(request)+'\n');
 if(closeLease){await waitPid();child.stdin.end();}
 const timer=setTimeout(()=>child.kill('SIGKILL'),5000);try{return await finished;}finally{clearTimeout(timer);}
}
const request=()=>({schemaVersion:1,operation:'archive.inspect',jobId:randomUUID(),file,format:'zip',inputSha256:digest('synthetic'),maxInputBytes:16777216,maxOutputBytes:2097152,timeoutMs:45000});
test('native deadline and parent EOF both reap a live worker',{skip},async()=>{
 for(const eof of [false,true]){
  await writeFile(worker,sleeper);const result=await raw({...request(),timeoutMs:800},eof);assert.equal(result.code,3,result.err);const report=JSON.parse(result.out);assert.equal(report.receipt.status,eof?'cancelled':'timed_out');stopped(await waitPid());await unlink(pidPath());
 }
});
test('native input contract rejects unknown executable, wrong hash and oversized input before spawning',{skip},async()=>{
 await writeFile(worker,sleeper);
 for(const change of [{command:'untrusted'}, {inputSha256:'0'.repeat(64)}, {maxInputBytes:1}]){
  const result=await raw({...request(),...change});assert.equal(result.code,2);assert.equal(result.out,'');await assert.rejects(readFile(pidPath()),{code:'ENOENT'});
 }
});
