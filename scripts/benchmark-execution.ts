import {readFile,writeFile,mkdtemp,unlink,rmdir,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {runImportWorker} from '../apps/api/src/imports.ts';
import {runSupervisedImport} from '../apps/api/src/execution.ts';
import {digest} from '../apps/api/src/security.ts';

// Synthetic, serial process-launch measurement. Not a load or memory benchmark.
const root=dirname(dirname(fileURLToPath(import.meta.url)));
const pythonPath=process.env.SENTINEL_TEST_PYTHON_PATH;
if(!pythonPath)throw new Error('Set SENTINEL_TEST_PYTHON_PATH to the local Python executable.');
const executionPath=join(root,'packages/execution-engine/target/debug',process.platform==='win32'?'sentinel-execution.exe':'sentinel-execution');
const binaryBytes=(await stat(executionPath)).size;
const bytes=Buffer.from((await readFile(join(root,'fixtures/lab/import-project.zip.base64'),'utf8')).trim(),'base64');
const folder=await mkdtemp(join(tmpdir(),'sentinel-runtime-measure-')),file=join(folder,'input.archive');
try{
 await writeFile(file,bytes,{flag:'wx',mode:0o600});
 const results:Record<string,unknown>={recordedAt:new Date().toISOString(),platform:process.platform,fixtureBytes:bytes.length,build:'debug',samples:8,supervisorBinaryBytes:binaryBytes};
 for(const name of ['node','rust']){
  const times:number[]=[];
  for(let i=0;i<8;i++){
   const start=performance.now(),options={pythonPath,file,format:'zip' as const,jobId:randomUUID(),inputSha256:digest(bytes)};
   await(name==='node'?runImportWorker(options):runSupervisedImport({...options,executionPath}));
   times.push(performance.now()-start);
  }
  times.sort((a,b)=>a-b);results[name]={minMs:times[0],medianMs:(times[3]+times[4])/2,maxMs:times[7]};
 }
 console.info(JSON.stringify(results,null,2));
}finally{
 await unlink(file).catch((error:NodeJS.ErrnoException)=>{if(error.code!=='ENOENT')throw error;});
 await rmdir(folder);
}
