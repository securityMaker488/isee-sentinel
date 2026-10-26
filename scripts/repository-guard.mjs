import {execFileSync,spawnSync} from 'node:child_process';
import {readFileSync,lstatSync,realpathSync} from 'node:fs';
import {resolve,relative,sep,basename} from 'node:path';
import {fileURLToPath} from 'node:url';

export function inspectContent(path,content){
 const issues=[];
 const patterns=[
  ['PRIVATE_KEY',/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{64,}-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g],
  ['GITHUB_TOKEN',/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
  ['OPENAI_KEY',/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b/g],
  ['AWS_KEY',/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['DATABASE_CREDENTIAL',/postgres(?:ql)?:\/\/[^\s/:]+:([^\s@]{12,})@/g],
  ['AGENT_CREDENTIAL',/"secret"\s*:\s*"[a-f0-9]{64}"/gi],
  ['MASTER_KEY',/SENTINEL_MASTER_KEY\s*=\s*[a-f0-9]{64}/gi],
 ];
 for(const [code,pattern] of patterns)for(const m of content.matchAll(pattern)){
  if(m[0]==='AKIAIOSFODNN7EXAMPLE')continue; // AWS public documentation fixture, exact value only.
  if(code==='DATABASE_CREDENTIAL'&&/REPLACE|EXAMPLE|PLACEHOLDER/.test(m[1]))continue;
  issues.push({path,line:content.slice(0,m.index).split('\n').length,code});
 }
 return issues;
}
export function inspectPath(path){
 const normalized=path.replaceAll('\\','/');
 return /(^|\/)(?:node_modules|target|__pycache__|\.sentinel|\.venv|\.codex)(\/|$)/.test(normalized)
  ||(/^\.env(?:\.|$)/.test(basename(normalized))&&basename(normalized)!=='.env.example')
  ||/(?:^|\/)(?:auth|.*credentials?|master\.key)\.json$/i.test(normalized)
  ||/\.(?:db|sqlite3?|dump|backup|pfx|p12|key|pyc)$/i.test(normalized)
  ||/(?:-wal|-shm)$/.test(normalized);
}
function git(root,args){return execFileSync('git',args,{cwd:root,windowsHide:true,maxBuffer:32*1024*1024});}
export function inspectRepository(root){
 const failures=[],paths=[...new Set(git(root,['ls-files','-z','--cached','--others','--exclude-standard']).toString().split('\0').filter(Boolean))];
 for(const path of paths){
  if(inspectPath(path)){failures.push({path,code:'FORBIDDEN_ARTIFACT'});continue;}
  const full=resolve(root,path);let stat;
  try{stat=lstatSync(full);}catch(e){if(e.code==='ENOENT')continue;throw e;}
  if(stat.isSymbolicLink()){failures.push({path,code:'SYMLINK_REVIEW'});continue;}
  if(!stat.isFile()||!realpathSync(full).startsWith(realpathSync(root)+sep)||stat.size>8*1024*1024){failures.push({path,code:'FILE_REVIEW_REQUIRED'});continue;}
  const bytes=readFileSync(full);if(!bytes.includes(0))failures.push(...inspectContent(path,bytes.toString('utf8')));
 }
 let indexBlobs=0;
 for(const entry of git(root,['ls-files','--stage','-z']).toString().split('\0').filter(Boolean)){
  const match=/^(\d+) ([a-f0-9]{40,64}) (\d)\t([\s\S]+)$/.exec(entry);if(!match)throw new Error('Unexpected Git index entry');
  const [,mode,oid,stage,path]=match;indexBlobs++;
  if(stage!=='0'||!['100644','100755'].includes(mode)){failures.push({path,code:'INDEX_MODE_REVIEW'});continue;}
  if(inspectPath(path)){failures.push({path,code:'FORBIDDEN_INDEX_ARTIFACT'});continue;}
  if(Number(git(root,['cat-file','-s',oid]).toString())>8*1024*1024){failures.push({path,code:'INDEX_SIZE_REVIEW'});continue;}
  const bytes=git(root,['cat-file','blob',oid]);if(!bytes.includes(0))failures.push(...inspectContent(path,bytes.toString('utf8')).map(issue=>({...issue,source:'index'})));
 }
 const head=spawnSync('git',['rev-parse','--verify','HEAD'],{cwd:root,windowsHide:true,stdio:'ignore'});
 let historyBlobs=0;
 if(head.status===0){
  const objects=git(root,['rev-list','--objects','--all']).toString().split('\n').filter(Boolean);
  for(const line of objects){const space=line.indexOf(' ');if(space<0)continue;const oid=line.slice(0,space),path=line.slice(space+1);if(!/^[a-f0-9]{40,64}$/.test(oid))throw new Error('Unexpected Git object');
   if(git(root,['cat-file','-t',oid]).toString().trim()!=='blob')continue;historyBlobs++;
   if(inspectPath(path)){failures.push({path,object:oid.slice(0,12),code:'FORBIDDEN_HISTORY_ARTIFACT'});continue;}
   const size=Number(git(root,['cat-file','-s',oid]).toString());if(size>8*1024*1024){failures.push({path,object:oid.slice(0,12),code:'HISTORY_SIZE_REVIEW'});continue;}
   const bytes=git(root,['cat-file','blob',oid]);if(!bytes.includes(0))failures.push(...inspectContent(path,bytes.toString('utf8')).map(issue=>({...issue,object:oid.slice(0,12)})));
  }
 }
 return {files:paths.length,indexBlobs,historyBlobs,failures};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
 const result=inspectRepository(root);
 if(result.failures.length){console.error(JSON.stringify(result,null,2));process.exitCode=1;}
 else console.info(`Repository guard PASS: ${result.files} tracked/candidate files, ${result.indexBlobs} index blobs and ${result.historyBlobs} history blobs. No matched high-confidence secret patterns or forbidden paths. Review still required; no upload performed.`);
}
