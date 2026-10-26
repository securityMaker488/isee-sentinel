import {spawnSync} from 'node:child_process';
import {existsSync,realpathSync,statSync} from 'node:fs';
import {delimiter,dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Read-only diagnostics: no environment values, credentials or database connections are printed.
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const flags=new Set(process.argv.slice(2));
if([...flags].some(flag=>!['--json','--require-ready','--help'].includes(flag))) {
  process.stderr.write('Uso: node scripts/doctor.mjs [--json] [--require-ready]\n');process.exit(2);
}
if(flags.has('--help')){process.stdout.write('Diagnóstico somente leitura. --json: saída estruturada. --require-ready: exige dependências e builds locais.\n');process.exit(0);}
const versionParts=value=>String(value).split('.').map(Number);
const atLeast=(value,minimum)=>{const a=versionParts(value),b=versionParts(minimum);for(let i=0;i<3;i++){if((a[i]??0)!==(b[i]??0))return(a[i]??0)>(b[i]??0);}return true;};
function executable(name) {
  const suffixes=process.platform==='win32'?['.exe','.cmd','.bat','']:[''];
  for(const folder of (process.env.PATH??'').split(delimiter))for(const suffix of suffixes) {
    const candidate=join(folder.replace(/^"|"$/g,''),name+suffix);
    try{if(statSync(candidate).isFile())return realpathSync(candidate);}catch{}
  }
  return null;
}
function run(command,args) {
  const result=spawnSync(command,args,{encoding:'utf8',timeout:8000,maxBuffer:65536,windowsHide:true,shell:false});
  return !result.error&&result.status===0?`${result.stdout??''}\n${result.stderr??''}`:null;
}
function probe(name,minimum,guide) {
  const path=executable(name),output=path?run(path,['--version']):null,version=output?.match(/\b(\d+\.\d+\.\d+)/)?.[1]??null;
  return {path,version,ok:!!version&&(!minimum||atLeast(version,minimum)),requirement:minimum?`>=${minimum}`:'disponível',guide};
}
const nodeVersion=process.versions.node;
const npmPath=executable('npm');
let npmCommand=null;
for(const candidate of [npmPath,join(dirname(process.execPath),'node_modules/npm/bin/npm-cli.js'),npmPath&&join(dirname(npmPath),'node_modules/npm/bin/npm-cli.js'),'/usr/share/nodejs/npm/bin/npm-cli.js']) {
  if(candidate&&candidate.endsWith('.js')&&existsSync(candidate)){npmCommand=candidate;break;}
}
const npmOutput=npmCommand?run(process.execPath,[npmCommand,'--version']):process.platform!=='win32'&&npmPath?run(npmPath,['--version']):null;
const npmVersion=npmOutput?.match(/\b(\d+\.\d+\.\d+)/)?.[1]??null;
let python={path:null,version:null,ok:false,requirement:'>=3.11',guide:'Instale Python 3.11 ou posterior; no Windows habilite o launcher ou inclua python.exe no PATH.'};
for(const name of process.platform==='win32'?['python','py','python3']:['python3','python']) {
  const candidate=executable(name);if(!candidate)continue;
  const output=run(candidate,[...(name==='py'?['-3']:[]),'-c','import json,sys; print(json.dumps({"path":sys.executable,"version":".".join(map(str,sys.version_info[:3]))}))']);
  if(!output)continue;
  try {const result=JSON.parse(output.trim());if(typeof result.path==='string'&&/^\d+\.\d+\.\d+$/.test(result.version)){
    if(!python.version||atLeast(result.version,python.version))python={...python,...result,ok:atLeast(result.version,'3.11.0')};if(python.ok)break;
  }}catch{}
}
const tools={
  node:{path:process.execPath,version:nodeVersion,ok:versionParts(nodeVersion)[0]===24,requirement:'24.x',guide:'Instale a linha Node.js 24 e reabra o terminal.'},
  npm:{path:npmCommand??npmPath,version:npmVersion,ok:!!npmVersion,requirement:'disponível com Node.js 24',guide:'Use o npm fornecido pela instalação Node.js 24.'},
  git:probe('git',null,'Instale Git e inclua seu executável no PATH.'),
  rustc:probe('rustc','1.98.1','Instale a toolchain Rust 1.98.1 com rustup. Versões anteriores não foram validadas com este lockfile.'),
  cargo:probe('cargo','1.98.1','Instale Cargo junto com a toolchain Rust 1.98.1 e inclua ~/.cargo/bin no PATH.'),
  python,
};
const files={packageLock:existsSync(join(root,'package-lock.json')),cargoLock:existsSync(join(root,'packages/endpoint-agent/Cargo.lock')),
  nodeDependencies:existsSync(join(root,'node_modules')),webBuild:existsSync(join(root,'apps/web/dist/index.html')),
  agentBuild:existsSync(join(root,'packages/endpoint-agent/target/debug',process.platform==='win32'?'sentinel-agent.exe':'sentinel-agent'))};
const missingTools=Object.entries(tools).filter(([,value])=>!value.ok).map(([name])=>name);
const sourceReady=files.packageLock&&files.cargoLock;
const artifactsReady=files.nodeDependencies&&files.webBuild&&files.agentBuild;
const ready=missingTools.length===0&&sourceReady&&artifactsReady;
const report={schemaVersion:1,readOnly:true,platform:process.platform,architecture:process.arch,root,
  status:missingTools.length?'missing_tools':!sourceReady?'incomplete_source':!artifactsReady?'needs_setup':'development_ready',
  tools,files,configuration:{databaseUrlPresent:!!process.env.DATABASE_URL,masterKeyEnvironmentPresent:!!process.env.SENTINEL_MASTER_KEY,
    localEnvFilePresent:existsSync(join(root,'.env')),localMasterKeyPresent:existsSync(join(root,'.sentinel/master.key'))},
  limitations:['Não conecta ao banco nem verifica sua senha.','Não verifica serviços, permissões de produção, dual boot ou partições.','Builds presentes podem estar desatualizados; o setup recompila o código.','A disponibilidade operacional no Debian exige homologação separada.']};
if(flags.has('--json'))process.stdout.write(JSON.stringify(report,null,2)+'\n');
else {
  process.stdout.write(`I.See Sentinel — diagnóstico de desenvolvimento (${process.platform}/${process.arch})\n`);
  for(const [name,result] of Object.entries(tools))process.stdout.write(`${result.ok?'OK':'FALTA'} ${name}: ${result.version??'não disponível'}${result.path?` · ${result.path}`:''}${result.ok?'':`\n  ${result.guide}`}\n`);
  process.stdout.write(`Arquivos de dependências fixadas: ${sourceReady?'OK':'incompletos'}\nDependências e builds locais: ${artifactsReady?'presentes':'execute o setup após instalar as ferramentas'}\nEstado: ${report.status}\nSomente leitura; nenhum banco, serviço ou arquivo de configuração foi alterado.\n`);
}
process.exitCode=missingTools.length||!sourceReady||(flags.has('--require-ready')&&!ready)?1:0;
