import {randomUUID,randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {createInterface} from 'node:readline/promises';
import {openDatabase,migrate} from './db.ts';
import {loadMasterKey,encrypt,decrypt,hashPassword,verifyPassword,verifyTotp,generateEnrollment,digest,constantEqual} from './security.ts';
import {config} from './config.ts';
import {audit} from './audit.ts';
import {recoverOperator} from './operator.ts';

const command=process.argv[2],cfg=config();
if(!['bootstrap','recover','adopt','migrate'].includes(command))throw new Error('Use bootstrap, recover, adopt or migrate. No additional operators in Private Edition.');
const key=await loadMasterKey(cfg.dataDir,command==='bootstrap');
const db=await openDatabase({url:cfg.databaseUrl,dataDir:resolve(cfg.dataDir,'database')});
async function question(label:string) {const rl=createInterface({input:process.stdin,output:process.stdout});try{return (await rl.question(label)).trim();}finally{rl.close();}}
async function secretQuestion(label:string):Promise<string> {
  if(!process.stdin.isTTY)throw new Error('Use an interactive terminal for credential input.');
  process.stdout.write(label);process.stdin.setRawMode(true);process.stdin.resume();
  return new Promise((res,rej)=>{let value='';const done=()=>{process.stdin.off('data',read);process.stdin.setRawMode(false);process.stdin.pause();process.stdout.write('\n');};const read=(chunk:Buffer)=>{for(const c of chunk.toString()){if(c==='\u0003'){done();rej(new Error('Cancelled'));return;}if(c==='\r'||c==='\n'){done();res(value);return;}if(c==='\u007f'||c==='\b'){value=value.slice(0,-1);continue;}if(c>=' '&&value.length<1024)value+=c;}};process.stdin.on('data',read);});
}
function display(password:string,enrollment:ReturnType<typeof generateEnrollment>,recovery:string) {
  console.info(`\nSenha: ${password}\nSegredo TOTP: ${enrollment.secret}\nURI: ${enrollment.uri}\nCódigo de recuperação: ${recovery}`);
  console.info('Guarde senha e TOTP em meios protegidos. Armazene o código de recuperação offline, separado do banco. Valores exibidos somente agora; nunca redirecione para logs.');
}
try {
  await migrate(db);
  const [founder]=await db.query('SELECT p.*,u.email,u.organization_id FROM private_operator p JOIN users u ON u.id=p.user_id');
  if(command==='migrate')console.info('Migrations applied successfully.');
  else if(command==='bootstrap') {
    if(founder)throw new Error('Private Edition already initialized. Only one founder is permitted.');
    const [count]=await db.query('SELECT count(*)::int AS count FROM users');if(count.count)throw new Error('Existing v5 users: use npm run operator:adopt with the founder credentials.');
    const email=(await question('E-mail do fundador: ')).toLowerCase(),orgName=await question('Organização [I.See Technologies]: ')||'I.See Technologies';
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||orgName.length>120)throw new Error('Dados inválidos');
    const password=randomBytes(24).toString('base64url'),enrollment=generateEnrollment(email),recovery=randomBytes(32).toString('base64url'),id=randomUUID(),org=randomUUID();
    const passwordHash=await hashPassword(password);
    await db.transaction(async tx=>{
      await tx.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,orgName]);
      await tx.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[id,org,email,'admin',passwordHash,encrypt(enrollment.secret,key,`totp:${id}`)]);
      await tx.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[id,digest(recovery)]);
      await tx.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[id,org]);
      await audit(tx,org,id,'operator.provisioned',id,{edition:'private',specification:'6.5'});
    });display(password,enrollment,recovery);
  } else if(command==='adopt') {
    if(founder)throw new Error('Founder already configured.');
    const email=(await question('E-mail do fundador já existente: ')).toLowerCase(),password=await secretQuestion('Senha atual (oculta): '),otp=await secretQuestion('TOTP atual (oculto): ');
    const [user]=await db.query("SELECT * FROM users WHERE email=$1 AND role='admin' AND NOT disabled",[email]);
    if(!user||!await verifyPassword(user.password_hash,password)||verifyTotp(decrypt(user.totp_cipher,key,`totp:${user.id}`).toString(),otp,Date.now())===null)throw new Error('Credenciais inválidas.');
    const recovery=randomBytes(32).toString('base64url');
    await db.transaction(async tx=>{await tx.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[user.id,digest(recovery)]);await tx.query('DELETE FROM sessions');await audit(tx,user.organization_id,user.id,'operator.adopted',user.id);});
    console.info(`Fundador selecionado. Demais usuários não podem entrar. Código de recuperação: ${recovery}`);
  } else {
    if(!founder)throw new Error('Founder not initialized.');
    const token=await secretQuestion('Código de recuperação offline (oculto): ');
    const recovered=await recoverOperator(db,key,token);display(recovered.password,recovered.enrollment,recovered.recovery);
  }
}finally{await db.close();}
