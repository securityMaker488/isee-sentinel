import {randomBytes} from 'node:crypto';
import type {Database} from './db.ts';
import {digest,constantEqual,generateEnrollment,hashPassword,encrypt} from './security.ts';
import {audit} from './audit.ts';
export async function recoverOperator(db:Database,key:Buffer,token:string) {
  const [founder]=await db.query('SELECT p.*,u.email,u.organization_id FROM private_operator p JOIN users u ON u.id=p.user_id');
  if(!founder||!constantEqual(digest(token),founder.recovery_hash))throw new Error('Código de recuperação inválido.');
  const password=randomBytes(24).toString('base64url'),enrollment=generateEnrollment(founder.email),recovery=randomBytes(32).toString('base64url'),passwordHash=await hashPassword(password);
  await db.transaction(async tx=>{
    const updated=await tx.query('UPDATE private_operator SET recovery_hash=$1 WHERE slot=1 AND recovery_hash=$2 RETURNING user_id',[digest(recovery),digest(token)]);
    if(updated.length!==1)throw new Error('Recovery code already consumed.');
    await tx.query("UPDATE users SET password_hash=$2,totp_cipher=$3,last_totp_counter=-1,disabled=false,role='admin' WHERE id=$1",[founder.user_id,passwordHash,encrypt(enrollment.secret,key,`totp:${founder.user_id}`)]);
    await tx.query('DELETE FROM sessions WHERE user_id=$1',[founder.user_id]);await tx.query('DELETE FROM login_attempts WHERE key=$1',[digest(founder.email)]);
    await audit(tx,founder.organization_id,founder.user_id,'operator.recovered',founder.user_id,{sessionsRevoked:true,recoveryRotated:true});
  });return {password,enrollment,recovery};
}
