import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Database } from './db.ts';
import { audit } from './audit.ts';
import { decrypt,digest,hashPassword,randomToken,verifyPassword,verifyTotp,constantEqual } from './security.ts';
import type { Identity } from '@sentinel/core';

export class HttpError extends Error { constructor(public statusCode: number, public code: string, message: string) {super(message);} }
export type Actor = Identity & {email:string;csrfToken:string;sessionHash:string;organizationName:string};
declare module 'fastify' { interface FastifyRequest { actor: Actor | null; } }
export const str=(maxLength=200)=>({type:'string',minLength:1,maxLength});
export const object=(properties:Record<string,unknown>,required=Object.keys(properties))=>({type:'object',additionalProperties:false,properties,required});
export const uuid={type:'string',format:'uuid'};

export async function registerAuth(app: FastifyInstance,db: Database,key: Buffer,origin: string,secure: boolean,now:()=>number) {
  const dummyHash=await hashPassword(randomToken());
  app.decorateRequest('actor',null);
  app.addHook('onRequest',async(request,reply)=>{
    reply.header('Cache-Control','no-store');
    if(!request.url.startsWith('/api/'))return;
    const expected=new URL(origin);
    if(request.headers.host!==expected.host && request.headers.host!=='127.0.0.1:4310') throw new HttpError(403,'HOST_REJECTED','Host não permitido.');
    if(!['GET','HEAD','OPTIONS'].includes(request.method)&&request.headers.origin!==origin)throw new HttpError(403,'ORIGIN_REJECTED','Origem não permitida.');
    const token=request.cookies.sentinel_session;
    if(token&&/^[A-Za-z0-9_-]{43}$/.test(token)) {
      const [session]=await db.query('SELECT s.token_hash,s.csrf_token,u.id,u.email,o.id AS organization_id,o.name AS organization_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN private_operator p ON p.user_id=u.id JOIN operator_organizations access ON access.operator_id=u.id AND access.organization_id=COALESCE(s.active_organization_id,u.organization_id) JOIN organizations o ON o.id=access.organization_id WHERE s.token_hash=$1 AND s.expires_at>$2 AND NOT u.disabled',[digest(token),new Date(now())]);
      if(session)request.actor={id:session.id,email:session.email,role:session.role,organizationId:session.organization_id,organizationName:session.organization_name,csrfToken:session.csrf_token,sessionHash:session.token_hash};
    }
    if(request.url.split('?')[0]==='/api/auth/login')return;
    if(!request.actor)throw new HttpError(401,'UNAUTHENTICATED','Autenticação necessária.');
    if(!['GET','HEAD','OPTIONS'].includes(request.method)) {
      const csrf=request.headers['x-csrf-token'];
      if(typeof csrf!=='string'||!constantEqual(csrf,request.actor.csrfToken))throw new HttpError(403,'CSRF_REJECTED','Token de proteção inválido.');
    }
  });
  app.post('/api/auth/login',{config:{rateLimit:{max:10,timeWindow:'1 minute'}},schema:{body:object({email:{...str(254),format:'email'},password:str(1024),otp:{type:'string',pattern:'^[0-9]{6}$'}})}},async(request,reply)=>{
    const body=request.body as {email:string;password:string;otp:string}; const email=body.email.toLowerCase().trim();const time=now();
    const outcome=await db.transaction(async tx=>{
      const attemptKey=digest(email);
      await tx.query('INSERT INTO login_attempts(key,failures,window_start) VALUES($1,0,$2) ON CONFLICT(key) DO NOTHING',[attemptKey,new Date(time)]);
      const [attempt]=await tx.query('SELECT * FROM login_attempts WHERE key=$1 FOR UPDATE',[attemptKey]);
      if(time-new Date(attempt.window_start).getTime()>=15*60*1000) {await tx.query('UPDATE login_attempts SET failures=0,window_start=$2 WHERE key=$1',[attemptKey,new Date(time)]);attempt.failures=0;}
      if(attempt.failures>=5)return {error:true,limited:true};
      const [user]=await tx.query('SELECT u.* FROM users u JOIN private_operator p ON p.user_id=u.id WHERE u.email=$1 FOR UPDATE OF u',[email]);
      const validPassword=await verifyPassword(user?.password_hash??dummyHash,body.password);
      const counter=user&&!user.disabled&&validPassword ? verifyTotp(decrypt(user.totp_cipher,key,`totp:${user.id}`).toString(),body.otp,time) : null;
      if(!user||user.disabled||!validPassword||counter===null||counter<=Number(user.last_totp_counter)) {
        await tx.query('UPDATE login_attempts SET failures=failures+1 WHERE key=$1',[attemptKey]);
        if(user)await audit(tx,user.organization_id,user.id,'auth.login_failed',null,{});
        return {error:true,limited:false};
      }
      const token=randomToken(),csrfToken=randomToken();
      await tx.query('UPDATE users SET last_totp_counter=$2 WHERE id=$1',[user.id,counter]);
      await tx.query('DELETE FROM sessions WHERE user_id=$1 AND expires_at<=$2',[user.id,new Date(time)]);
      await tx.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),user.id,csrfToken,new Date(time+8*60*60*1000),user.organization_id]);
      await tx.query('UPDATE login_attempts SET failures=0 WHERE key=$1',[attemptKey]);
      await audit(tx,user.organization_id,user.id,'auth.login',user.id,{mfa:'totp'});
      const [organization]=await tx.query('SELECT id,name FROM organizations WHERE id=$1',[user.organization_id]);
      return {error:false,token,csrfToken,user:{id:user.id,email:user.email,organizationId:user.organization_id,role:user.role},activeOrganization:organization};
    });
    if(outcome.error)throw new HttpError(outcome.limited?429:401,'LOGIN_FAILED','Credenciais inválidas ou acesso temporariamente limitado.');
    if(request.actor)await db.query('DELETE FROM sessions WHERE token_hash=$1',[request.actor.sessionHash]);
    reply.setCookie('sentinel_session',outcome.token!,{path:'/',httpOnly:true,sameSite:'strict',secure,maxAge:8*60*60});
    return {user:outcome.user,csrfToken:outcome.csrfToken,activeOrganization:outcome.activeOrganization};
  });
  app.get('/api/auth/session',async request=>({user:publicActor(request),csrfToken:request.actor!.csrfToken,activeOrganization:{id:request.actor!.organizationId,name:request.actor!.organizationName}}));
  app.post('/api/auth/logout',async(request,reply)=>{
    const actor=request.actor!;
    await db.transaction(async tx=>{await tx.query('DELETE FROM sessions WHERE token_hash=$1',[actor.sessionHash]);await audit(tx,actor.organizationId,actor.id,'auth.logout',actor.id);});
    reply.clearCookie('sentinel_session',{path:'/',httpOnly:true,sameSite:'strict',secure});return {ok:true};
  });
  app.post('/api/auth/revoke-sessions',async request=>{
    const actor=request.actor!;
    await db.transaction(async tx=>{await tx.query('DELETE FROM sessions WHERE user_id=$1',[actor.id]);await audit(tx,actor.organizationId,actor.id,'auth.sessions_revoked',actor.id);});return {ok:true};
  });
}
export function publicActor(request:FastifyRequest) {const a=request.actor!;return {id:a.id,email:a.email,role:a.role,organizationId:a.organizationId};}
