import { createHash, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { Algorithm, hash, verify } from '@node-rs/argon2';
import * as OTPAuth from 'otpauth';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
export const randomToken = () => randomBytes(32).toString('base64url');
export function constantEqual(a: string,b: string) { const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y); }
export const hashPassword = (password: string) => hash(password,{algorithm:Algorithm.Argon2id,memoryCost:19456,timeCost:2,parallelism:1});
export const verifyPassword = (encoded: string,password: string) => verify(encoded,password);
export function encrypt(value: Buffer | string, key: Buffer, context: string): string {
  const nonce=randomBytes(12); const cipher=createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(Buffer.from(context));
  return Buffer.concat([nonce,cipher.update(value),cipher.final(),cipher.getAuthTag()]).toString('base64');
}
export function decrypt(value: string,key: Buffer,context: string): Buffer {
  const data=Buffer.from(value,'base64');if(data.length<28)throw new Error('Invalid ciphertext');
  const cipher=createDecipheriv('aes-256-gcm',key,data.subarray(0,12));cipher.setAAD(Buffer.from(context));cipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([cipher.update(data.subarray(12,-16)),cipher.final()]);
}
export function totp(secret: string, label='operator') { return new OTPAuth.TOTP({issuer:'I.See Sentinel',label,algorithm:'SHA1',digits:6,period:30,secret:OTPAuth.Secret.fromBase32(secret)}); }
export function verifyTotp(secret: string, token: string, now: number): number | null {
  const delta=totp(secret).validate({token,timestamp:now,window:1});
  return delta===null ? null : Math.floor(now/30000)+delta;
}
export function generateEnrollment(email: string) { const secret=new OTPAuth.Secret({size:20}).base32;return {secret,uri:totp(secret,email).toString()}; }
export async function loadMasterKey(dataDir: string,create=false): Promise<Buffer> {
  if(process.env.SENTINEL_MASTER_KEY) {
    if(!/^[a-fA-F0-9]{64}$/.test(process.env.SENTINEL_MASTER_KEY))throw new Error('SENTINEL_MASTER_KEY must be 64 hexadecimal characters');
    return Buffer.from(process.env.SENTINEL_MASTER_KEY,'hex');
  }
  const path=resolve(dataDir,'master.key');
  if(create) { await mkdir(dataDir,{recursive:true,mode:0o700});try {await writeFile(path,randomBytes(32),{flag:'wx',mode:0o600});}catch(e:any){if(e.code!=='EEXIST')throw e;} }
  const key=await readFile(path).catch(()=>{throw new Error('Master key missing. Run npm run bootstrap before starting.');});
  if(key.length!==32)throw new Error('Invalid master key');return key;
}
export function canonical(value: any): string {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value!==null&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
