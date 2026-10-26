import { resolve } from 'node:path';
export function config() {
  const databaseMode=process.env.SENTINEL_DATABASE_MODE??'postgres';
  if(!['postgres','embedded'].includes(databaseMode))throw new Error('SENTINEL_DATABASE_MODE must be postgres or embedded');
  if(databaseMode==='postgres'&&!process.env.DATABASE_URL)throw new Error('V6.5 requires a dedicated local PostgreSQL DATABASE_URL. See docs/OPERACAO.md. For isolated development only, explicitly set SENTINEL_DATABASE_MODE=embedded.');
  const port=Number(process.env.SENTINEL_PORT??4310),origin=process.env.SENTINEL_ORIGIN??`http://127.0.0.1:${port}`;
  const url=new URL(origin);
  if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('Invalid SENTINEL_PORT');
  if(url.origin!==origin)throw new Error('SENTINEL_ORIGIN must be an origin without path');
  if(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))throw new Error('Remote origin requires HTTPS');
  if(url.protocol==='https:'&&process.env.SENTINEL_SECURE_COOKIE==='false')throw new Error('HTTPS requires Secure cookies');
  return {port,origin,dataDir:resolve(process.env.SENTINEL_DATA_DIR??'.sentinel'),databaseMode,databaseUrl:databaseMode==='postgres'?process.env.DATABASE_URL:undefined,secureCookie:url.protocol==='https:'||process.env.SENTINEL_SECURE_COOKIE==='true'};
}
