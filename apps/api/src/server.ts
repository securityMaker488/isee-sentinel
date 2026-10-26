import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase,verifySchema } from './db.ts';
import { loadMasterKey } from './security.ts';
import { buildApp } from './app.ts';
import { config } from './config.ts';
import { audit } from './audit.ts';

const cfg=config(),masterKey=await loadMasterKey(cfg.dataDir);
const db=await openDatabase({url:cfg.databaseUrl,dataDir:resolve(cfg.dataDir,'database')});
await verifySchema(db);
// A crashed synchronous job is visible for operator review; never blindly replay source execution.
await db.transaction(async tx=>{
  const interrupted=await tx.query("UPDATE jobs SET status='interrupted',completed_at=now() WHERE status='running' RETURNING id,organization_id");
  for(const job of interrupted)await audit(tx,job.organization_id,null,'job.interrupted',job.id);
});
const app=await buildApp({db,masterKey,origin:cfg.origin,secureCookie:cfg.secureCookie,staticDir:fileURLToPath(new URL('../../web/dist/',import.meta.url)),logger:true});
await app.listen({host:'127.0.0.1',port:cfg.port});
console.info(`I.See Sentinel listening on http://127.0.0.1:${cfg.port} (${db.engine}); expected browser origin ${cfg.origin}`);
let closing=false;
for(const signal of ['SIGINT','SIGTERM'] as const)process.on(signal,()=>{if(closing)return;closing=true;void app.close().then(()=>db.close()).then(()=>process.exit(0));});
