import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import Fastify from 'fastify';
import {registerAgents} from '../src/agents.ts';
import type {Database} from '../src/db.ts';

test('agent identity rejects malformed UUIDs before touching the database and keeps auth errors generic',async()=>{
  let queries=0;const clock=Date.now();
  const db:Database={engine:'validation-only test stub',async query(){queries++;return [];},async transaction(){throw new Error('no authenticated identity in this fixture');},async close(){}};
  const app=Fastify();await registerAgents(app,{db,masterKey:randomBytes(32),now:()=>clock});await app.ready();
  try{
    const headers=(id:string)=>({'content-type':'application/vnd.sentinel.agent+json','x-sentinel-agent':id,'x-sentinel-timestamp':String(Math.floor(clock/1000)),'x-sentinel-nonce':randomUUID(),'x-sentinel-signature':'0'.repeat(64)});
    const malformed=['-'.repeat(36),'a'.repeat(36),'000000000000-4000-8000-000000000001','00000000-0000-4000-8000-00000000000-',randomUUID().toUpperCase()];
    for(const id of malformed){
      const response=await app.inject({method:'POST',url:'/agent/v1/observations',headers:headers(id),payload:'{}'});
      assert.equal(response.statusCode,401,response.body);assert.equal(response.json().code,'AGENT_AUTH_FAILED');assert.equal(queries,0,'invalid UUID must not reach PostgreSQL');
    }
    const canonicalUnknown=await app.inject({method:'POST',url:'/agent/v1/observations',headers:headers(randomUUID()),payload:'{}'});
    assert.equal(canonicalUnknown.statusCode,401);assert.equal(queries,1,'canonical UUID reaches normal identity lookup');
  }finally{await app.close();}
});
