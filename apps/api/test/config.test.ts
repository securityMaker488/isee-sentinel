import {test} from 'node:test';
import assert from 'node:assert/strict';
import {config} from '../src/config.ts';
test('V6.5 exige PostgreSQL configurado, sem fallback silencioso',()=>{
  const saved={...process.env};
  try {delete process.env.DATABASE_URL;delete process.env.SENTINEL_DATABASE_MODE;assert.throws(()=>config(),/dedicated local PostgreSQL/);process.env.SENTINEL_DATABASE_MODE='embedded';assert.equal(config().databaseMode,'embedded');process.env.SENTINEL_ORIGIN='http://remote.invalid';assert.throws(()=>config(),/HTTPS/);process.env.SENTINEL_ORIGIN='https://sentinel.invalid';process.env.SENTINEL_SECURE_COOKIE='false';assert.throws(()=>config(),/Secure cookies/);}finally{for(const k of Object.keys(process.env))if(!(k in saved))delete process.env[k];Object.assign(process.env,saved);}
});
