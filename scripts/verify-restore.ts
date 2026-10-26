import assert from 'node:assert/strict';
import {openDatabase} from '../apps/api/src/db.ts';
import {verifyAuditChain} from '../apps/api/src/audit.ts';
if(!process.env.SENTINEL_TEST_DATABASE_URL || !process.env.SENTINEL_RESTORE_DATABASE_URL) throw new Error('Configure both isolated validation database URLs.');
const original=await openDatabase({url:process.env.SENTINEL_TEST_DATABASE_URL});
const restored=await openDatabase({url:process.env.SENTINEL_RESTORE_DATABASE_URL});
try {
  const tables=await original.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
  assert.deepEqual(await restored.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"),tables);
  for(const {tablename:table} of tables) {
    if(!/^[a-z][a-z0-9_]*$/.test(table))throw new Error('Unexpected table identifier');
    const sql=`SELECT to_jsonb(t) AS row FROM public."${table}" t ORDER BY to_jsonb(t)::text`;
    const rows=await original.query(sql);assert.deepEqual(await restored.query(sql),rows);
    console.info(`${table}: ${rows.length} rows restored exactly`);
  }
  for(const row of await restored.query('SELECT id FROM organizations')) {
    const result=verifyAuditChain(await restored.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[row.id]));assert.equal(result.valid,true);
  }
  console.info('Native PostgreSQL backup/restore: PASS; audit chains intact.');
} finally {await original.close();await restored.close();}
