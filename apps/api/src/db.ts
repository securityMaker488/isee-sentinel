import { PGlite } from '@electric-sql/pglite';
import pg from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

export interface Sql { query<T = Record<string, any>>(sql: string, params?: any[]): Promise<T[]>; }
export interface Database extends Sql { transaction<T>(fn: (sql: Sql) => Promise<T>): Promise<T>; close(): Promise<void>; engine: string; }
export async function openDatabase(options: { url?: string; dataDir?: string } = {}): Promise<Database> {
  if (options.url) {
    const pool = new pg.Pool({ connectionString: options.url, max: 5, connectionTimeoutMillis: 5000, statement_timeout: 15000 });
    return {
      engine: 'PostgreSQL', query: async (sql, params) => (await pool.query(sql, params)).rows,
      async transaction(fn) {
        const client = await pool.connect();
        try { await client.query('BEGIN'); const result = await fn({query: async (s,p) => (await client.query(s,p)).rows}); await client.query('COMMIT'); return result; }
        catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
      }, close: () => pool.end()
    };
  }
  const embedded = new PGlite(options.dataDir ?? 'memory://');
  await embedded.waitReady;
  return {
    engine: 'PGlite (PostgreSQL embedded)',
    query: async <T>(sql: string, params?: any[]) => (await embedded.query<T>(sql,params)).rows,
    transaction: (fn) => embedded.transaction(tx => fn({query: async <T>(s: string,p?: any[]) => (await tx.query<T>(s,p)).rows})),
    close: () => embedded.close()
  };
}
export async function migrate(db: Database) {
  const dir = fileURLToPath(new URL('../migrations/', import.meta.url));
  await db.query('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
  for (const file of (await readdir(dir)).filter(f=>f.endsWith('.sql')).sort()) {
    const source = await readFile(`${dir}/${file}`, 'utf8');
    const checksum = createHash('sha256').update(source).digest('hex');
    const [applied] = await db.query('SELECT checksum FROM schema_migrations WHERE version=$1',[file]);
    if (applied) { if (applied.checksum !== checksum) throw new Error(`Migration checksum mismatch: ${file}`); continue; }
    await db.transaction(async tx => {
      // Migrations are trusted repository code; input data never reaches this path.
      for (const statement of splitMigration(source)) await tx.query(statement);
      await tx.query('INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)',[file,checksum]);
    });
  }
}
export async function verifySchema(db:Database) {
  const dir=fileURLToPath(new URL('../migrations/',import.meta.url));
  for(const file of (await readdir(dir)).filter(f=>f.endsWith('.sql')).sort()) {
    const checksum=createHash('sha256').update(await readFile(`${dir}/${file}`,'utf8')).digest('hex');
    const [applied]=await db.query('SELECT checksum FROM schema_migrations WHERE version=$1',[file]);
    if(applied?.checksum!==checksum)throw new Error(`Schema requires verified migration ${file}. Run npm run db:migrate with the migration identity before startup.`);
  }
}
// Handle the one dollar-quoted trigger function without splitting its semicolons.
function splitMigration(source: string): string[] {
  const parts: string[]=[]; let buffer=''; let quoted=false;
  for(let i=0;i<source.length;i++) {
    if(source.slice(i,i+2)==='$$') { quoted=!quoted; buffer+='$$'; i++; }
    else if(source[i]===';'&&!quoted) { if(buffer.trim())parts.push(buffer); buffer=''; }
    else buffer+=source[i];
  }
  if(buffer.trim())parts.push(buffer); return parts;
}
