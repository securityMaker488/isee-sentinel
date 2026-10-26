import {readFile,writeFile,mkdir} from 'node:fs/promises';
const lock=JSON.parse(await readFile(new URL('../package-lock.json',import.meta.url),'utf8'));
const packages=Object.entries(lock.packages).filter(([path,p])=>path&&p.version&&!p.link).map(([path,p])=>({path,name:p.name??path.split('node_modules/').at(-1),version:p.version,license:p.license??'UNKNOWN — review required',integrity:p.integrity??null,dev:!!p.dev,optional:!!p.optional}));
await mkdir(new URL('../docs/generated/',import.meta.url),{recursive:true});
await writeFile(new URL('../docs/generated/dependencies.json',import.meta.url),JSON.stringify({generatedAt:new Date().toISOString(),source:'package-lock.json',notice:'Inventário técnico; não constitui parecer jurídico ou SBOM CycloneDX.',packages},null,2));
console.info(`Recorded ${packages.length} locked dependency entries.`);
