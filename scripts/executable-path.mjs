import {statSync} from 'node:fs';
import {resolve} from 'node:path';

/** Keep the invoked filename: rustup and other dispatchers select a tool from argv[0]. */
export function findExecutable(name,{searchPath=process.env.PATH??'',platform=process.platform}={}) {
  const suffixes=platform==='win32'?['.exe','.cmd','.bat','']:[''];
  for(const entry of searchPath.split(platform==='win32'?';':':')) {
    const folder=entry.replace(/^"|"$/g,'');
    if(!folder)continue;
    for(const suffix of suffixes) {
      const candidate=resolve(folder,name+suffix);
      try{if(statSync(candidate).isFile())return candidate;}catch{}
    }
  }
  return null;
}
