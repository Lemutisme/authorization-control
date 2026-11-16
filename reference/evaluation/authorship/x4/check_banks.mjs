/** Recompute JavaScript serialization hashes of retained fresh repair samples. */
import {readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {hash} from './pi_draw.mjs';
const root=process.argv[2];let checked=0;const findings=[];
for(const entry of await readdir(root,{withFileTypes:true})){
 if(!entry.isDirectory())continue;
 const directory=join(root,entry.name,'repair-bank');let files;
 try{files=await readdir(directory);}catch(error){if(error.code==='ENOENT')continue;throw error;}
 for(const filename of files.filter(name=>name.endsWith('.json'))){
  const record=JSON.parse(await readFile(join(directory,filename),'utf8'));checked++;
  if(filename!==record.sample_key+'.json'||hash(record.message)!==record.response_sha256)findings.push([entry.name,filename,'sample_identity']);
 }
}
console.log(JSON.stringify({checked,findings}));if(findings.length)process.exitCode=1;
