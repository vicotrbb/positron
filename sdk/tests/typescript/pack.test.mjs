import assert from 'node:assert/strict';
import {mkdtemp,cp,readFile,writeFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {test} from 'node:test';
const root = process.env.POSITRON_TYPESCRIPT_SDK;
test('two independent npm packages reproduce and install into a clean typed consumer',async()=>{
  const temp = await mkdtemp(path.join(tmpdir(),'positron-npm-'));
  try {
    const archives = [];
    for (const name of ['first','second']) {
      const source = path.join(temp,name); await mkdir(source);
      for (const file of ['package.json','README.md','LICENSE','api','src','tsconfig.json','examples']) await cp(path.join(root,file),path.join(source,file),{recursive:true});
      const manifest = JSON.parse(await readFile(path.join(source,'package.json'),'utf8'));
      // Explicitly private fixture identity. This is never publication evidence.
      manifest.gitHead = '0123456789abcdef0123456789abcdef01234567';
      await writeFile(path.join(source,'package.json'),JSON.stringify(manifest));
      execFileSync(path.join(root,'node_modules/.bin/tsc'),['-p','tsconfig.json','--typeRoots',path.join(root,'node_modules/@types')],{cwd:source});
      const result = JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json'],{cwd:source,encoding:'utf8'}));
      archives.push(path.join(source,result[0].filename));
    }
    assert.deepEqual(await readFile(archives[0]),await readFile(archives[1]));
    const consumer = path.join(temp,'consumer'); await mkdir(consumer);
    await writeFile(path.join(consumer,'package.json'),'{"private":true,"type":"module"}');
    execFileSync('npm',['install','--offline','--ignore-scripts','--no-audit','--no-fund',archives[0]],{cwd:consumer});
    execFileSync('node',['--input-type=module','-e',"import {PositronClient,apiVersion,BatchTracker} from '@positron/sdk'; if(apiVersion!=='positron.v1'||!new PositronClient({endpoint:'https://example.invalid'})||!new BatchTracker()) process.exit(1)"],{cwd:consumer});
    await cp(path.join(root,'examples/query.ts'),path.join(consumer,'query.ts'));
    await writeFile(path.join(consumer,'example.ts'),"import {PositronClient, LogQuerySessionRequest} from '@positron/sdk'; const client = new PositronClient({endpoint:'https://localhost:8443'}); const request: LogQuerySessionRequest = {resume:'AP8=',batchLimit:1}; void client.logQuerySession(request);\n");
    execFileSync(path.join(root,'node_modules/.bin/tsc'),['--noEmit','--strict','--target','ES2022','--module','NodeNext','example.ts','query.ts'],{cwd:consumer});
  } finally { await rm(temp,{recursive:true,force:true}); }
});
