import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
const temp = await mkdtemp(path.join(tmpdir(),'positron-live-npm-'));
const source = fileURLToPath(new URL('../../typescript',import.meta.url));
const packed = JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd:source,encoding:'utf8'}));
const consumer = path.join(temp,'consumer'); await mkdir(consumer);
await writeFile(path.join(consumer,'package.json'),'{"private":true,"type":"module"}');
execFileSync('npm',['install','--offline','--ignore-scripts','--no-audit','--no-fund',path.join(temp,packed[0].filename)],{cwd:consumer});
const {PositronClient,BatchTracker,terminalStatus,QueryError} = await import(pathToFileURL(path.join(consumer,'node_modules/@positron/sdk/dist/index.js')));
let text = '';
for await (const part of process.stdin) text += part;
const {endpoint,bearer,admin} = JSON.parse(text);
const client = new PositronClient({endpoint,allowPlaintext:true});
const options = {bearer,timeoutMs:30000};
const query = {pipeline:'pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2',budget:{scannedBytes:'1048576',decodedRecords:'16',outputRows:'16',outputBytes:'16384',memoryBytes:'1048576',cpuWorkUnits:'16',wallSeconds:'5',maximumTimeRangeNanoseconds:'100'}};
async function admitted(call) {
  for (let attempts=0; attempts<5; attempts++) {
    try { return await call(); }
    catch (error) { if (!(error instanceof QueryError) || error.failure !== 'CapacityUnavailable') throw error; await new Promise(resolve=>setTimeout(resolve,1000)); }
  }
  throw new Error('Query admission exhausted');
}
let phase = 'old capability';
try {
  // Old v1 client request still negotiates; SDK does not require exact digest equality.
  const old = await client.capabilityNegotiate({api_major:1}); assert.equal(old.api_major,1);
  phase = 'unsupported capability';
  const unsupported = await client.capabilityNegotiate({api_major:1,capability:3}); assert.equal(unsupported.availability,3);
  phase = 'execute';
  const first = await admitted(()=>client.logQueryExecute(query,options));
  assert.equal(terminalStatus(first.events.at(-1).terminal).kind,'complete');
  assert.equal(new BatchTracker().filter(first).flatMap(batch=>batch.rows).length,2);
  const tracker = new BatchTracker();
  phase = 'session';
  const page = await admitted(()=>client.logQuerySession({execute:query,batchLimit:1},options));
  tracker.filter(page);
  const terminal = terminalStatus(page.events.at(-1).terminal); assert.equal(terminal.kind,'continued');
  phase = 'resume';
  const next = await admitted(()=>client.logQuerySession({resume:terminal.cursor,batchLimit:1},options));
  assert.equal(tracker.filter(next).flatMap(batch=>batch.rows).length,1,JSON.stringify({firstRows:page.events.filter(event=>event.batch).flatMap(event=>event.batch.rows).length,reason:next.events.at(-1).terminal.reason,stats:next.events.at(-1).terminal.stats}));
  const resumed = terminalStatus(next.events.at(-1).terminal);
  assert.equal(resumed.kind,'complete');
  assert.deepEqual(next.events[0].header.snapshot,page.events[0].header.snapshot);
  phase = 'cancel page';
  const cancelledPage = await admitted(()=>client.logQuerySession({execute:query,batchLimit:1},options));
  const original = cancelledPage.events[0].header.initialCursor;
  phase = 'cancel';
  assert.equal((await client.logQueryCancel({query:original},options)).cancelled,true);
  const tailQuery = {...query,pipeline:query.pipeline.replace('limit 2','limit all'),budget:{...query.budget,wallSeconds:'60'}};
  phase = 'tail';
  const tail = await admitted(()=>client.logQuerySession({tail:{query:tailQuery},batchLimit:1},options));
  new BatchTracker('tail').filter(tail);
  const tailCursor = tail.events.at(-1).terminal.continuationCursor;
  assert.equal((await client.logQueryCancel({tail:tailCursor},options)).cancelled,true);
  await assert.rejects(client.logQueryExecute(query,{bearer:'invalid'}),error=>error.failure==='AuthenticationRejected' && error.completionState==='COMPLETION_STATE_REJECTED');
  phase = 'tenant list';
  const tenants = await client.tenantList({}, {bearer:admin}); assert.ok(Array.isArray(tenants.tenants));
  console.log('TypeScript live conformance passed');
} catch(error) {
  // Never print input, credentials, cursor or raw response diagnostics.
  console.error(`TypeScript conformance failed at ${phase}: ${error.name} ${error.failure ?? ''} ${error.message}`);
  process.exitCode=1;
} finally { await rm(temp,{recursive:true,force:true}); }
