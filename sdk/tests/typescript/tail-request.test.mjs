import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {test} from 'node:test';
const root = process.env.POSITRON_TYPESCRIPT_SDK;
const {PositronClient, WireError} = await import(`${root}/dist/index.js`);
const fixtures = JSON.parse(await readFile(`${root}/api/query-golden-fixtures.json`, 'utf8'));

test('Tail historicalRows is a bounded optional integer', async () => {
  const response = fixtures.responses.find(item => item.id === 'tail-single-incomplete').input;
  const query = {pipeline:'pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all', budget:response.events[0].header.effectiveBudget};
  const requests = [];
  const server = createServer(async (request, reply) => {
    let body = '';
    for await (const part of request) body += part;
    requests.push({path:request.url, body:JSON.parse(body)});
    reply.setHeader('content-type', 'application/json');
    reply.end(JSON.stringify(request.url === '/v1/capabilities:negotiate' ? {api_major:1,schema_digest:'a'.repeat(64),capability:5,availability:1,refusal:null} : response));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = new PositronClient({endpoint:`http://127.0.0.1:${server.address().port}`,allowPlaintext:true});
  try {
    for (const tail of [{query}, {query,historicalRows:1}, {query,historicalRows:128}]) {
      const request = {tail,batchLimit:1};
      assert.deepEqual(await client.logQuerySession(request), response);
      assert.deepEqual(requests.at(-1), {path:'/v1/logs:session',body:request});
    }
    const before = requests.length;
    for (const historicalRows of [0,-1,129,4294967295,4294967296,true,false,1.5,'1']) {
      await assert.rejects(client.logQuerySession({tail:{query,historicalRows},batchLimit:1}), WireError);
    }
    await assert.rejects(client.logQuerySession({tail:{query,historicalRows:1,cursor:'YQ=='},batchLimit:1}), WireError);
    assert.equal(requests.length, before);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
