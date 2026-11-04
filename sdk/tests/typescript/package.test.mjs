import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = process.env.POSITRON_TYPESCRIPT_SDK;
const { PositronClient, apiVersion, schemaDigest, decode } = await import(`${root}/dist/index.js`);
test('package embeds the canonical identity and typed value codec', async () => {
  assert.equal(apiVersion, 'positron.v1');
  assert.equal(schemaDigest, (await readFile(`${root}/api/schema.sha256`, 'utf8')).trim());
  const value = decode('LogQueryValue', '{"integerValue":"-9223372036854775808"}');
  assert.deepEqual(value, {integerValue:'-9223372036854775808'});
  assert.throws(() => decode('LogQueryValue', '{"integerValue":"9223372036854775808"}'));
});
test('credentials cannot enter URL or diagnostics', () => {
  assert.throws(() => new PositronClient({endpoint:'https://user:secret@example.com'}), error => !String(error).includes('secret'));
  assert.throws(() => new PositronClient({endpoint:'http://example.com'}));
});

test('HTTP failure is bounded, ambiguous, never retried and does not leak credentials', async () => {
  const {createServer} = await import('node:http');
  let calls = 0;
  const server = createServer((request,response) => {
    calls++;
    if (calls === 1) { request.socket.destroy(); return; }
    response.writeHead(200,{'content-type':'application/json'}); response.end(' '.repeat(4097));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  const client = new PositronClient({endpoint,allowPlaintext:true});
  try {
    const secret = 'private-test-bearer';
    await assert.rejects(client.capabilityNegotiate({api_major:1},{bearer:secret}),error=>error.kind==='transport' && error.completionState==='COMPLETION_STATE_AMBIGUOUS' && !String(error).includes(secret));
    assert.equal(calls,1);
    await assert.rejects(client.capabilityNegotiate({api_major:1}),error=>error.kind==='transport');
    assert.equal(calls,2);
    await assert.rejects(client.capabilityNegotiate({api_major:1},{signal:AbortSignal.abort()}));
    assert.equal(calls,2);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});

test('administration preserves full uint64 JSON integers without number rounding', async () => {
  const {encode} = await import(`${root}/dist/index.js`);
  const request = {tenant:'00000000-0000-0000-0000-000000000001',expected_display_generation:18446744073709551615n,display_name:'wide integer',idempotency_key:'00000000-0000-0000-0000-000000000002'};
  const text = encode('TenantDisplayNameUpdateRequest',request);
  assert.match(text,/"expected_display_generation":18446744073709551615/);
  assert.equal(decode('TenantDisplayNameUpdateRequest',text).expected_display_generation,18446744073709551615n);
  assert.throws(()=>encode('TenantDisplayNameUpdateRequest',{...request,expected_display_generation:18446744073709551616n}));
});

test('new features negotiate every call and allow additive v1 schema skew',async()=>{
  const {createServer} = await import('node:http');
  const fixtures = JSON.parse(await readFile(`${root}/api/query-golden-fixtures.json`,'utf8'));
  const query = fixtures.responses.find(item=>item.id==='one-batch-complete').input;
  let available = false, calls = 0, negotiated = 0;
  const server = createServer((request,response)=>{
    response.setHeader('content-type','application/json');
    if(request.url==='/v1/capabilities:negotiate') { negotiated++; response.end(JSON.stringify({api_major:1,schema_digest:'0'.repeat(64),capability:4,availability:available?1:3,refusal:null})); }
    else { calls++; response.end(JSON.stringify(query)); }
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const client = new PositronClient({endpoint:`http://127.0.0.1:${server.address().port}`,allowPlaintext:true});
  try {
    const request = {resume:'AP8=',batchLimit:1};
    await assert.rejects(client.logQuerySession(request),error=>error.failure==='UnsupportedFeature'); assert.equal(calls,0);
    available=true; await client.logQuerySession(request); assert.equal(calls,1);
    available=false; await assert.rejects(client.logQuerySession(request),error=>error.failure==='UnsupportedFeature');
    assert.equal(calls,1); assert.equal(negotiated,3);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});
