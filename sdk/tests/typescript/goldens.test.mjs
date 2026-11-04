import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {test} from 'node:test';
const root = process.env.POSITRON_TYPESCRIPT_SDK;
const sdk = await import(`${root}/dist/index.js`);
const fixture = JSON.parse(await readFile(`${root}/api/query-golden-fixtures.json`, 'utf8'));
for (const value of fixture.representations) test(`canonical representation ${value.id}`, () => {
  if (value.accepted) assert.deepEqual(sdk.decode(value.type, value.input), value.canonical);
  else assert.throws(() => sdk.decode(value.type, value.input));
});
for (const value of fixture.responses) test(`canonical response ${value.id}`, () => {
  if (value.accepted) sdk.decodeQuery(JSON.stringify(value.input), value.mode);
  else assert.throws(() => sdk.decodeQuery(JSON.stringify(value.input), value.mode));
});
for (const value of fixture.errors) test(`canonical error ${value.id}`, () => {
  const error = sdk.queryError(value.status, JSON.stringify(value.input), value.cancellation ?? false);
  assert.equal(error.failure, value.failure);
  assert.equal(error.retryClass, value.retryClass);
  assert.equal(error.completionState, value.completionState);
});
