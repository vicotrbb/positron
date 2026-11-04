import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {test} from 'node:test';
const root = process.env.POSITRON_TYPESCRIPT_SDK;
const sdk = await import(`${root}/dist/index.js`);
const fixtures = JSON.parse(await readFile(`${root}/api/query-golden-fixtures.json`,'utf8'));
const response = id => structuredClone(fixtures.responses.find(value => value.id === id).input);
test('query receipt deduplicates verified replay and rejects changed content atomically', () => {
  const tracker = new sdk.BatchTracker();
  const first = response('one-batch-complete');
  assert.equal(tracker.filter(first).length,1);
  assert.equal(tracker.filter(first).length,0);
  const changed = structuredClone(first);
  changed.events[1].batch.rows[0].cells[0].nativeValue.textValue = 'changed';
  assert.throws(() => tracker.filter(changed));
  assert.equal(tracker.filter(first).length,0);
});
test('Tail receipt requires explicit caller acknowledgement and preserves state on a gap', () => {
  const tracker = new sdk.BatchTracker('tail');
  const first = response('tail-single-incomplete');
  assert.equal(tracker.filter(first).length,1);
  assert.equal(tracker.filter(first).length,0);
  assert.deepEqual(tracker.acknowledgement(),{sequence:'0',digest:first.events[1].batch.digest});
  const next = response('tail-next-incomplete');
  const gap = structuredClone(next); gap.events[1].batch.sequence = '4';
  assert.throws(() => tracker.filter(gap));
  assert.equal(tracker.filter(next).length,1);
  assert.throws(() => tracker.filter(first));
});
