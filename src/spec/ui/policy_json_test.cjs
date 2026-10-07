const { test } = require('node:test');
const assert = require('node:assert/strict');
require('../../public/js/policy-json.js');

test('formatting and saving preserve large integers, decimal literals, arrays, and Unicode', () => {
  const source = '{"integer":9007199254740993,"decimal":0.1234567890123456789,"nested":[{"not":null}],"source":"Юникод"}';
  assert.equal(JSON.stringify(PolicyJSON.parse(source)), source);
  assert.equal(JSON.stringify(PolicyJSON.parse(JSON.stringify(PolicyJSON.parse(source), null, 2))), source);
});

test('API response parsing preserves definition numbers while keeping ordinary metadata usable', () => {
  const result = PolicyJSON.response('{"id":1,"priority":0.5,"revision":2,"definition":{"number":9007199254740993}}');
  assert.equal(result.id, 1);
  assert.equal(result.priority, 0.5);
  assert.equal(result.revision, 2);
  assert.equal(JSON.stringify(result.definition), '{"number":9007199254740993}');
});

test('metadata lists keep ordinary numbers usable', () => {
  const result = PolicyJSON.response('{"total":1,"data":[{"id":1,"priority":0.5,"assignment_count":2}]}');
  assert.deepEqual(result, { total: 1, data: [{ id: 1, priority: 0.5, assignment_count: 2 }] });
});

test('invalid JSON is rejected and older browsers cannot silently round large integers', () => {
  assert.throws(() => PolicyJSON.parse('{invalid'));
  const original = JSON.rawJSON;
  JSON.rawJSON = undefined;
  try { assert.throws(() => PolicyJSON.parse('{"number":9007199254740993}'), /cannot safely edit/); }
  finally { JSON.rawJSON = original; }
});
