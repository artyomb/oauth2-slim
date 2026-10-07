const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const policy = { id: 1, name: 'Existing policy', description: '', type: 'filter', resource_type: 'resource', actions: ['read'], effect: 'allow', priority: 0, active: false, schema_version: 1, definition: { saved: true }, revision: 1, assignment_count: 0, updated_at: '2026-10-07T00:00:00Z' };
const tick = () => new Promise(resolve => setImmediate(resolve));
const reply = (value, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(value) });
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function ui(intercept = () => undefined) {
  const nodes = new Map();
  const created = [];
  const requests = [];
  function element(tag = 'div') {
    return { tag, value: '', textContent: '', dataset: {}, children: [], handlers: {}, disabled: false, isConnected: true,
      addEventListener(name, callback) { this.handlers[name] = callback; },
      append(...items) { this.children.push(...items); },
      replaceChildren(...items) { this.children = items; },
      setAttribute() {}, removeAttribute() {}, focus() {}, querySelectorAll() { return []; },
      showModal() { this.open = true; }, close() { this.open = false; }
    };
  }
  function get(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); }
  get('policy-app').dataset = { api: '/policies', usersApi: '/users', csrf: 'test' };
  get('policy-translations').textContent = '{}';
  get('policy-editor').hidden = true;
  const form = get('policy-form');
  form.elements = Object.fromEntries(['name', 'description', 'resource_type', 'actions', 'effect', 'priority', 'active', 'definition'].map(key => [key, element('input')]));
  Object.defineProperty(form.elements, 'namedItem', { value: key => form.elements[key] });
  form.querySelectorAll = selector => selector === 'input, select, textarea, button' ? [...Object.values(form.elements), get('policy-save')] : [];
  vm.runInNewContext(fs.readFileSync(require.resolve('../../public/js/policies.js'), 'utf8'), {
    document: { getElementById: get, createElement(tag) { const node = element(tag); created.push(node); return node; } },
    window: { addEventListener() {} }, URLSearchParams,
    FormData: class {
      constructor(target) { this.target = target; }
      *[Symbol.iterator]() {
        for (const [key, field] of Object.entries(this.target.elements || {})) {
          if (!field.disabled && key !== 'active') yield [key, field.value];
        }
      }
    },
    PolicyJSON: { parse: JSON.parse, response: JSON.parse },
    fetch: async (url, options) => {
      requests.push({ url, ...options });
      const intercepted = intercept(url, options);
      if (intercepted !== undefined) return intercepted;
      if (url === '/policies/1') return reply(policy);
      const data = url.startsWith('/policies?') ? [policy] : [];
      return reply({ data, offset: 0, limit: 25, total: data.length });
    }
  });
  await tick();
  return { get, form, requests, click: label => created.find(node => node.tag === 'button' && node.textContent === label).handlers.click(),
    submit: () => { form.handlers.submit({ preventDefault() {} }); } };
}

test('opening a policy blocks overlapping navigation until the request finishes', async () => {
  const pending = deferred();
  const app = await ui(url => url === '/policies/1' ? pending.promise : undefined);
  const opening = app.click('open');
  assert.equal(app.get('policy-new').disabled, true);
  await app.get('policy-new').onclick();
  await app.click('open');
  assert.equal(app.requests.filter(request => request.url === '/policies/1').length, 1);
  pending.resolve(reply(policy));
  await opening;
  assert.equal(app.form.elements.name.value, policy.name);
  assert.equal(app.get('policy-new').disabled, false);
  await app.get('policy-new').onclick();
  app.form.elements.name.value = 'Unsaved new draft';
  await tick();
  assert.equal(app.form.elements.name.value, 'Unsaved new draft');
});

test('duplicating blocks navigation and creates a disabled policy without copying assignments', async () => {
  const pending = deferred();
  const app = await ui((url, options) => options.method === 'POST' ? pending.promise : undefined);
  const duplicating = app.click('duplicate');
  await tick();
  assert.equal(app.get('policy-new').disabled, true);
  const body = JSON.parse(app.requests.find(request => request.method === 'POST').body);
  assert.equal(body.active, false);
  assert.equal(body.type, 'filter');
  assert.equal(body.schema_version, 1);
  assert.equal('assignment_count' in body, false);
  pending.resolve(reply({ ...policy, id: 2, name: body.name }));
  await duplicating;
  assert.equal(app.form.elements.name.value, body.name);
});

test('saving locks navigation before awaiting the state-change confirmation', async () => {
  const pending = deferred();
  let confirmPending = false;
  const app = await ui(url => confirmPending && url.includes('/assignments') ? pending.promise : undefined);
  await app.click('open');
  app.form.elements.active.checked = true;
  app.form.handlers.input();
  confirmPending = true;
  app.submit();
  assert.equal(app.get('policy-new').disabled, true);
  assert.equal(app.form.elements.name.disabled, true);
  await app.get('policy-new').onclick();
  pending.resolve(reply({ data: [], total: 0, limit: 25, offset: 0 }));
  await tick();
  assert.equal(app.get('policy-confirm').open, true);
  app.get('policy-confirm-no').onclick();
  await tick();
  assert.equal(app.form.elements.name.value, policy.name);
  assert.equal(app.form.elements.active.checked, true);
  assert.equal(app.get('policy-new').disabled, false);
  assert.equal(app.requests.some(request => request.method === 'PATCH'), false);
});

test('failed saves preserve edits and unlock controls for retry', async () => {
  const app = await ui((url, options) => options.method === 'PATCH' ? reply({ error: 'Storage unavailable' }, 503) : undefined);
  await app.click('open');
  app.form.elements.name.value = 'Unsaved edit';
  app.form.handlers.input();
  app.submit();
  await tick();
  assert.equal(app.form.elements.name.value, 'Unsaved edit');
  assert.equal(app.form.elements.name.disabled, false);
  assert.equal(app.get('policy-save').disabled, false);
  assert.equal(app.get('policy-message').textContent, 'Storage unavailable');
  const body = JSON.parse(app.requests.find(request => request.method === 'PATCH').body);
  assert.equal(body.name, 'Unsaved edit');
  assert.equal(body.type, 'filter');
  assert.equal(body.schema_version, 1);
});

test('editing metadata preserves existing exact action names when the action field is unchanged', async () => {
  const existing = { ...policy, actions: ['read,write', ' spaced '] };
  const app = await ui((url, options) => url === '/policies/1' ? reply(existing) : undefined);
  await app.click('open');
  app.form.elements.description.value = 'Metadata edit';
  app.form.handlers.input();
  app.submit();
  await tick();
  const body = JSON.parse(app.requests.find(request => request.method === 'PATCH').body);
  assert.deepEqual(body.actions, existing.actions);
  assert.equal(body.description, 'Metadata edit');
});
