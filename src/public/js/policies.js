(() => {
  'use strict';
  const root = document.getElementById('policy-app');
  if (!root) return;
  const texts = JSON.parse(document.getElementById('policy-translations').textContent);
  const $ = (id) => document.getElementById(id);
  const form = $('policy-form');
  const api = root.dataset.api;
  const limit = 25;
  const fields = ['name', 'description', 'resource_type', 'actions', 'effect', 'priority', 'active', 'definition'];
  const state = { policy: null, dirty: false, offset: 0, bindingOffset: 0, userOffset: 0, bindings: [], listRequest: 0, busy: false };
  const text = (key, values = {}) => Object.entries(values).reduce((s, [k, v]) => s.replaceAll(`{${k}}`, v), texts[key] || key);
  const example = { example: { values: ['value'] } };

  function message(value = '', error = false) {
    $('policy-message').textContent = value;
    $('policy-message').dataset.error = String(error);
    $('policy-message').setAttribute('role', error ? 'alert' : 'status');
  }
  function node(tag, content, className) {
    const element = document.createElement(tag);
    if (content !== undefined) element.textContent = content;
    if (className) element.className = className;
    return element;
  }
  function button(label, action) {
    const element = node('button', label, 'btn btn-secondary btn-small');
    element.type = 'button';
    element.addEventListener('click', () => run(action, element));
    return element;
  }
  async function request(url, method = 'GET', body) {
    let response;
    try {
      response = await fetch(url, {
        method, credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': root.dataset.csrf },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    } catch (_) { throw new Error(text('network_failure')); }
    let result;
    try { result = PolicyJSON.response(await response.text()); } catch (_) { throw new Error(`${text('failure')} (${response.status})`); }
    if (!response.ok) {
      const error = new Error(result.error || text('failure'));
      error.details = result;
      throw error;
    }
    return result;
  }
  function showError(error) {
    message(error.message, true);
    if (error.details?.code === 'stale_revision') $('policy-conflict').hidden = false;
    Object.entries(error.details?.fields || {}).forEach(([key, value]) => {
      const field = form.elements.namedItem(key);
      if (field) field.setAttribute('aria-invalid', 'true');
      if ($(`error-${key}`)) $(`error-${key}`).textContent = value;
    });
  }
  async function run(action, control) {
    if (control) control.disabled = true;
    try { await action(); } catch (error) { showError(error); }
    finally { if (control?.isConnected) control.disabled = false; }
  }
  function confirmAction(value) {
    const dialog = $('policy-confirm');
    $('policy-confirm-text').textContent = value;
    return new Promise((resolve) => {
      const finish = (accepted) => { dialog.close(); resolve(accepted); };
      $('policy-confirm-yes').onclick = () => finish(true);
      $('policy-confirm-no').onclick = () => finish(false);
      dialog.oncancel = (event) => { event.preventDefault(); finish(false); };
      dialog.showModal();
      $('policy-confirm-no').focus();
    });
  }
  async function edit(action, discard = false) {
    if (state.busy) return;
    state.busy = true;
    const controls = [...form.querySelectorAll('input, select, textarea, button'), $('policy-new'), $('policy-back')];
    const disabled = controls.map((control) => control.disabled);
    controls.forEach((control) => { control.disabled = true; });
    try {
      if (!discard || !state.dirty || await confirmAction(text('unsaved_confirm'))) await action();
    } finally {
      controls.forEach((control, index) => { control.disabled = disabled[index]; });
      state.busy = false;
      if (!$('policy-editor').hidden) form.elements.name.focus();
    }
  }
  function dirty(value = true) {
    state.dirty = value;
    $('policy-save-state').textContent = value ? text('unsaved') : text('saved');
  }
  function clearErrors() {
    form.querySelectorAll('[aria-invalid]').forEach((field) => field.removeAttribute('aria-invalid'));
    form.querySelectorAll('.policy-error').forEach((field) => { field.textContent = ''; });
    $('policy-conflict').hidden = true;
  }
  function pagination(prefix, page) {
    $(prefix + '-prev').disabled = page.offset === 0;
    $(prefix + '-next').disabled = page.offset + page.limit >= page.total;
    $(prefix + '-page-info').textContent = text('page_info', { start: page.total ? page.offset + 1 : 0, end: Math.min(page.offset + page.limit, page.total), total: page.total });
  }
  async function loadList() {
    const serial = ++state.listRequest;
    $('policy-list-state').textContent = text('loading');
    const query = new URLSearchParams(new FormData($('policy-filters')));
    query.set('limit', limit); query.set('offset', state.offset);
    try {
      const page = await request(`${api}?${query}`);
      if (serial !== state.listRequest) return;
      $('policy-rows').replaceChildren();
      page.data.forEach((policy) => {
        const row = node('tr');
        const values = { name: policy.name, type: policy.type, resource_type: policy.resource_type, actions: policy.actions.join(', '), effect: text(policy.effect), state: text(policy.active ? 'enabled' : 'disabled'), priority: policy.priority, assignments: policy.assignment_count, updated: new Date(policy.updated_at).toLocaleString() };
        Object.entries(values).forEach(([key, value]) => {
          const cell = node('td'); cell.dataset.label = text(key);
          if (key === 'effect' || key === 'state') cell.append(node('span', value, `policy-badge ${key === 'effect' ? policy.effect : ''}`));
          else cell.textContent = value;
          row.append(cell);
        });
        const cell = node('td'); const actions = node('div', undefined, 'policy-row-actions');
        actions.append(button(text('open'), () => openPolicy(policy.id)), button(text('duplicate'), () => duplicate(policy)), button(text(policy.active ? 'disable' : 'enable'), () => toggle(policy)));
        const remove = button(text('delete'), async () => {
          if (!await confirmAction(text('delete_confirm'))) return;
          await request(`${api}/${policy.id}`, 'DELETE', { expected_revision: policy.revision });
          message(text('deleted')); await loadList();
        });
        remove.disabled = policy.active || policy.assignment_count > 0;
        if (remove.disabled) remove.title = text('delete_blocked');
        actions.append(remove); cell.append(actions); row.append(cell); $('policy-rows').append(row);
      });
      $('policy-list-state').textContent = page.total ? '' : text('empty');
      pagination('policy', page);
    } catch (error) { if (serial === state.listRequest) $('policy-list-state').textContent = text('failure'); throw error; }
  }
  function fill(policy) {
    state.policy = policy;
    clearErrors();
    fields.forEach((key) => {
      const field = form.elements.namedItem(key);
      if (key === 'active') field.checked = policy.active;
      else if (key === 'definition') field.value = JSON.stringify(policy.definition, null, 2);
      else if (key === 'actions') { field.value = policy.actions.join(', '); field.defaultValue = field.value; }
      else field.value = policy[key] ?? '';
    });
    $('policy-editor-title').textContent = policy.id ? policy.name : text('new');
    $('policy-revision').textContent = policy.id ? `${text('revision')} ${policy.revision} · ${new Date(policy.updated_at).toLocaleString()}` : '';
    $('policy-list').hidden = true; $('policy-editor').hidden = false;
    $('policy-assignments').hidden = !policy.id;
    $('policy-bindings').replaceChildren(); $('policy-user-results').replaceChildren();
    $('policy-user-state').textContent = ''; $('user-page-info').textContent = '';
    $('user-prev').disabled = true; $('user-next').disabled = true;
    state.bindingOffset = 0; state.userOffset = 0; state.bindings = [];
    dirty(!policy.id);
  }
  async function openPolicy(id) {
    await edit(async () => {
      const policy = await request(`${api}/${id}`);
      fill(policy); message();
      await loadBindings();
    }, true);
  }
  function definition() {
    try {
      const parsed = PolicyJSON.parse(form.elements.definition.value);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error();
      $('error-definition').textContent = '';
      form.elements.definition.removeAttribute('aria-invalid');
      return parsed;
    } catch (_) {
      $('error-definition').textContent = text('invalid_json');
      form.elements.definition.setAttribute('aria-invalid', 'true');
      throw new Error(text('invalid_json'));
    }
  }
  function content(policy) { return { ...Object.fromEntries(fields.map((key) => [key, policy[key]])), type: policy.type, schema_version: policy.schema_version }; }
  async function confirmState(policy) {
    const page = await request(`${api}/${policy.id}/assignments?limit=25`);
    let description = text('state_confirm', { count: page.total });
    page.data.forEach((user) => { description += `\n${user.login} · #${user.id}`; });
    if (page.total > page.data.length) description += '\n' + text('more_bindings', { count: page.total - page.data.length });
    return confirmAction(description);
  }
  async function toggle(policy) {
    if (!await confirmState(policy)) return;
    await request(`${api}/${policy.id}`, 'PATCH', { active: !policy.active, expected_revision: policy.revision });
    message(text('saved')); await loadList();
  }
  async function duplicate(policy) {
    await edit(async () => {
      const source = await request(`${api}/${policy.id}`);
      const created = await request(api, 'POST', { ...content(source), name: source.name.slice(0, 180) + text('copy_suffix'), active: false });
      fill(created); message(text('duplicated')); await loadBindings();
    }, true);
  }
  async function loadBindings() {
    const id = state.policy.id;
    $('policy-assignment-state').textContent = text('loading');
    try {
      const page = await request(`${api}/${id}/assignments?limit=${limit}&offset=${state.bindingOffset}`);
      if (state.policy.id !== id) return;
      state.bindings = page.data.map((user) => user.id);
      state.policy.assignment_count = page.total;
      $('policy-bindings').replaceChildren();
      page.data.forEach((user) => {
        const row = node('li'); row.append(node('span', `${user.login}${user.name ? ' · ' + user.name : ''} · #${user.id}`));
        row.append(button(text('remove'), async () => {
          if (!await confirmAction(text('remove_confirm'))) return;
          await request(`${api}/${id}/assignments/users/${user.id}`, 'DELETE');
          message(text('removed')); await loadBindings();
        }));
        $('policy-bindings').append(row);
      });
      $('policy-assignment-state').textContent = page.total ? '' : text('no_assignments');
      pagination('binding', page);
    } catch (error) { $('policy-assignment-state').textContent = text('failure'); throw error; }
  }
  async function searchUsers() {
    const id = state.policy.id;
    $('policy-user-state').textContent = text('loading');
    const query = new URLSearchParams(new FormData($('policy-user-search')));
    query.set('limit', limit); query.set('offset', state.userOffset);
    try {
      const page = await request(`${root.dataset.usersApi}?${query}`);
      if (state.policy.id !== id) return;
      $('policy-user-results').replaceChildren();
      page.data.forEach((user) => {
        const row = node('li'); row.append(node('span', `${user.login}${user.name ? ' · ' + user.name : ''} · #${user.id}`));
        const add = button(text('add'), async () => {
          await request(`${api}/${id}/assignments/users/${user.id}`, 'PUT');
          message(text('assigned')); await loadBindings(); await searchUsers();
        });
        add.disabled = state.bindings.includes(user.id);
        if (add.disabled) add.textContent = text('assigned');
        row.append(add); $('policy-user-results').append(row);
      });
      $('policy-user-state').textContent = page.total ? '' : text('no_users');
      pagination('user', page);
    } catch (error) { $('policy-user-state').textContent = text('failure'); throw error; }
  }

  form.addEventListener('input', () => dirty());
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (state.busy) return;
    run(async () => {
      clearErrors();
      const values = Object.fromEntries(new FormData(form));
      values.active = form.elements.active.checked;
      values.priority = Number(values.priority);
      values.type = state.policy.type; values.schema_version = state.policy.schema_version;
      values.actions = values.actions === form.elements.actions.defaultValue ? state.policy.actions : values.actions.split(',').map((value) => value.trim()).filter(Boolean);
      values.definition = definition();
      await edit(async () => {
        if (state.policy.id && values.active !== state.policy.active && !await confirmState(state.policy)) return;
        $('policy-save-state').textContent = text('saving');
        try {
          const saved = await request(state.policy.id ? `${api}/${state.policy.id}` : api, state.policy.id ? 'PATCH' : 'POST', state.policy.id ? { ...values, expected_revision: state.policy.revision } : values);
          fill(saved); message(text('saved')); await loadBindings();
        } catch (error) { $('policy-save-state').textContent = text('failure'); throw error; }
      });
    }, $('policy-save'));
  });
  $('policy-new').onclick = () => run(() => edit(async () => {
    fill({ name: '', description: '', type: 'filter', resource_type: 'resource', actions: ['read'], effect: 'allow', active: false, priority: 0, schema_version: 1, definition: {} }); message();
  }, true));
  $('policy-back').onclick = () => run(() => edit(async () => {
    dirty(false); $('policy-editor').hidden = true; $('policy-list').hidden = false; message(); await loadList();
  }, true));
  $('policy-reload').onclick = () => run(() => openPolicy(state.policy.id));
  $('policy-format').onclick = () => run(async () => { form.elements.definition.value = JSON.stringify(definition(), null, 2); dirty(); });
  $('policy-example').onclick = () => run(async () => {
    if (!await confirmAction(text('example_confirm'))) return;
    form.elements.definition.value = JSON.stringify(example, null, 2); dirty(); definition();
  });
  $('policy-filters').onsubmit = (event) => { event.preventDefault(); state.offset = 0; run(loadList); };
  $('policy-user-search').onsubmit = (event) => { event.preventDefault(); state.userOffset = 0; run(searchUsers); };
  [['policy', 'offset', loadList], ['binding', 'bindingOffset', loadBindings], ['user', 'userOffset', searchUsers]].forEach(([prefix, key, loader]) => {
    $(prefix + '-prev').onclick = () => { state[key] = Math.max(0, state[key] - limit); run(loader); };
    $(prefix + '-next').onclick = () => { state[key] += limit; run(loader); };
  });
  window.addEventListener('beforeunload', (event) => { if (state.dirty || state.busy) { event.preventDefault(); event.returnValue = ''; } });
  root.querySelectorAll('a').forEach((link) => link.addEventListener('click', (event) => {
    if (!state.dirty && !state.busy) return;
    event.preventDefault(); run(() => edit(async () => { dirty(false); window.location.assign(link.href); }, true));
  }));
  run(loadList);
})();
