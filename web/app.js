const state = {tenants: [], applications: [], keys: [], contracts: [], users: [], pending_users: [], selectedTenant: ''};
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
}[c]));
const date = value => value ? new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
}).format(new Date(value)) : 'Never';
const notice = (message, error = false) => {
    const el = $('#notice');
    el.textContent = message;
    el.hidden = false;
    el.style.borderColor = error ? 'var(--danger)' : 'var(--accent)';
    setTimeout(() => el.hidden = true, 5000)
};

async function api(path, options = {}) {
    const response = await fetch(path, {
        credentials: 'same-origin', ...options,
        headers: {'Content-Type': 'application/json', ...(options.headers || {})}
    });
    if (response.status === 401) {
        location.href = '/login';
        throw new Error('Session expired')
    }
    const body = response.status === 204 ? null : await response.json();
    if (!response.ok) throw new Error(body?.error || `Request failed (${response.status})`);
    return body;
}

async function load() {
    const data = await api('/api/v1/dashboard');
    Object.assign(state, data);
    if (!state.tenants.some(tenant => tenant.id === state.selectedTenant)) state.selectedTenant = state.tenants[0]?.id || '';
    $('#identity').textContent = data.user.display_name || data.user.email;
    render();
}

function render() {
    const tenantID = state.selectedTenant;
    const selectedTenant = state.tenants.find(item => item.id === tenantID);
    const canManageTenant = selectedTenant && ['owner', 'admin'].includes(selectedTenant.role);
    const tenantApps = state.applications.filter(item => item.tenant_id === tenantID);
    const tenantAppIDs = new Set(tenantApps.map(item => item.id));
    const tenantKeys = state.keys.filter(item => tenantAppIDs.has(item.application_id));
    const tenantContracts = state.contracts.filter(item => tenantAppIDs.has(item.application_id));
    const tenantUsers = state.users.filter(item => item.tenant_id === tenantID);
    const apps = new Map(state.applications.map(item => [item.id, item]));
    $('#tenant-count').textContent = state.tenants.length;
    $('#app-count').textContent = tenantApps.length;
    $('#key-count').textContent = tenantKeys.length;
    $('#contract-count').textContent = tenantContracts.length;
    $('#user-count').textContent = tenantUsers.length + state.pending_users.length;
    $('#tenant-context').innerHTML = state.tenants.map(item => `<option value="${escapeHTML(item.id)}" ${item.id === tenantID ? 'selected' : ''}>${escapeHTML(item.name)}</option>`).join('');
    $('#new-tenant').hidden = !state.is_system_administrator;
    $('#tenant-list').innerHTML = state.tenants.map(item => `<article class="card"><span class="badge">${escapeHTML(item.role)}</span><h3>${escapeHTML(item.name)}</h3><p>${escapeHTML(item.slug)}</p><div class="meta"><span>Tenant</span><code>${escapeHTML(item.id.slice(0, 8))}</code></div></article>`).join('') || empty('No tenants yet');
    $('#app-list').innerHTML = tenantApps.map(item => `<article class="card"><span class="badge">${escapeHTML(item.tenant_slug)}</span><h3>${escapeHTML(item.name)}</h3><p>${escapeHTML(item.description || 'No description')}</p><div class="meta"><span>${item.client_ready ? 'Client login ready' : 'Client login not configured'}</span><code>${escapeHTML(item.client_id)}</code></div>${canManageTenant ? `<button class="card-action" data-client="${escapeHTML(item.id)}">Configure client login</button>` : ''}</article>`).join('') || empty('No applications yet');
    $('#key-list').innerHTML = tenantKeys.map(item => `<tr><td>${escapeHTML(item.name)}</td><td>${escapeHTML(apps.get(item.application_id)?.name || '—')}</td><td><code>${escapeHTML(item.prefix)}…</code></td><td><span class="badge">${escapeHTML(item.status)}</span></td><td>${date(item.last_used_at)}</td><td>${canManageTenant && item.status === 'active' ? `<button class="danger" data-revoke="${escapeHTML(item.id)}">Revoke</button>` : ''}</td></tr>`).join('') || rowEmpty(6, 'No keys issued');
    $('#contract-list').innerHTML = tenantContracts.map(item => `<tr><td>${escapeHTML(apps.get(item.application_id)?.name || '—')}</td><td>${escapeHTML(item.version)}</td><td>${item.endpoint_count}</td><td>${item.source_url ? `<a href="${escapeHTML(item.source_url)}" target="_blank" rel="noreferrer">source</a>` : 'Pasted'}</td><td>${date(item.created_at)}</td></tr>`).join('') || rowEmpty(5, 'No contracts imported');
    const pending = state.is_system_administrator ? state.pending_users.map(item => `<tr><td><strong>${escapeHTML(item.display_name)}</strong><br><small>${escapeHTML(item.email)}</small></td><td>Waiting room</td><td>—</td><td><span class="badge">pending</span></td><td>0</td><td><button class="card-action" data-pending="${escapeHTML(item.id)}">Approve</button></td></tr>`).join('') : '';
    $('#user-list').innerHTML = tenantUsers.map(item => `<tr><td><strong>${escapeHTML(item.display_name)}</strong><br><small>${escapeHTML(item.email)}</small></td><td>${escapeHTML(state.tenants.find(t => t.id === item.tenant_id)?.name || '—')}</td><td><span class="badge">${escapeHTML(item.role)}</span></td><td>${escapeHTML(item.status)}</td><td>${item.application_ids.length}</td><td>${canManageTenant ? `<button class="card-action" data-access="${escapeHTML(item.id)}" data-tenant="${escapeHTML(item.tenant_id)}">Manage</button>` : ''}</td></tr>`).join('') + pending || rowEmpty(6, 'No users');
    $$('[data-tenant-action]').forEach(element => element.hidden = !canManageTenant);
    $$('.tenant-select').forEach(select => {
        select.innerHTML = state.tenants.map(item => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join('');
        select.value = tenantID;
    });
    $$('.app-select').forEach(select => select.innerHTML = tenantApps.map(item => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join(''));
}

const empty = text => `<article class="card"><p>${text}</p></article>`;
const rowEmpty = (span, text) => `<tr><td colspan="${span}">${text}</td></tr>`;

function formJSON(form) {
    const data = Object.fromEntries(new FormData(form));
    if (data.allowed_hosts !== undefined) data.allowed_hosts = data.allowed_hosts.split('\n').map(v => v.trim()).filter(Boolean);
    if (!data.expires_at) delete data.expires_at; else data.expires_at = new Date(data.expires_at).toISOString();
    return data;
}

$$('[data-dialog]').forEach(button => button.addEventListener('click', () => $('#' + button.dataset.dialog).showModal()));
$$('.close').forEach(button => button.addEventListener('click', () => button.closest('dialog').close()));
$$('.tab').forEach(button => button.addEventListener('click', () => {
    $$('.tab,.panel').forEach(el => el.classList.remove('active'));
    button.classList.add('active');
    $('#' + button.dataset.panel).classList.add('active')
}));

$('#tenant-form').addEventListener('submit', async event => submit(event, '/api/v1/tenants', 'Tenant created'));
$('#app-form').addEventListener('submit', async event => submit(event, '/api/v1/applications', 'Application registered'));
$('#key-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
        const result = await api('/api/v1/keys', {method: 'POST', body: JSON.stringify(formJSON(event.target))});
        event.target.closest('dialog').close();
        event.target.reset();
        showSecret('API key issued', 'This API key is shown once. Copy it now.', result.secret);
        await load()
    } catch (error) {
        notice(error.message, true)
    }
});
$('#contract-form').addEventListener('submit', async event => submit(event, '/api/v1/contracts', 'Contract imported'));
$('#user-form').addEventListener('submit', async event => submit(event, '/api/v1/users', 'User invited'));
$('#client-form').addEventListener('submit', async event => {
    event.preventDefault();
    const data = formJSON(event.target), id = data.application_id;
    data.redirect_uris = data.redirect_uris.split('\n').map(v => v.trim()).filter(Boolean);
    delete data.application_id;
    delete data.client_id;
    try {
        const result = await api(`/api/v1/applications/${id}/client-config`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        event.target.closest('dialog').close();
        showSecret('Client secret rotated', 'Update the client application now. This secret is shown once.', result.client_secret);
        await load()
    } catch (error) {
        notice(error.message, true)
    }
});
$('#access-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.target, data = formJSON(form);
    data.application_ids = [...form.querySelectorAll('input[name=application_ids]:checked')].map(input => input.value);
    const userID = data.user_id, approval = data.approval_mode === 'true';
    delete data.user_id;
    delete data.approval_mode;
    if (approval) data.tenant_id = data.approval_tenant_id;
    delete data.approval_tenant_id;
    try {
        await api(`/api/v1/users/${userID}/${approval ? 'approve' : 'access'}`, {
            method: approval ? 'POST' : 'PUT', body: JSON.stringify(data)
        });
        form.closest('dialog').close();
        notice(approval ? 'User approved' : 'User access updated');
        await load()
    } catch (error) {
        notice(error.message, true)
    }
});

async function submit(event, path, message) {
    event.preventDefault();
    try {
        await api(path, {method: 'POST', body: JSON.stringify(formJSON(event.target))});
        event.target.closest('dialog').close();
        event.target.reset();
        notice(message);
        await load()
    } catch (error) {
        notice(error.message, true)
    }
}

document.addEventListener('click', async event => {
    const revoke = event.target.dataset.revoke;
    if (revoke) {
        if (!confirm('Revoke this key? Existing integrations will stop working.')) return;
        try {
            await api(`/api/v1/keys/${revoke}/revoke`, {method: 'POST'});
            notice('Key revoked');
            await load()
        } catch (error) {
            notice(error.message, true)
        }
        return
    }
    const clientID = event.target.dataset.client;
    if (clientID) {
        const app = state.applications.find(item => item.id === clientID), form = $('#client-form');
        form.application_id.value = app.id;
        form.client_id.value = app.client_id;
        form.redirect_uris.value = app.redirect_uris.join('\n');
        $('#client-dialog').showModal();
        return
    }
    const userID = event.target.dataset.access;
    if (userID) {
        const user = state.users.find(item => item.id === userID && item.tenant_id === event.target.dataset.tenant),
            form = $('#access-form');
        form.user_id.value = user.id;
        form.tenant_id.value = user.tenant_id;
        form.approval_mode.value = 'false';
        $('#approval-tenant-label').hidden = true;
        form.role.value = user.role;
        renderAccessApps(user.tenant_id, user.application_ids);
        $('#access-dialog').showModal();
        return
    }
    const pendingID = event.target.dataset.pending;
    if (pendingID) {
        const form = $('#access-form');
        form.user_id.value = pendingID;
        form.approval_mode.value = 'true';
        $('#approval-tenant-label').hidden = false;
        form.approval_tenant_id.value = state.selectedTenant;
        form.role.value = 'viewer';
        renderAccessApps(state.selectedTenant, []);
        $('#access-dialog').showModal()
    }
});
$('#copy-secret').addEventListener('click', () => navigator.clipboard.writeText($('#new-secret').textContent).then(() => notice('Secret copied')));

function showSecret(title, description, secret) {
    $('#secret-title').textContent = title;
    $('#secret-description').textContent = description;
    $('#new-secret').textContent = secret;
    $('#secret-dialog').showModal()
}

const theme = $('#theme'), mode = $('#mode');
theme.value = localStorage.getItem('gl-theme') || 'tokyo';
document.documentElement.dataset.theme = theme.value;
document.documentElement.dataset.mode = localStorage.getItem('gl-mode') || 'dark';
theme.addEventListener('change', () => {
    document.documentElement.dataset.theme = theme.value;
    localStorage.setItem('gl-theme', theme.value)
});
mode.addEventListener('click', () => {
    const next = document.documentElement.dataset.mode === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.mode = next;
    localStorage.setItem('gl-mode', next)
});
$('#tenant-context').addEventListener('change', event => {
    state.selectedTenant = event.target.value;
    render()
});
$('#access-form').approval_tenant_id.addEventListener('change', event => renderAccessApps(event.target.value, []));

function renderAccessApps(tenantID, selected) {
    $('#access-apps').innerHTML = state.applications.filter(app => app.tenant_id === tenantID).map(app => `<label><input type="checkbox" name="application_ids" value="${escapeHTML(app.id)}" ${selected.includes(app.id) ? 'checked' : ''}><span>${escapeHTML(app.name)}</span></label>`).join('') || '<p>No applications</p>'
}
load().catch(error => notice(error.message, true));
