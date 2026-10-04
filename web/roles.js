const state = {tenants: [], roles: [], permissions: [], selectedTenant: ''};
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
}[c]));
const notice = (message, error = false) => {
    const el = $('#notice');
    el.textContent = message;
    el.hidden = false;
    el.style.borderColor = error ? 'var(--danger)' : 'var(--accent)';
    clearTimeout(notice.timer);
    notice.timer = setTimeout(() => el.hidden = true, 5000)
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
    return body
}

async function load() {
    const dashboard = await api('/api/v1/dashboard');
    state.tenants = dashboard.tenants;
    state.permissions = dashboard.permissions || [];
    if (!state.tenants.some(tenant => tenant.id === state.selectedTenant)) state.selectedTenant = state.tenants[0]?.id || '';
    renderIdentity(dashboard.profile);
    await loadRoles();
    render()
}

function renderIdentity(profile) {
    profile = profile || {};
    $('#identity-name').textContent = profile.display_name || profile.email || '';
    const image = $('#identity-avatar');
    if (profile.avatar_url) {
        image.src = profile.avatar_url;
        image.hidden = false
    } else {
        image.hidden = true;
        image.removeAttribute('src')
    }
}

async function loadRoles() {
    if (!state.selectedTenant) {
        state.roles = [];
        return
    }
    try {
        state.roles = (await api(`/api/v1/roles?tenant_id=${encodeURIComponent(state.selectedTenant)}`)).roles
    } catch (error) {
        state.roles = [];
        notice('You do not have permission to read the roles of this tenant.', true)
    }
}

function selectedTenant() {
    return state.tenants.find(tenant => tenant.id === state.selectedTenant)
}

const canManageRoles = () => Boolean(selectedTenant()?.permissions?.includes('roles.manage'));

function render() {
    const tenant = selectedTenant();
    const custom = state.roles.filter(item => !item.system);
    $('#tenant-context').innerHTML = state.tenants.map(item =>
        `<option value="${escapeHTML(item.id)}" ${item.id === state.selectedTenant ? 'selected' : ''}>${escapeHTML(item.name)}</option>`).join('');
    $('#role-tenant').textContent = tenant ? tenant.name : 'No tenant';
    $('#role-count').textContent = String(state.roles.length);
    $('#role-summary').textContent = canManageRoles() ? 'Roles · editable' : 'Roles · read only';
    $('#stat-roles').textContent = state.roles.length;
    $('#stat-system').textContent = state.roles.length - custom.length;
    $('#stat-custom').textContent = custom.length;
    $('#stat-assignable').textContent = state.roles.filter(item => item.assignable).length;
    $('#new-role').hidden = !canManageRoles();

    $('#role-list').innerHTML = state.roles.map(item => `<tr>
        <td><strong>${escapeHTML(item.name)}</strong>${item.system ? ' <span class="badge">built-in</span>' : ''}<br><small>${escapeHTML(item.description || 'No description')}</small></td>
        <td><code>${escapeHTML(item.slug)}</code></td>
        <td class="capabilities">${item.permissions.map(permission => `<span class="chip">${escapeHTML(permission)}</span>`).join('') || '<span class="muted">None</span>'}</td>
        <td>${item.member_count}</td>
        <td>${item.assignable ? 'Yes' : '<span class="muted">No</span>'}</td>
        <td>${item.system ? '' : canManageRoles() ? `<button class="card-action" data-edit="${escapeHTML(item.id)}">Edit</button><button class="danger" data-delete="${escapeHTML(item.id)}">Delete</button>` : ''}</td>
    </tr>`).join('') || '<tr><td colspan="6">No roles available for this tenant.</td></tr>';

    $('#permission-list').innerHTML = state.permissions.map(item => `<tr>
        <td><code>${escapeHTML(item.value)}</code></td>
        <td>${escapeHTML(item.description)}</td>
    </tr>`).join('')
}

function permissionCheckboxes(selected) {
    const held = new Set(selected || []);
    $('#role-permissions').innerHTML = state.permissions.map(item => `<label>
        <input type="checkbox" name="permissions" value="${escapeHTML(item.value)}" ${held.has(item.value) ? 'checked' : ''}>
        <span><strong>${escapeHTML(item.label)}</strong><br><small>${escapeHTML(item.description)}</small></span>
    </label>`).join('')
}

function openDialog(item) {
    const form = $('#role-form');
    form.reset();
    form.role_id.value = item?.id || '';
    form.slug.value = item?.slug || '';
    form.name.value = item?.name || '';
    form.description.value = item?.description || '';
    // The slug identifies a role for the lifetime of the role, so it is fixed
    // once the role exists.
    $('#role-slug-label').hidden = Boolean(item);
    form.slug.required = !item;
    $('#role-dialog-title').textContent = item ? `Edit ${item.name}` : 'New role';
    $('#role-hint').textContent = item
        ? 'Saving replaces the permissions of every member holding this role.'
        : 'The slug cannot be changed later.';
    permissionCheckboxes(item?.permissions);
    $('#role-dialog').showModal()
}

$('#new-role').addEventListener('click', () => openDialog(null));
$$('.close').forEach(button => button.addEventListener('click', () => button.closest('dialog').close()));

$('#role-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.target;
    const permissions = [...form.querySelectorAll('input[name=permissions]:checked')].map(input => input.value);
    const id = form.role_id.value;
    const body = id
        ? {name: form.name.value, description: form.description.value, permissions}
        : {tenant_id: state.selectedTenant, slug: form.slug.value, name: form.name.value, description: form.description.value, permissions};
    try {
        await api(id ? `/api/v1/roles/${id}` : '/api/v1/roles', {
            method: id ? 'PUT' : 'POST',
            body: JSON.stringify(body)
        });
        form.closest('dialog').close();
        notice(id ? 'Role updated' : 'Role created');
        await loadRoles();
        render()
    } catch (error) {
        notice(error.message, true)
    }
});

document.addEventListener('click', async event => {
    const edit = event.target.dataset.edit;
    if (edit) {
        openDialog(state.roles.find(item => item.id === edit));
        return
    }
    const remove = event.target.dataset.delete;
    if (remove) {
        const item = state.roles.find(role => role.id === remove);
        if (!confirm(`Delete the role "${item.name}"?`)) return;
        try {
            await api(`/api/v1/roles/${remove}`, {method: 'DELETE'});
            notice('Role deleted');
            await loadRoles();
            render()
        } catch (error) {
            notice(error.message, true)
        }
    }
});

const theme = $('#theme');
theme.value = localStorage.getItem('gl-theme') || 'tokyo';
document.documentElement.dataset.theme = theme.value;
document.documentElement.dataset.mode = localStorage.getItem('gl-mode') || 'dark';
theme.addEventListener('change', () => {
    document.documentElement.dataset.theme = theme.value;
    localStorage.setItem('gl-theme', theme.value)
});
$('#mode').addEventListener('click', () => {
    const next = document.documentElement.dataset.mode === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.mode = next;
    localStorage.setItem('gl-mode', next)
});
$('#tenant-context').addEventListener('change', async event => {
    state.selectedTenant = event.target.value;
    await loadRoles();
    render()
});

load().catch(error => notice(error.message, true));
