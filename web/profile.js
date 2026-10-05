const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
}[c]));
const date = value => value ? new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short'}).format(new Date(value)) : 'Never';
const notice = (message, error = false) => {
    const el = $('#notice');
    el.textContent = message;
    el.hidden = false;
    el.style.borderColor = error ? 'var(--danger)' : 'var(--accent)';
    clearTimeout(notice.timer);
    notice.timer = setTimeout(() => el.hidden = true, 5000)
};
const avatar = {dataURL: '', fileName: '', pending: false};

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
    render(await api('/api/v1/profile'))
}

function render(profile) {
    $('#display-name').value = profile.display_name;
    $('#email').value = profile.email;
    $('#system-admin').textContent = profile.is_system_administrator ? 'Yes' : 'No';
    $('#created-at').textContent = date(profile.created_at);
    $('#last-login').textContent = date(profile.last_login_at);
    $('#name-source').textContent = profile.name_customized ? 'You' : 'Your identity provider';
    renderAvatar(profile);
    $('#membership-list').innerHTML = profile.memberships.map(item => `<tr>
        <td>${escapeHTML(item.tenant_name)}</td>
        <td><code>${escapeHTML(item.tenant_slug)}</code></td>
        <td><span class="badge">${escapeHTML(item.role)}</span></td>
        <td class="capabilities">${item.permissions.map(permission => `<span class="chip">${escapeHTML(permission)}</span>`).join('') || '<span class="muted">None</span>'}</td>
    </tr>`).join('') || '<tr><td colspan="4">No tenant role assigned yet</td></tr>'
}

function renderAvatar(profile) {
    const image = $('#avatar-image'), fallback = $('#avatar-fallback'), link = $('#avatar-url');
    const source = avatar.pending ? avatar.dataURL : profile.avatar_url;
    $('#avatar-remove').hidden = !profile.avatar_url;
    $('#copy-avatar').hidden = !profile.avatar_url;
    if (source) {
        image.src = source;
        image.hidden = false;
        fallback.hidden = true
    } else {
        image.hidden = true;
        image.removeAttribute('src');
        fallback.hidden = false;
        fallback.textContent = initials(profile.display_name || profile.email)
    }
    link.textContent = profile.avatar_url || (avatar.pending ? 'Saved on upload' : 'No picture uploaded')
}

function initials(name) {
    return String(name || '?').split(/[\s@._-]+/).filter(Boolean).slice(0, 2).map(part => part[0].toUpperCase()).join('') || '?'
}

$('#profile-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
        render(await api('/api/v1/profile', {
            method: 'PUT',
            body: JSON.stringify({display_name: $('#display-name').value})
        }));
        notice('Profile saved')
    } catch (error) {
        notice(error.message, true)
    }
});

$('#avatar-file').addEventListener('change', async event => {
    const file = event.target.files?.[0];
    avatar.pending = false;
    if (!file) {
        $('#avatar-save').disabled = true;
        return
    }
    if (file.size > 2 * 1024 * 1024) {
        notice('The picture must be 2 MiB or smaller', true);
        event.target.value = '';
        $('#avatar-save').disabled = true;
        return
    }
    avatar.dataURL = await readAsDataURL(file);
    avatar.fileName = file.name;
    avatar.pending = true;
    $('#avatar-save').disabled = false;
    renderAvatar({avatar_url: '', display_name: $('#display-name').value, email: $('#email').value})
});

$('#avatar-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!avatar.pending) return;
    try {
        const profile = await api('/api/v1/profile', {
            method: 'PUT', body: JSON.stringify({avatar: avatar.dataURL})
        });
        avatar.pending = false;
        $('#avatar-file').value = '';
        $('#avatar-save').disabled = true;
        render(profile);
        notice('Profile picture updated')
    } catch (error) {
        notice(error.message, true)
    }
});

$('#avatar-remove').addEventListener('click', async () => {
    if (!confirm('Remove your profile picture?')) return;
    try {
        const profile = await api('/api/v1/profile', {method: 'PUT', body: JSON.stringify({remove_avatar: true})});
        avatar.pending = false;
        $('#avatar-file').value = '';
        $('#avatar-save').disabled = true;
        render(profile);
        notice('Profile picture removed')
    } catch (error) {
        notice(error.message, true)
    }
});

$('#copy-avatar').addEventListener('click', () => navigator.clipboard.writeText($('#avatar-url').textContent).then(() => notice('Picture link copied')));

function readAsDataURL(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('could not read the selected file'));
        reader.readAsDataURL(file)
    })
}

// The palette and appearance controls are the components shipped by the theme
// service. See the note in app.js for why this file no longer drives them.

load().catch(error => notice(error.message, true));