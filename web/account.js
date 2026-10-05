// The header account control.
//
// One component, mounted into every page by the placeholder below it, so the
// identity and the two things a person can do about their own account live
// together. It replaced a separate sign-out button, which meant the header showed
// two controls describing one fact.
//
// The menu is rendered here rather than duplicated into each page's markup so that
// the keyboard handling, the outside-click behaviour and the sign-out form exist
// once. The trade is one small request for the profile, which the pages that show a
// tenant context were making anyway.
//
// The sign-out item is a real form posting to /auth/logout rather than a fetch, so
// signing out works without JavaScript and cannot be triggered by a stray
// cross-site request: the endpoint only accepts POST.
//
// Everything is wrapped in an IIFE and exposed only as window.mountAccountMenu.
// These are classic scripts sharing one global scope, so a top-level const here
// would collide with the escapeHTML and initials that each page already declares,
// and the collision is a SyntaxError that stops the whole script before it runs.

(function () {
  const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
  }[character]));

  const initials = name => String(name || '?')
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map(part => part[0].toUpperCase())
      .join('') || '?';

  async function loadProfile() {
      const response = await fetch('/api/v1/profile', {
          credentials: 'same-origin',
          headers: {accept: 'application/json'}
      });
      if (response.status === 401) {
          // Signed out: the page itself will redirect, so there is nothing to show.
          return null
      }
      if (!response.ok) return null;
      return response.json()
  }

  // Mounts the control into a placeholder element. Exported on window because the
  // pages load their own script and there is no module loader here; the alternative
  // would be repeating this markup and this wiring in every page.
  function mount(host) {
      if (!host || host.dataset.mounted === 'true') return;
      host.dataset.mounted = 'true';
      host.classList.add('account');
      host.innerHTML = `
          <button type="button" class="account-trigger" aria-haspopup="true" aria-expanded="false" hidden>
              <span class="account-avatar-slot"></span>
              <span class="account-name"></span>
              <span class="account-caret" aria-hidden="true">▾</span>
          </button>
          <div class="account-menu" role="menu" hidden>
              <div class="account-identity">
                  <strong class="account-display-name"></strong>
                  <span class="account-email"></span>
              </div>
              <a class="account-profile" role="menuitem" href="/profile">Edit profile</a>
              <form method="post" action="/auth/logout">
                  <button type="submit" role="menuitem">Log out</button>
              </form>
              <p class="account-note" hidden>Signing out here also ends your sessions in the applications that use this sign-in.</p>
          </div>`;

      const trigger = host.querySelector('.account-trigger');
      const menu = host.querySelector('.account-menu');
      const note = host.querySelector('.account-note');

      const setOpen = open => {
          menu.hidden = !open;
          trigger.setAttribute('aria-expanded', String(open));
      };

      trigger.addEventListener('click', event => {
          event.stopPropagation();
          setOpen(menu.hidden)
      });

      // Escape closes and returns focus, which is the one keyboard path a menu has to
      // get right: without it the menu is a trap for anyone not using a mouse.
      document.addEventListener('keydown', event => {
          if (event.key !== 'Escape' || menu.hidden) return;
          setOpen(false);
          trigger.focus()
      });

      // A click anywhere else dismisses it. Capture phase, so a click that also
      // dismisses a dialog underneath does not race this.
      document.addEventListener('click', () => setOpen(false), true);

      loadProfile().then(profile => {
          if (!profile) {
              // No session: leave the control hidden rather than showing an empty name.
              return
          }
          const name = profile.display_name || profile.email || '';
          // The trigger and the menu both carry the name. Filling only the menu
          // leaves the header showing a picture and a caret with no name beside
          // them, which is the one thing the control exists to say.
          host.querySelector('.account-name').textContent = name;
          host.querySelector('.account-display-name').textContent = name;
          host.querySelector('.account-email').textContent = profile.email || '';
          const slot = host.querySelector('.account-avatar-slot');
          slot.innerHTML = profile.avatar_url
              ? `<img class="avatar" src="${escapeHTML(profile.avatar_url)}" alt="" width="24" height="24">`
              : `<span class="avatar avatar-empty">${escapeHTML(initials(name))}</span>`;
          trigger.hidden = false;

          // Only explain the cross-application effect when it is true. A person with
          // no hosted-login sessions has nothing to sign out of elsewhere.
          const usesHostedLogin = (profile.memberships || []).length > 0;
          note.hidden = !usesHostedLogin
      })
  };

  window.mountAccountMenu = mount

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-account-menu]').forEach(mount)
  })
})()