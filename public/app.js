import {
  b64u, generateDropKeys, fingerprint, encryptTo, decryptWith, makeRecoveryFile, openRecoveryFile, solvePow,
} from './crypto.js';
import { passkeySupported, hasPasskeyVault, protectWithPasskey, unlockWithPasskey, forgetPasskeyVault } from './passkey.js';

const te = new TextEncoder();
const td = new TextDecoder();
const app = document.getElementById('app');

// ---- tiny DOM helpers (no innerHTML anywhere: secrets are only ever set via textContent) ----
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
};
const render = (...nodes) => {
  app.replaceChildren(...nodes);
  window.scrollTo(0, 0);
};
const note = (text, kind = '') => h('div', { class: `note ${kind}`, role: kind === 'err' ? 'alert' : 'status' }, text);

const ERRORS = {
  rate_limited: 'Too many requests from your network. Please wait a few minutes and try again.',
  bad_pow: 'The proof-of-work check failed. Please try again.',
  capacity: 'The service is at capacity right now. Please try again later.',
  already_filled: 'A secret has already been sent to this drop.',
  not_found: 'This drop does not exist or has expired.',
  too_large: 'That is too large to send.',
};
const errText = (e) => ERRORS[e.code] || (e.status ? `Request failed (${e.code || e.status}).` : 'Network error. Check your connection and try again.');

async function api(path, { method = 'GET', body, token } = {}) {
  const r = await fetch(path, {
    method,
    cache: 'no-store',
    headers: { ...(body && { 'content-type': 'application/json' }), ...(token && { authorization: `Bearer ${token}` }) },
    body: body && JSON.stringify(body),
  });
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) throw Object.assign(new Error(data?.error || `http_${r.status}`), { status: r.status, code: data?.error });
  return data;
}

async function proofOfWork(purpose, setStatus) {
  setStatus('Running anti-abuse check…');
  const ch = await api(`/api/pow?purpose=${purpose}`);
  return solvePow(ch, (n) => setStatus(`Running anti-abuse check… (${n.toLocaleString()} attempts)`));
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => (btn.textContent = old), 1500);
  } catch {
    btn.textContent = 'Press Ctrl/⌘+C';
  }
}
const copyRow = (value) => {
  const input = h('input', { type: 'text', readonly: true, value, 'aria-label': 'Link', onfocus: (e) => e.target.select() });
  const btn = h('button', { type: 'button', class: 'ghost', onclick: () => copy(value, btn) }, 'Copy');
  return h('div', { class: 'copybox' }, input, btn);
};
const fmtExpiry = (ts) => new Date(ts * 1000).toLocaleString();
const TTL_LABEL = { 3600: '1 hour', 86400: '24 hours', 604800: '7 days' };

// ---- views --------------------------------------------------------------------------------
async function home() {
  const cfg = await api('/api/config').catch(() => ({ ttls: [86400], maxSecretBytes: 8192 }));
  const status = h('p', { class: 'progress', 'aria-live': 'polite' });
  const err = h('div');
  const ttl = h('select', { id: 'ttl' }, cfg.ttls.map((t) => h('option', { value: t, selected: t === 86400 }, TTL_LABEL[t] || `${t}s`)));
  const pass = h('input', { type: 'password', id: 'pass', autocomplete: 'new-password', minlength: 12, required: true });
  const pass2 = h('input', { type: 'password', id: 'pass2', autocomplete: 'new-password', required: true });
  const pk = passkeySupported() ? h('input', { type: 'checkbox', id: 'pk' }) : null;
  const submit = h('button', { type: 'submit' }, 'Create secure drop');

  const form = h(
    'form',
    {
      class: 'card',
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        if (pass.value.length < 12) return err.replaceChildren(note('Use a passphrase of at least 12 characters.', 'err'));
        if (pass.value !== pass2.value) return err.replaceChildren(note('The passphrases do not match.', 'err'));
        submit.disabled = true;
        try {
          await createDrop({ ttl: Number(ttl.value), passphrase: pass.value, usePasskey: !!pk?.checked }, (s) => (status.textContent = s));
        } catch (ex) {
          err.replaceChildren(note(errText(ex), 'err'));
          status.textContent = '';
          submit.disabled = false;
        }
      },
    },
    h('h2', {}, 'Create a drop'),
    h('label', { for: 'ttl' }, 'Link expires after'),
    ttl,
    h('label', { for: 'pass' }, 'Recovery file passphrase'),
    pass,
    h('label', { for: 'pass2' }, 'Confirm passphrase'),
    pass2,
    h('p', { class: 'hint' }, 'Your private key never leaves this browser. It is saved to a recovery file encrypted with this passphrase. Nobody, including us, can reset it.'),
    pk && h('label', { class: 'check', for: 'pk' }, pk, h('span', {}, 'Also protect this device with a passkey (Face ID, Touch ID, security key) for quick unlocking')),
    err,
    h('div', { class: 'row' }, submit),
    status,
  );

  render(
    h('h1', {}, 'Receive credentials securely'),
    h('p', { class: 'lead' }, 'Create a one-time drop, send the link to whoever has the secret, and read it here. It is encrypted in their browser to a key only you hold.'),
    h(
      'ol',
      { class: 'steps' },
      h('li', {}, h('span', {}, 'Create a drop. Your browser generates a key pair and a recovery file.')),
      h('li', {}, h('span', {}, 'Send the drop link to the sender and confirm the fingerprint with them by phone or chat.')),
      h('li', {}, h('span', {}, 'They submit the secret. You unlock it once, and it is deleted from the server.')),
    ),
    form,
  );
}

async function createDrop({ ttl, passphrase, usePasskey }, setStatus) {
  const solved = await proofOfWork('create', setStatus);
  setStatus('Generating keys…');
  const keys = await generateDropKeys();
  const res = await api('/api/drops', { method: 'POST', body: { tokenHash: keys.tokenHash, ttl, pow: solved } });
  const vault = {
    v: 1,
    dropId: res.id,
    privateJwk: keys.privateJwk,
    readToken: keys.readToken,
    publicKey: b64u.enc(keys.publicRaw),
    expiresAt: res.expiresAt,
  };
  setStatus('Encrypting recovery file…');
  const file = await makeRecoveryFile(vault, passphrase);
  let passkeyMsg = null;
  if (usePasskey) {
    setStatus('Waiting for your passkey…');
    try {
      await protectWithPasskey(vault);
      passkeyMsg = note('Passkey saved: you can unlock this drop on this device without the recovery file.', 'ok');
    } catch (e) {
      passkeyMsg = note(`Passkey protection failed (${e.message}). Use the recovery file instead.`);
    }
  }
  showCreated(res, keys.publicRaw, file, passkeyMsg);
}

async function showCreated(res, publicRaw, file, passkeyMsg) {
  const sendLink = `${location.origin}/d/${res.id}#${b64u.enc(publicRaw)}`;
  const readLink = `${location.origin}/r/${res.id}`;
  const fp = await fingerprint(publicRaw);
  const url = URL.createObjectURL(new Blob([JSON.stringify(file)], { type: 'application/json' }));
  const download = h('a', { href: url, download: `sealdrop-${res.id.slice(0, 6)}.recovery.json`, hidden: true });
  document.body.append(download); // must be attached for Firefox to honour click()
  const dlBtn = h('button', { type: 'button', onclick: () => download.click() }, 'Download recovery file');

  render(
    h('h1', {}, 'Your drop is ready'),
    h('p', { class: 'lead' }, `It expires ${fmtExpiry(res.expiresAt)} and can receive one secret.`),
    h(
      'div',
      { class: 'card' },
      h('h2', {}, '1. Save your recovery file'),
      h('p', {}, 'This file plus your passphrase is the only way to read the secret. We cannot recover it.'),
      h('div', { class: 'row' }, dlBtn),
      passkeyMsg,
    ),
    h(
      'div',
      { class: 'card' },
      h('h2', {}, '2. Send this link to the sender'),
      copyRow(sendLink),
      h('p', { class: 'hint' }, 'The part after # holds your public key. It is never sent to the server.'),
      h('h2', { class: 'mt' }, 'Then confirm this fingerprint with them'),
      h('div', { class: 'fp' }, fp),
      h('p', { class: 'hint' }, 'Read it to them by phone or on a channel you trust. It should match what they see on their page. This protects against a swapped link.'),
    ),
    h(
      'div',
      { class: 'card' },
      h('h2', {}, '3. Read the secret later'),
      copyRow(readLink),
      h('div', { class: 'row' }, h('a', { href: `/r/${res.id}`, 'data-link': true }, 'Open the receive page')),
    ),
  );
  setTimeout(() => download.click(), 300);
}

function gone(title = 'This link is invalid or has expired') {
  render(h('div', { class: 'card' }, h('h2', {}, title), h('p', {}, 'Drops are single-use and expire automatically. Ask the recipient to create a new one.'), h('a', { href: '/', 'data-link': true }, 'Go to Sealdrop')));
}

async function send(id) {
  render(h('p', { class: 'progress' }, 'Loading…'));
  let st;
  try {
    st = await api(`/api/drops/${id}`);
  } catch {
    return gone();
  }
  if (st.state === 'filled') return gone('A secret was already sent to this drop');

  let pub;
  try {
    pub = b64u.dec(location.hash.slice(1));
    if (pub.length !== 65 || pub[0] !== 4) throw new Error();
  } catch {
    return render(h('div', { class: 'card' }, h('h2', {}, 'Link is incomplete'), note('This link is missing its encryption key (the part after #). Ask the recipient for the full link.', 'err')));
  }
  const fp = await fingerprint(pub);
  const cfg = await api('/api/config');
  const text = h('textarea', { id: 'secret', autocomplete: 'off', spellcheck: false, 'aria-describedby': 'count', required: true });
  const count = h('p', { class: 'hint', id: 'count' }, `0 / ${cfg.maxSecretBytes} bytes`);
  const status = h('p', { class: 'progress', 'aria-live': 'polite' });
  const err = h('div');
  const btn = h('button', { type: 'submit' }, 'Encrypt and send');
  text.addEventListener('input', () => (count.textContent = `${te.encode(text.value).length} / ${cfg.maxSecretBytes} bytes`));

  const form = h(
    'form',
    {
      class: 'card',
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        const bytes = te.encode(text.value);
        if (!bytes.length) return;
        if (bytes.length > cfg.maxSecretBytes) return err.replaceChildren(note(`Too long: the limit is ${cfg.maxSecretBytes} bytes.`, 'err'));
        btn.disabled = true;
        try {
          const solved = await proofOfWork('submit', (s) => (status.textContent = s));
          status.textContent = 'Encrypting…';
          const blob = await encryptTo(pub, bytes, id);
          await api(`/api/drops/${id}/secret`, { method: 'POST', body: { ciphertext: b64u.enc(blob), pow: solved } });
          text.value = '';
          render(
            h('div', { class: 'card' }, h('h2', {}, 'Delivered'), note('Your secret was encrypted in this browser and sent. Only the recipient can open it, once.', 'ok'), h('p', { class: 'small' }, 'You can close this tab. Let the recipient know it is ready.')),
          );
        } catch (ex) {
          err.replaceChildren(note(ex.code === 'already_filled' ? ERRORS.already_filled : ex.code ? errText(ex) : `Could not send: ${ex.message}`, 'err'));
          status.textContent = '';
          btn.disabled = false;
        }
      },
    },
    h('h2', {}, 'Confirm the recipient'),
    h('div', { class: 'fp' }, fp),
    h('p', { class: 'hint' }, 'Ask the recipient to read their fingerprint to you on a trusted channel. Only continue if they match exactly.'),
    h('label', { for: 'secret' }, 'Secret to send'),
    text,
    count,
    err,
    h('div', { class: 'row' }, btn),
    status,
  );
  render(
    h('h1', {}, 'Send a secret securely'),
    h('p', { class: 'lead' }, `Encrypted in your browser before it leaves. The recipient can read it once. The drop expires ${fmtExpiry(st.expiresAt)}.`),
    form,
  );
}

async function receive(id) {
  render(h('p', { class: 'progress' }, 'Loading…'));
  let st;
  try {
    st = await api(`/api/drops/${id}`);
  } catch {
    return gone('This drop has expired or was already read');
  }
  const err = h('div');
  const status = h('p', { class: 'progress', 'aria-live': 'polite' });

  const afterUnlock = async (vault) => {
    if (vault.dropId !== id) return err.replaceChildren(note('That key belongs to a different drop.', 'err'));
    err.replaceChildren();
    let cur;
    try {
      cur = await api(`/api/drops/${id}`);
    } catch {
      return gone('This drop has expired or was already read');
    }
    if (cur.state === 'empty') {
      return render(
        h('div', { class: 'card' }, h('h2', {}, 'Nothing here yet'), note('No secret has been sent to this drop yet.'), h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => afterUnlock(vault) }, 'Check again'))),
      );
    }
    try {
      const { ciphertext } = await api(`/api/drops/${id}/secret`, { token: vault.readToken });
      let bytes;
      try {
        bytes = await decryptWith(vault.privateJwk, b64u.dec(ciphertext), id);
      } catch {
        return render(h('div', { class: 'card' }, h('h2', {}, 'Could not decrypt'), note('Decryption failed: the data was altered or does not match this key. The secret was NOT deleted from the server.', 'err')));
      }
      let burned = true;
      try {
        await api(`/api/drops/${id}`, { method: 'DELETE', token: vault.readToken });
        forgetPasskeyVault(id);
      } catch {
        burned = false;
      }
      showSecret(td.decode(bytes), burned);
    } catch (ex) {
      err.replaceChildren(note(errText(ex), 'err'));
    }
  };

  const fileIn = h('input', { type: 'file', id: 'rf', accept: '.json,application/json' });
  const pass = h('input', { type: 'password', id: 'rp', autocomplete: 'current-password' });
  const unlockBtn = h('button', { type: 'submit' }, 'Unlock with recovery file');
  const fileForm = h(
    'form',
    {
      onsubmit: async (e) => {
        e.preventDefault();
        err.replaceChildren();
        const f = fileIn.files[0];
        if (!f || f.size > 65536) return err.replaceChildren(note('Choose your recovery file.', 'err'));
        unlockBtn.disabled = true;
        status.textContent = 'Unlocking…';
        try {
          const vault = await openRecoveryFile(JSON.parse(await f.text()), pass.value);
          pass.value = '';
          await afterUnlock(vault);
        } catch {
          err.replaceChildren(note('Could not unlock: wrong passphrase or not a valid recovery file.', 'err'));
        }
        status.textContent = '';
        unlockBtn.disabled = false;
      },
    },
    h('label', { for: 'rf' }, 'Recovery file'),
    fileIn,
    h('label', { for: 'rp' }, 'Passphrase'),
    pass,
    h('div', { class: 'row' }, unlockBtn),
  );

  const pkBtn =
    passkeySupported() && hasPasskeyVault(id)
      ? h('div', { class: 'row' }, h('button', {
          type: 'button',
          onclick: async () => {
            err.replaceChildren();
            try {
              await afterUnlock(await unlockWithPasskey(id));
            } catch (ex) {
              err.replaceChildren(note(`Passkey unlock failed: ${ex.message}`, 'err'));
            }
          },
        }, 'Unlock with passkey'))
      : null;

  render(
    h('h1', {}, 'Read your secret'),
    h('p', { class: 'lead' }, st.state === 'filled' ? 'A secret is waiting. Unlock it with your key. It will be deleted from the server once decrypted.' : 'No secret has arrived yet, but you can unlock now and check.'),
    h('div', { class: 'card' }, pkBtn, pkBtn && h('p', { class: 'hint' }, 'or'), fileForm, err, status),
  );
}

function showSecret(text, burned) {
  const box = h('div', { class: 'secret hidden', id: 'secret-box', 'aria-live': 'polite' });
  box.textContent = text;
  const reveal = h('button', { type: 'button', onclick: () => {
    box.classList.toggle('hidden');
    reveal.textContent = box.classList.contains('hidden') ? 'Reveal' : 'Hide';
  } }, 'Reveal');
  const copyBtn = h('button', { type: 'button', class: 'ghost', onclick: () => copy(box.textContent, copyBtn) }, 'Copy');
  const clear = h('button', { type: 'button', class: 'ghost', onclick: () => {
    box.textContent = '';
    render(h('div', { class: 'card' }, h('h2', {}, 'Cleared'), h('p', {}, 'The secret has been removed from this page.')));
  } }, 'Clear from screen');
  render(
    h('h1', {}, 'Your secret'),
    h('div', { class: 'card' }, box, h('div', { class: 'row' }, reveal, copyBtn, clear)),
    burned
      ? note('Deleted from the server. This is the only time it can be shown, so copy it to your password manager now.', 'ok')
      : note('Warning: we could not confirm deletion on the server. It will still expire automatically.'),
  );
}

function about() {
  const li = (...t) => h('li', {}, ...t);
  render(
    h('h1', {}, 'Security model'),
    h('p', { class: 'lead' }, 'What Sealdrop protects, how, and what it cannot do.'),
    h('div', { class: 'card' },
      h('h2', {}, 'How it works'),
      h('ul', { class: 'plain' },
        li('The recipient’s browser generates an ECDH P-256 key pair. The private key never leaves their device.'),
        li('The drop link carries the public key in the URL fragment (after #), which browsers never send to servers.'),
        li('The sender’s browser encrypts with ephemeral ECDH + HKDF-SHA256 + AES-256-GCM, bound to the drop id. The server only receives ciphertext.'),
        li('Messages are padded to 1 KiB buckets so length reveals little.'),
        li('The recipient proves ownership with a read token (only its hash is stored) to fetch and delete. The secret is deleted only after it decrypts successfully.'),
        li('Everything expires automatically (1 hour to 7 days) and deletes use SQLite secure_delete.'),
      )),
    h('div', { class: 'card' },
      h('h2', {}, 'What it protects against'),
      h('ul', { class: 'plain' },
        li('A database leak or backup theft: only ciphertext is stored, with no usable keys.'),
        li('Network eavesdroppers and log files: no plaintext, and request logging is disabled.'),
        li('Link interception after use: a link can receive one secret and is useless afterwards.'),
      )),
    h('div', { class: 'card' },
      h('h2', {}, 'What it cannot protect against'),
      h('ul', { class: 'plain' },
        li('A malicious or compromised server that serves altered JavaScript. Mitigations: strict CSP, no third-party scripts, and published file hashes (see “Verify file hashes”). Self-host if this is your threat model.'),
        li('A swapped drop link. That is why you must compare the fingerprint over a separate trusted channel.'),
        li('A compromised device or browser on either end, or a lost recovery file and passphrase.'),
      )),
    h('p', {}, h('a', { href: '/', 'data-link': true }, '← Back')),
  );
}

// ---- router --------------------------------------------------------------------------------
function route() {
  const p = location.pathname;
  let m;
  const run = (fn) => fn().catch((e) => render(h('div', { class: 'card' }, note(`Something went wrong: ${e.message}`, 'err'))));
  if (p === '/about') return about();
  if ((m = /^\/d\/([A-Za-z0-9_-]{22})$/.exec(p))) return run(() => send(m[1]));
  if ((m = /^\/r\/([A-Za-z0-9_-]{22})$/.exec(p))) return run(() => receive(m[1]));
  return run(home);
}
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-link]');
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
  e.preventDefault();
  history.pushState(null, '', a.getAttribute('href'));
  route();
});
addEventListener('popstate', route);
route();
