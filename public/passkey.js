// Optional passkey protection of the recipient's vault using the WebAuthn PRF extension.
// The passkey never leaves the authenticator; its PRF output is turned into an AES key
// that wraps the vault stored in this browser's localStorage. If PRF is unsupported the
// caller falls back to the passphrase-protected recovery file.
import { b64u, rand, keyFromPrf, sealVault, openVault } from './crypto.js';

const storeKey = (dropId) => `sealdrop:pk:${dropId}`;

export const passkeySupported = () => !!(globalThis.PublicKeyCredential && navigator.credentials);

export function hasPasskeyVault(dropId) {
  try {
    return !!localStorage.getItem(storeKey(dropId));
  } catch {
    return false;
  }
}

async function prfAssertion(credId, salt) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      allowCredentials: [{ type: 'public-key', id: credId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const out = cred.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('This passkey or browser does not support the PRF extension.');
  return new Uint8Array(out);
}

export async function protectWithPasskey(vault) {
  const salt = rand(32);
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Sealdrop' },
      user: { id: rand(16), name: `drop-${vault.dropId.slice(0, 6)}`, displayName: 'Sealdrop drop' },
      challenge: rand(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  // Many authenticators only return PRF output on assertion, not creation.
  const created = cred.getClientExtensionResults().prf?.results?.first;
  const prf = created ? new Uint8Array(created) : await prfAssertion(cred.rawId, salt);
  const sealed = await sealVault(vault, await keyFromPrf(prf));
  localStorage.setItem(
    storeKey(vault.dropId),
    JSON.stringify({ credId: b64u.enc(new Uint8Array(cred.rawId)), salt: b64u.enc(salt), ...sealed }),
  );
}

export async function unlockWithPasskey(dropId) {
  const rec = JSON.parse(localStorage.getItem(storeKey(dropId)) || 'null');
  if (!rec) throw new Error('No passkey-protected key for this drop in this browser.');
  const prf = await prfAssertion(b64u.dec(rec.credId), b64u.dec(rec.salt));
  return openVault(rec, await keyFromPrf(prf));
}

export function forgetPasskeyVault(dropId) {
  try {
    localStorage.removeItem(storeKey(dropId));
  } catch {}
}
