# Sealdrop

Exchange sensitive credentials without trusting the server. Recipient-keyed, single-use, zero-knowledge, with zero npm dependencies.

## How it works

1. **Recipient** creates a drop. Their browser generates an ECDH P-256 key pair, a read token and a passphrase-encrypted **recovery file**. A passkey (WebAuthn PRF) can optionally protect the key on that device.
2. The recipient sends the **drop link** `/d/<id>#<publicKey>` to the sender. The key is in the URL fragment, so it is never sent to the server. They also read out a short **fingerprint** over a separate channel to catch swapped links.
3. **Sender** types a text secret (8 KB max). The browser encrypts it with ephemeral ECDH, HKDF-SHA256 and AES-256-GCM, bound to the drop id, padded to 1 KiB buckets. Only ciphertext is uploaded.
4. **Recipient** opens `/r/<id>`, unlocks with the passkey or recovery file, and the browser decrypts. The server copy is **deleted only after a successful decrypt** (authenticated `DELETE`). Drops also expire (1 hour, 24 hours or 7 days).

The server stores a random id, `SHA-256(readToken)`, the ciphertext and an expiry. It stores no public keys, plaintext or IPs, and it does no request logging.

## Quick start (Docker)

```bash
git clone <your-fork> sealdrop && cd sealdrop
cp .env.example .env            # set SEALDROP_IMAGE to your GHCR image, or leave it and build locally
docker compose pull && docker compose up -d      # published image
# or: docker compose up -d --build               # build from source
```

The container is published on `127.0.0.1:8480` only (change with `HOST_PORT`; the app itself listens on 8080 inside the container). Put nginx in front of it:

```bash
sudo cp deploy/nginx.conf /etc/nginx/conf.d/sealdrop.conf
# edit server_name + certificate paths, then:
sudo nginx -t && sudo nginx -s reload
```

nginx must **overwrite** `X-Real-IP` (the example does), because the app trusts it for per-IP rate limits. Clear `CLIENT_IP_HEADER` if you ever expose the container directly.

### Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | Listen address inside the container |
| `DB_PATH` | `/data/sealdrop.db` | SQLite file (named volume) |
| `CLIENT_IP_HEADER` | `x-real-ip` in compose | Trusted real-IP header, empty to use the socket address |
| `POW_BITS` | `17` | Proof-of-work difficulty (each +1 doubles client cost) |
| `MAX_SECRET_BYTES` | `8192` | Max secret size. Raise nginx `client_max_body_size` too |
| `MAX_DROPS` | `20000` | Hard cap on stored drops |

## Publishing the image (GHCR)

`.github/workflows/ci.yml` runs the tests on every push and PR. On pushes to `main` and `v*` tags it builds a multi-arch (amd64 and arm64) image, pushes it to `ghcr.io/<owner>/<repo>` with SBOM and provenance attestations, and tags it `latest`, the branch, the semver and the sha. No secrets are needed beyond the built-in `GITHUB_TOKEN`. After the first publish, set the package visibility to public if you want anonymous `docker pull`, and set `SEALDROP_IMAGE` in `.env`.

## Development

```bash
npm test      # Node >= 22.13, no install step
npm start     # http://localhost:8080
```

Layout: `server/` (Node http + `node:sqlite`), `public/` (static ES modules, no build step), `test/`.

## Verifying what the server serves

The server serves only static files from `public/`, and `GET /api/integrity` returns the SHA-256 of every file. Compare it with hashes from your own build. If a malicious server serving altered JavaScript is in your threat model, self-host.

## Known limitations

- The server is the trust root for the JavaScript. Hash verification and self-hosting mitigate this but cannot remove it.
- Passkey protection needs a browser and authenticator with WebAuthn PRF support. The recovery file always works as a fallback.
- Proof-of-work is a speed bump. The real abuse controls are rate limits and size and count caps.
- SQLite means a single replica.
