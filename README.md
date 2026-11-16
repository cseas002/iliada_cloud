# Iliada Cloud

The server behind the **Iliada account**: sign up with a passkey (later
Google and Apple), approve your computers with a code, and keep your
settings and data, encrypted on your computer before they leave it. The
design is in [iliada_os/docs/account.md](https://github.com/cseas002/iliada_os/blob/main/docs/account.md).

Iliada runs the default server; anyone can run their own.

## Status

The account server (`iliada-account`) and its website: sign up with an
email code, add a passkey, sign in with it, approve a computer's code at
`/device`, see and sign out your computers, delete the account. Computers
sign in with the OAuth device flow and keep encrypted blobs (with a size
limit). Not yet: sending email (codes go to the log while developing),
Google/Apple, the NixOS module, Vaultwarden.

The computer side is in Iliada itself
([`crates/iliada-account`](https://github.com/cseas002/iliada_os/tree/main/crates/iliada-account):
Settings → Account, the Setup Assistant, `iliada account`). It seals
everything with a key the server never sees before uploading it.

## Tests

    cargo test                     # the API, with a software passkey
    bash tests/browser/run.sh      # the website in headless Chromium with a
                                   # virtual passkey (SHOTS=dir saves screenshots)

## Run it while developing

    ILIADA_ACCOUNT_LOG_CODES=1 cargo run      # http://localhost:8480, codes in the log

Settings (environment): `ILIADA_ACCOUNT_ORIGIN`, `ILIADA_ACCOUNT_LISTEN`,
`ILIADA_ACCOUNT_DATA`, `ILIADA_ACCOUNT_QUOTA_MB`, `ILIADA_ACCOUNT_LOG_CODES`.

## API (v1, JSON; `Authorization: Bearer <token>`)

| | |
|---|---|
| `POST /v1/email/start {email}`, `POST /v1/email/finish {email, code}` → `{token}` | sign in or up with a six-digit code |
| `POST /v1/passkey/register/start` → `{flow, options}`, `…/finish {flow, credential}` | add a passkey (website) |
| `POST /v1/passkey/login/start {email}`, `…/finish {flow, credential}` → `{token}` | sign in with a passkey |
| `POST /v1/device/code {name}` → `{device_code, user_code, verification_uri, verification_uri_complete, interval}` | a computer asks to sign in |
| `POST /v1/device/approve {user_code}` (website) | approve it |
| `POST /v1/device/token {device_code}` → `{token}` (428 while waiting) | the computer collects its token |
| `GET /v1/account`, `DELETE /v1/account` (website) | the account, its sign-ins, storage used |
| `DELETE /v1/sessions/{id}`, `POST /v1/signout` | sign a computer or browser out |
| `GET /v1/blobs`, `GET/PUT/DELETE /v1/blobs/{name}` | encrypted data (opaque bytes) |

Tokens and codes are stored only as SHA-256 hashes.

## Licence

MIT OR Apache-2.0.
