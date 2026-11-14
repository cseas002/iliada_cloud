# Iliada Cloud

The server behind the **Iliada account**: sign up with a passkey (later
Google and Apple), approve your computers with a code, and keep your
settings and data, encrypted on your computer before they leave it. The
design is in [iliada_os/docs/account.md](https://github.com/cseas002/iliada_os/blob/main/docs/account.md).

Iliada runs the default server; anyone can run their own.

## Status

First version of the account server (`iliada-account`): email codes,
passkeys, computers signing in with a code (OAuth device flow), encrypted
blobs per account with a size limit, signing computers out, deleting the
account. Not yet: the website pages, sending email, Google/Apple, the
NixOS module, Vaultwarden.

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
| `POST /v1/device/code {name}` → `{device_code, user_code, verification_uri, interval}` | a computer asks to sign in |
| `POST /v1/device/approve {user_code}` (website) | approve it |
| `POST /v1/device/token {device_code}` → `{token}` (428 while waiting) | the computer collects its token |
| `GET /v1/account`, `DELETE /v1/account` (website) | the account, its sign-ins, storage used |
| `DELETE /v1/sessions/{id}`, `POST /v1/signout` | sign a computer or browser out |
| `GET /v1/blobs`, `GET/PUT/DELETE /v1/blobs/{name}` | encrypted data (opaque bytes) |

Tokens and codes are stored only as SHA-256 hashes.

## Licence

MIT OR Apache-2.0.
