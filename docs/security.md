# Security Notes

## Local Secrets

Do not commit runtime secrets or locally generated credentials.

Ignored local files:
- `src/signing_key`
- `src/auth_bot/.secrets`
- `src/auth_bot/users.txt`

Recommended permissions for local secret files:

```sh
chmod 600 src/signing_key src/auth_bot/.secrets
```

Rotate any value that was committed, shared in logs, or copied outside the deployment secret store.

## Ceph ForwardAuth

`GET /auth/ceph` is a trusted identity boundary for Ceph Dashboard OAuth mode. It removes any client-provided `X-Access-Token` and returns the server-validated auth cookie as that header. Attach it only to a Dashboard route that cannot bypass the authenticating reverse proxy.

Do not attach `/auth/ceph` to general ForwardAuth consumers. Use `/auth` unless an upstream explicitly requires the raw signed access token.

## Logging

Logs must not include passwords, OAuth codes, `state`, bearer tokens, cookies, `Set-Cookie`, client secrets, access tokens, refresh tokens, private keys, signing keys, or Telegram bot tokens.
