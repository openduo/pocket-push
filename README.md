# pocket-push

The push relay for 多多随身 (DuoDuo Pocket). A user's own ambient channel cannot sign Apple push
notifications for the app: that takes the openduo APNs key, which cannot go to every user's host.
This Cloudflare Worker holds the key and nothing else. It keeps no database and no request logs, and
it cannot read what it carries.

## Protocol

`POST /v1/grant` (from the phone, over the internet)

```json
{ "token": "<APNs device token, hex>", "environment": "sandbox" | "production" }
→ 200 { "grant": "<opaque>", "expires_at": "<ISO 8601>" }
```

The grant is the phone's APNs address sealed with a relay key (AES-256-GCM): version byte, key id,
nonce, ciphertext. Only the relay can open it. It is accepted for `GRANT_LIFETIME_S` after issue.

`POST /v1/push` (from the channel)

```json
{ "grant": "...", "sealed": "<base64, exactly 2934 bytes>", "id": "<64 hex>", "thread": "<64 hex>" }
→ 200 | 400 | 401 grant_invalid/grant_expired | 410 unregistered | 429 | 502 apns
```

`sealed` is the message encrypted on the channel with a key only the phone and its channel hold;
every message has one size. `id` and `thread` are HMACs of the answer and the room under that key.
The relay sends an alert with a localized placeholder, `mutable-content`, `thread-id = thread`,
`apns-collapse-id = id` and the sealed bytes; the app's notification service extension opens them.
`410` means APNs no longer knows the phone: the channel drops the registration.

## Limits

- Per phone (`PUSH_LIMIT` in `wrangler.toml`, keyed by the SHA-256 of the device token): 20 per
  minute. Minting more grants for one phone buys no more.
- Device token: at most 1024 bytes, far above a real APNs token (32 bytes today); it only stops a
  request from making the relay seal megabytes.
- Per IP: one Cloudflare WAF rate-limiting rule on `/v1/*`: 10 requests per 10 s (60 a minute; the free plan offers only the 10 s period), then blocked for 10 s.

## Secrets

| Name                                            | Content                                            |
| ----------------------------------------------- | -------------------------------------------------- |
| `APNS_KEY_SANDBOX`, `APNS_KEY_ID_SANDBOX`       | APNs key restricted to the app's topic, sandbox    |
| `APNS_KEY_PRODUCTION`, `APNS_KEY_ID_PRODUCTION` | the same, production                               |
| `APNS_TEAM_ID`                                  | Apple developer team                               |
| `RELAY_KEYS`                                    | JSON object of key id to base64url 32-byte AES key |

Apple offers topic-restricted keys for one environment at a time, hence two.

## Develop and deploy

```sh
pnpm install
pnpm run check      # types, tests, lint, format
pnpm run dry-run    # always before a deploy
pnpm run deploy
```

Deploy only with the explicit `--config` the scripts pass.

See [SECURITY.md](SECURITY.md) for key rotation and revocation.

## License

FSL-1.1-Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
