# Security

Report a vulnerability privately through GitHub security advisories on this repository.

## What the relay can and cannot do

- It sees, per grant request, the phone's IP address and APNs device token; per push, the
  channel host's IP address, the time, and a sealed message of one fixed size.
- It cannot read message text, room names or message ids: the channel seals them with a key the
  relay never receives, and the identifiers it sees are HMACs under that key.
- It can wake a registered phone with a notification. Anything it did not receive sealed from the
  channel is shown as a silent placeholder.

## Rotating the relay key

1. Add a new id to `RELAY_KEYS` (keep the old one) and `wrangler secret put RELAY_KEYS`.
2. Set `RELAY_KEY_CURRENT` to the new id in `wrangler.toml`; dry-run; deploy.
3. After one grant lifetime every phone has renewed; remove the old id and put the secret again.

## Revoking an APNs key

1. Create a replacement key for the same environment, restricted to the app's topic.
2. `wrangler secret put APNS_KEY_<ENV>` and `APNS_KEY_ID_<ENV>` with the new key.
3. Revoke the old key in the Apple developer console.

Existing grants keep working: they name the phone, not the APNs key.
