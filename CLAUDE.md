# CLAUDE.md

The push relay for the DuoDuo Pocket app: a Cloudflare Worker.

- Use `pnpm`. Run `pnpm run check` before committing.
- Deploy only with `pnpm run dry-run` first, then `pnpm run deploy`; both pass `--config`.
- Every `ts` and `js` file starts with the two-line SPDX header (`FSL-1.1-Apache-2.0`).
- Secrets live only in Cloudflare secrets. Never put keys, team ids, device tokens, account ids or
  hostnames other than the public relay address in tracked files.
- The relay keeps nothing: no storage bindings, no request logging, observability off.
- Do not add limits, retries or other runtime constants without documenting their reason.
