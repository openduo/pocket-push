// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

/**
 * pocket-push: the relay between a user's own ambient channel and Apple Push Notification service
 * for the DuoDuo Pocket app. It holds the openduo APNs key, which cannot go to every user's host,
 * and nothing else: no database, no logs of content. See README.md for the protocol.
 *
 *   POST /v1/grant  {token, environment}        from the phone: seal its APNs address
 *   POST /v1/push   {grant, sealed, id, thread} from the channel: deliver one sealed message
 */
import { sendApns, type ApnsCredentials } from "./apns";
import { fromBase64, sha256Hex } from "./bytes";
import { SEALED_BYTES, ID_PATTERN, envelope, APNS_PAYLOAD_MAX_BYTES } from "./envelope";
import { loadRelayKeys, openGrant, sealGrant, type RelayKeys } from "./grant";

/**
 * Apple offers a topic-restricted APNs key for one environment only, so there are two keys, each
 * restricted to `APNS_TOPIC`; a grant's environment picks one.
 */
export type Env = {
  /** Secret: the sandbox APNs auth key (.p8, PKCS#8 PEM). */
  APNS_KEY_SANDBOX: string;
  /** Secret: its key id. */
  APNS_KEY_ID_SANDBOX: string;
  /** Secret: the production APNs auth key (.p8, PKCS#8 PEM). */
  APNS_KEY_PRODUCTION: string;
  /** Secret: its key id. */
  APNS_KEY_ID_PRODUCTION: string;
  /** Secret: the Apple developer team id. */
  APNS_TEAM_ID: string;
  /** Secret: JSON object of relay key id to base64url 32-byte AES key. */
  RELAY_KEYS: string;
  /** The relay key id new grants are sealed with. */
  RELAY_KEY_CURRENT: string;
  /** The only APNs topic grants are issued for: the app's bundle id. */
  APNS_TOPIC: string;
  /** Seconds a grant is accepted after it was issued. */
  GRANT_LIFETIME_S: string;
  /** Per-phone push limit (`wrangler.toml`), keyed by the SHA-256 of the device token. */
  PUSH_LIMIT: RateLimit;
};

/** The default `fetch`, replaceable by tests. */
export type Seams = { fetch?: typeof fetch; now?: () => number };

const HEX_TOKEN = /^(?:[0-9a-f]{2})+$/;
/**
 * A device token is 32 bytes today and Apple says not to rely on its length. This bound is
 * deliberately far above any real token (owner's decision): it only stops a request from making
 * the relay seal megabytes, and never refuses a real phone.
 */
export const TOKEN_MAX_BYTES = 1024;

function reply(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
  });
}

async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    return null;
  }
  try {
    const value: unknown = await req.json();
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

let keysCache: { source: string; keys: RelayKeys } | null = null;

async function relayKeys(env: Env): Promise<RelayKeys> {
  const source = `${env.RELAY_KEY_CURRENT}\n${env.RELAY_KEYS}`;
  if (keysCache?.source !== source) {
    keysCache = { source, keys: await loadRelayKeys(env.RELAY_KEYS, env.RELAY_KEY_CURRENT) };
  }
  return keysCache.keys;
}

function lifetime(env: Env): number {
  const value = Number(env.GRANT_LIFETIME_S);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error("GRANT_LIFETIME_S must be a positive integer");
  }
  return value;
}

async function grant(req: Request, env: Env, nowS: number): Promise<Response> {
  const b = await body(req);
  const token = typeof b?.token === "string" ? b.token.toLowerCase() : "";
  const environment = b?.environment;
  if (
    token.length > TOKEN_MAX_BYTES * 2 ||
    !HEX_TOKEN.test(token) ||
    (environment !== "sandbox" && environment !== "production")
  ) {
    return reply(400, { error: "bad_request" });
  }
  const sealed = await sealGrant(await relayKeys(env), {
    token,
    environment,
    topic: env.APNS_TOPIC,
    iat: nowS
  });
  return reply(200, {
    grant: sealed,
    expires_at: new Date((nowS + lifetime(env)) * 1000).toISOString()
  });
}

async function push(req: Request, env: Env, seams: Seams, nowS: number): Promise<Response> {
  const b = await body(req);
  const sealed = typeof b?.sealed === "string" ? fromBase64(b.sealed) : null;
  const id = b?.id;
  const thread = b?.thread;
  if (
    typeof b?.grant !== "string" ||
    !sealed ||
    typeof id !== "string" ||
    !ID_PATTERN.test(id) ||
    typeof thread !== "string" ||
    !ID_PATTERN.test(thread)
  ) {
    return reply(400, { error: "bad_request" });
  }
  // One size for every message, so the size says nothing about the content.
  if (sealed.length !== SEALED_BYTES) return reply(400, { error: "bad_size" });
  const claims = await openGrant(await relayKeys(env), b.grant);
  if (!claims) return reply(401, { error: "grant_invalid" });
  if (nowS - claims.iat > lifetime(env)) return reply(401, { error: "grant_expired" });

  // Keyed by the phone, not the grant: minting more grants for one phone buys no more pushes.
  const { success } = await env.PUSH_LIMIT.limit({ key: await sha256Hex(claims.token) });
  if (!success) return reply(429, { error: "rate_limited" });

  const payload = envelope(thread, b.sealed as string);
  if (new TextEncoder().encode(payload).length > APNS_PAYLOAD_MAX_BYTES) {
    return reply(500, { error: "envelope_too_large" });
  }
  const creds: ApnsCredentials =
    claims.environment === "production"
      ? {
          keyPem: env.APNS_KEY_PRODUCTION,
          keyId: env.APNS_KEY_ID_PRODUCTION,
          teamId: env.APNS_TEAM_ID
        }
      : { keyPem: env.APNS_KEY_SANDBOX, keyId: env.APNS_KEY_ID_SANDBOX, teamId: env.APNS_TEAM_ID };
  const result = await sendApns(
    creds,
    {
      environment: claims.environment,
      token: claims.token,
      topic: claims.topic,
      collapseId: id,
      payload
    },
    nowS,
    seams.fetch
  );
  if (result.status === 200) return reply(200, { ok: true });
  // The phone is gone or the token never belonged to this app: the channel drops the registration.
  if (
    result.status === 410 ||
    (result.status === 400 &&
      (result.reason === "BadDeviceToken" || result.reason === "DeviceTokenNotForTopic"))
  ) {
    return reply(410, { error: "unregistered", reason: result.reason });
  }
  if (result.status === 429) return reply(429, { error: "apns_rate_limited" });
  // A provider-token problem is the relay's, not the phone's: logged (no token, no content).
  console.error("apns refused", { status: result.status, reason: result.reason });
  return reply(502, { error: "apns", status: result.status, reason: result.reason });
}

export function handler(seams: Seams = {}) {
  return async (req: Request, env: Env): Promise<Response> => {
    const nowS = Math.floor((seams.now ?? Date.now)() / 1000);
    const path = new URL(req.url).pathname;
    if (path !== "/v1/grant" && path !== "/v1/push") return reply(404, { error: "not_found" });
    if (req.method !== "POST") return reply(405, { error: "method_not_allowed" });
    return path === "/v1/grant" ? grant(req, env, nowS) : push(req, env, seams, nowS);
  };
}

export default { fetch: handler() } satisfies ExportedHandler<Env>;
