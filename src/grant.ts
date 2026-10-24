// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

/**
 * A grant is the relay's sealed note of one phone's APNs address. The relay keeps no state: the
 * channel stores the grant and presents it with every push, and only the relay can open it.
 *
 * Layout (then base64url): version byte, key id length byte, key id (UTF-8), 12-byte nonce,
 * AES-256-GCM ciphertext and tag. The version byte and key id are the additional data, so neither
 * can be swapped without failing the tag.
 */
import { base64url, fromBase64url, fromUtf8, utf8 } from "./bytes";

export const GRANT_VERSION = 1;
/** AES-GCM's standard nonce length (NIST SP 800-38D). */
const NONCE_BYTES = 12;
/** AES-256. */
export const RELAY_KEY_BYTES = 32;

export type ApnsEnvironment = "sandbox" | "production";

export type GrantClaims = {
  /** The APNs device token, lowercase hex. */
  token: string;
  environment: ApnsEnvironment;
  /** The APNs topic (the app's bundle id). */
  topic: string;
  /** Issue time, Unix seconds. */
  iat: number;
};

export type RelayKeys = {
  /** The id new grants are sealed with. */
  current: string;
  keys: Map<string, CryptoKey>;
};

/**
 * `RELAY_KEYS` is a JSON object of key id to base64url 32-byte key. Rotation adds a new id, makes
 * it current, and drops the old id once every phone has renewed (one grant lifetime later).
 */
export async function loadRelayKeys(json: string, current: string): Promise<RelayKeys> {
  const parsed: unknown = JSON.parse(json);
  if (typeof parsed !== "object" || parsed === null) throw new Error("RELAY_KEYS is not an object");
  const keys = new Map<string, CryptoKey>();
  for (const [id, raw] of Object.entries(parsed as Record<string, unknown>)) {
    const bytes = typeof raw === "string" ? fromBase64url(raw) : null;
    if (!bytes || bytes.length !== RELAY_KEY_BYTES || utf8.encode(id).length > 255 || !id) {
      throw new Error(`RELAY_KEYS entry ${JSON.stringify(id)} is not a 32-byte base64url key`);
    }
    keys.set(
      id,
      await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"])
    );
  }
  if (!keys.has(current)) throw new Error("RELAY_KEY_CURRENT names no key in RELAY_KEYS");
  return { current, keys };
}

function header(keyId: string): Uint8Array {
  const id = utf8.encode(keyId);
  const out = new Uint8Array(2 + id.length);
  out[0] = GRANT_VERSION;
  out[1] = id.length;
  out.set(id, 2);
  return out;
}

export async function sealGrant(keys: RelayKeys, claims: GrantClaims): Promise<string> {
  const head = header(keys.current);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const body = utf8.encode(
    JSON.stringify({ t: claims.token, e: claims.environment, p: claims.topic, iat: claims.iat })
  );
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: head },
      keys.keys.get(keys.current)!,
      body
    )
  );
  const out = new Uint8Array(head.length + NONCE_BYTES + sealed.length);
  out.set(head, 0);
  out.set(nonce, head.length);
  out.set(sealed, head.length + NONCE_BYTES);
  return base64url(out);
}

/** The claims, or null for anything the relay did not seal with a key it still holds. */
export async function openGrant(keys: RelayKeys, grant: string): Promise<GrantClaims | null> {
  const bytes = fromBase64url(grant);
  if (!bytes || bytes.length < 2 || bytes[0] !== GRANT_VERSION) return null;
  const idLength = bytes[1]!;
  const start = 2 + idLength;
  if (bytes.length < start + NONCE_BYTES) return null;
  let keyId: string;
  try {
    keyId = fromUtf8.decode(bytes.subarray(2, start));
  } catch {
    return null;
  }
  const key = keys.keys.get(keyId);
  if (!key) return null;
  let body: Uint8Array;
  try {
    body = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bytes.subarray(start, start + NONCE_BYTES),
          additionalData: bytes.subarray(0, start)
        },
        key,
        bytes.subarray(start + NONCE_BYTES)
      )
    );
  } catch {
    return null;
  }
  const c = JSON.parse(fromUtf8.decode(body)) as Record<string, unknown>;
  if (
    typeof c.t !== "string" ||
    (c.e !== "sandbox" && c.e !== "production") ||
    typeof c.p !== "string" ||
    typeof c.iat !== "number"
  ) {
    return null;
  }
  return { token: c.t, environment: c.e, topic: c.p, iat: c.iat };
}
