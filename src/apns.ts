// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

/** Token-based APNs: an ES256 provider token and one HTTP/2 POST per notification. */
import { base64url, utf8 } from "./bytes";
import type { ApnsEnvironment } from "./grant";

const HOSTS: Record<ApnsEnvironment, string> = {
  sandbox: "https://api.sandbox.push.apple.com",
  production: "https://api.push.apple.com"
};

/**
 * APNs refuses a provider token older than one hour and answers `TooManyProviderTokenUpdates`
 * when a token changes more often than every 20 minutes. Rounding `iat` down to the half hour
 * keeps every token in an isolate between those bounds, and isolates started in the same half
 * hour carry the same `iat`.
 */
export const PROVIDER_TOKEN_PERIOD_S = 30 * 60;

export type ApnsCredentials = { keyPem: string; keyId: string; teamId: string };

/** Per key id: one imported key and one cached provider token each. */
const signingKeys = new Map<string, { pem: string; key: CryptoKey }>();
const cached = new Map<string, { iat: number; token: string }>();

async function importKey(keyId: string, pem: string): Promise<CryptoKey> {
  const known = signingKeys.get(keyId);
  if (known?.pem === pem) return known.key;
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  signingKeys.set(keyId, { pem, key });
  return key;
}

export async function providerToken(creds: ApnsCredentials, nowS: number): Promise<string> {
  const iat = nowS - (nowS % PROVIDER_TOKEN_PERIOD_S);
  const hit = cached.get(creds.keyId);
  if (hit?.iat === iat) return hit.token;
  const key = await importKey(creds.keyId, creds.keyPem);
  const part = (o: unknown): string => base64url(utf8.encode(JSON.stringify(o)));
  const signed = `${part({ alg: "ES256", kid: creds.keyId })}.${part({ iss: creds.teamId, iat })}`;
  // WebCrypto returns the raw r||s signature JWS ES256 wants (RFC 7518 §3.4).
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    utf8.encode(signed)
  );
  const token = `${signed}.${base64url(new Uint8Array(sig))}`;
  cached.set(creds.keyId, { iat, token });
  return token;
}

export type ApnsRequest = {
  environment: ApnsEnvironment;
  token: string;
  topic: string;
  collapseId: string;
  payload: string;
};

export type ApnsResult = { status: number; reason: string | null };

export async function sendApns(
  creds: ApnsCredentials,
  req: ApnsRequest,
  nowS: number,
  fetcher: typeof fetch = fetch
): Promise<ApnsResult> {
  const res = await fetcher(`${HOSTS[req.environment]}/3/device/${req.token}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${await providerToken(creds, nowS)}`,
      "apns-topic": req.topic,
      "apns-push-type": "alert",
      "apns-priority": "10",
      "apns-collapse-id": req.collapseId,
      "content-type": "application/json"
    },
    body: req.payload
  });
  if (res.status === 200) return { status: 200, reason: null };
  let reason: string | null = null;
  try {
    const body = (await res.json()) as { reason?: unknown };
    if (typeof body.reason === "string") reason = body.reason;
  } catch {
    // APNs answers errors with a JSON reason; anything else keeps the status alone.
  }
  return { status: res.status, reason };
}

/** For tests: forget the cached key and token. */
export function resetApnsCache(): void {
  signingKeys.clear();
  cached.clear();
}
