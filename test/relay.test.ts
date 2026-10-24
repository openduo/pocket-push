// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

import { generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { TOKEN_MAX_BYTES, handler, type Env } from "../src/index";
import { APNS_PAYLOAD_MAX_BYTES, SEALED_BYTES, envelope } from "../src/envelope";
import { PROVIDER_TOKEN_PERIOD_S, providerToken, resetApnsCache } from "../src/apns";
import { base64url, fromBase64url } from "../src/bytes";

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const PEM_PRODUCTION = generateKeyPairSync("ec", { namedCurve: "P-256" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();
const TOKEN = "ab".repeat(32);
const ID = "1".repeat(64);
const THREAD = "2".repeat(64);
const T0 = 1_800_000_000_000;

type Sent = { url: string; headers: Record<string, string>; body: string };

function rig(apns: { status: number; reason?: string } = { status: 200 }) {
  const limited: string[] = [];
  let allow = true;
  const sent: Sent[] = [];
  let now = T0;
  const env: Env = {
    APNS_KEY_SANDBOX: PEM,
    APNS_KEY_ID_SANDBOX: "SANDBOXID",
    APNS_KEY_PRODUCTION: PEM_PRODUCTION,
    APNS_KEY_ID_PRODUCTION: "PRODID",
    APNS_TEAM_ID: "TEAMID",
    RELAY_KEYS: JSON.stringify({ k1: base64url(randomBytes(32)) }),
    RELAY_KEY_CURRENT: "k1",
    APNS_TOPIC: "dev.openduo.pocket",
    GRANT_LIFETIME_S: "604800",
    PUSH_LIMIT: {
      limit: async ({ key }: { key: string }) => {
        limited.push(key);
        return { success: allow };
      }
    } as unknown as RateLimit
  };
  const fetcher = (async (url: string, init: RequestInit) => {
    sent.push({ url, headers: init.headers as Record<string, string>, body: init.body as string });
    return new Response(apns.reason ? JSON.stringify({ reason: apns.reason }) : null, {
      status: apns.status
    });
  }) as unknown as typeof fetch;
  const run = handler({ fetch: fetcher, now: () => now });
  const post = (path: string, body: unknown) =>
    run(
      new Request(`https://pocket-push.openduo.app${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      }),
      env
    );
  return {
    env,
    sent,
    limited,
    post,
    run,
    deny: () => (allow = false),
    advance: (ms: number) => (now += ms)
  };
}

const sealed = () => Buffer.from(randomBytes(SEALED_BYTES)).toString("base64");

async function grantOf(r: ReturnType<typeof rig>, environment = "sandbox"): Promise<string> {
  const res = await r.post("/v1/grant", { token: TOKEN, environment });
  expect(res.status).toBe(200);
  return ((await res.json()) as { grant: string }).grant;
}

beforeEach(() => resetApnsCache());

describe("envelope", () => {
  it("SEALED_BYTES is the largest sealed size that fits the APNs payload limit", () => {
    const size = (n: number) =>
      new TextEncoder().encode(envelope(THREAD, Buffer.alloc(n).toString("base64"))).length;
    expect(size(SEALED_BYTES)).toBeLessThanOrEqual(APNS_PAYLOAD_MAX_BYTES);
    expect(size(SEALED_BYTES + 1)).toBeGreaterThan(APNS_PAYLOAD_MAX_BYTES);
  });
});

describe("grant", () => {
  it("issues a grant with the configured lifetime", async () => {
    const r = rig();
    const res = await r.post("/v1/grant", {
      token: TOKEN.toUpperCase(),
      environment: "production"
    });
    const body = (await res.json()) as { grant: string; expires_at: string };
    expect(res.status).toBe(200);
    expect(Date.parse(body.expires_at)).toBe(T0 + 604800 * 1000);
    // The token is sealed, not readable from the grant.
    expect(Buffer.from(fromBase64url(body.grant)!).toString("latin1")).not.toContain("abab");
  });

  it("refuses a token that is not hex and an unknown environment", async () => {
    const r = rig();
    expect((await r.post("/v1/grant", { token: "xyz", environment: "sandbox" })).status).toBe(400);
    expect((await r.post("/v1/grant", { token: TOKEN, environment: "dev" })).status).toBe(400);
    expect((await r.post("/v1/grant", { token: "abc", environment: "sandbox" })).status).toBe(400);
    const max = "ab".repeat(TOKEN_MAX_BYTES);
    expect((await r.post("/v1/grant", { token: max, environment: "sandbox" })).status).toBe(200);
    expect((await r.post("/v1/grant", { token: max + "ab", environment: "sandbox" })).status).toBe(
      400
    );
  });
});

describe("push", () => {
  it("delivers through APNs with the grant's address and the caller's ids", async () => {
    const r = rig();
    const grant = await grantOf(r);
    const s = sealed();
    const res = await r.post("/v1/push", { grant, sealed: s, id: ID, thread: THREAD });
    expect(res.status).toBe(200);
    expect(r.sent).toHaveLength(1);
    const req = r.sent[0]!;
    expect(req.url).toBe(`https://api.sandbox.push.apple.com/3/device/${TOKEN}`);
    expect(req.headers["apns-topic"]).toBe("dev.openduo.pocket");
    expect(req.headers["apns-collapse-id"]).toBe(ID);
    expect(req.headers["apns-push-type"]).toBe("alert");
    const payload = JSON.parse(req.body);
    expect(payload.s).toBe(s);
    expect(payload.aps["thread-id"]).toBe(THREAD);
    expect(payload.aps["mutable-content"]).toBe(1);
    expect(new TextEncoder().encode(req.body).length).toBeLessThanOrEqual(4096);
  });

  it("rate-limits by the device token's digest, not by the grant", async () => {
    const r = rig();
    await r.post("/v1/push", { grant: await grantOf(r), sealed: sealed(), id: ID, thread: THREAD });
    await r.post("/v1/push", { grant: await grantOf(r), sealed: sealed(), id: ID, thread: THREAD });
    const digest = createHash("sha256").update(TOKEN).digest("hex");
    expect(r.limited).toEqual([digest, digest]);
    r.deny();
    const res = await r.post("/v1/push", {
      grant: await grantOf(r),
      sealed: sealed(),
      id: ID,
      thread: THREAD
    });
    expect(res.status).toBe(429);
    expect(r.sent).toHaveLength(2);
  });

  it("refuses a sealed message of any other size", async () => {
    const r = rig();
    const grant = await grantOf(r);
    const short = Buffer.from(randomBytes(SEALED_BYTES - 1)).toString("base64");
    expect(
      (await r.post("/v1/push", { grant, sealed: short, id: ID, thread: THREAD })).status
    ).toBe(400);
    expect(r.sent).toHaveLength(0);
  });

  it("refuses ids that are not 64 hex characters", async () => {
    const r = rig();
    const grant = await grantOf(r);
    for (const bad of [{ id: "x" }, { thread: "room-name" }]) {
      const res = await r.post("/v1/push", {
        grant,
        sealed: sealed(),
        id: ID,
        thread: THREAD,
        ...bad
      });
      expect(res.status).toBe(400);
    }
  });

  it("refuses a tampered grant, a grant of another relay key, and an expired grant", async () => {
    const r = rig();
    const grant = await grantOf(r);
    const bytes = fromBase64url(grant)!;
    bytes[bytes.length - 1]! ^= 1;
    const tampered = base64url(bytes);
    expect(
      (await r.post("/v1/push", { grant: tampered, sealed: sealed(), id: ID, thread: THREAD }))
        .status
    ).toBe(401);

    const other = rig();
    const foreign = await grantOf(other);
    expect(
      (await r.post("/v1/push", { grant: foreign, sealed: sealed(), id: ID, thread: THREAD }))
        .status
    ).toBe(401);

    r.advance(604800 * 1000 + 1000);
    const res = await r.post("/v1/push", { grant, sealed: sealed(), id: ID, thread: THREAD });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "grant_expired" });
    expect(r.sent).toHaveLength(0);
  });

  it("keeps old grants working after rotation while the old key stays listed", async () => {
    const r = rig();
    const grant = await grantOf(r);
    const keys = JSON.parse(r.env.RELAY_KEYS);
    r.env.RELAY_KEYS = JSON.stringify({ ...keys, k2: base64url(randomBytes(32)) });
    r.env.RELAY_KEY_CURRENT = "k2";
    expect(
      (await r.post("/v1/push", { grant, sealed: sealed(), id: ID, thread: THREAD })).status
    ).toBe(200);
    r.env.RELAY_KEYS = JSON.stringify({ k2: JSON.parse(r.env.RELAY_KEYS).k2 });
    expect(
      (await r.post("/v1/push", { grant, sealed: sealed(), id: ID, thread: THREAD })).status
    ).toBe(401);
  });

  it.each([
    [410, "Unregistered"],
    [400, "BadDeviceToken"],
    [400, "DeviceTokenNotForTopic"]
  ])("answers 410 when APNs says the phone is gone (%i %s)", async (status, reason) => {
    const r = rig({ status, reason });
    const res = await r.post("/v1/push", {
      grant: await grantOf(r),
      sealed: sealed(),
      id: ID,
      thread: THREAD
    });
    expect(res.status).toBe(410);
  });

  it("answers 502 for a provider-token refusal and keeps the registration", async () => {
    const r = rig({ status: 403, reason: "InvalidProviderToken" });
    const res = await r.post("/v1/push", {
      grant: await grantOf(r),
      sealed: sealed(),
      id: ID,
      thread: THREAD
    });
    expect(res.status).toBe(502);
  });
});

describe("environments", () => {
  it("signs each environment with its own key and sends to its own host", async () => {
    const r = rig();
    for (const environment of ["sandbox", "production"]) {
      const grant = await grantOf(r, environment);
      expect(
        (await r.post("/v1/push", { grant, sealed: sealed(), id: ID, thread: THREAD })).status
      ).toBe(200);
    }
    const kid = (s: Sent) =>
      JSON.parse(
        Buffer.from(fromBase64url(s.headers.authorization!.slice(7).split(".")[0]!)!).toString()
      ).kid;
    expect(r.sent.map((s) => [new URL(s.url).host, kid(s)])).toEqual([
      ["api.sandbox.push.apple.com", "SANDBOXID"],
      ["api.push.apple.com", "PRODID"]
    ]);
  });
});

describe("routing", () => {
  it("serves nothing but the two POST endpoints", async () => {
    const r = rig();
    expect((await r.run(new Request("https://x/"), r.env)).status).toBe(404);
    expect((await r.run(new Request("https://x/v1/push"), r.env)).status).toBe(405);
  });
});

describe("provider token", () => {
  it("is reused within the half hour and renewed after it", async () => {
    const creds = { keyPem: PEM, keyId: "KEYID", teamId: "TEAMID" };
    const start = 1_800_000_000 - (1_800_000_000 % PROVIDER_TOKEN_PERIOD_S);
    const a = await providerToken(creds, start + 1);
    const b = await providerToken(creds, start + PROVIDER_TOKEN_PERIOD_S - 1);
    const c = await providerToken(creds, start + PROVIDER_TOKEN_PERIOD_S);
    expect(b).toBe(a);
    expect(c).not.toBe(a);
    const claims = JSON.parse(Buffer.from(fromBase64url(a.split(".")[1]!)!).toString());
    expect(claims).toEqual({ iss: "TEAMID", iat: start });
  });
});
