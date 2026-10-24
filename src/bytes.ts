// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

/** Byte helpers that run unchanged in a Worker and in Node (the tests). */

export const utf8 = new TextEncoder();
export const fromUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

function toBinary(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function fromBinary(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function base64(bytes: Uint8Array): string {
  return btoa(toBinary(bytes));
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Strict standard base64 with padding; null for anything else. */
export function fromBase64(s: string): Uint8Array | null {
  return BASE64.test(s) ? fromBinary(atob(s)) : null;
}

export function base64url(bytes: Uint8Array): string {
  return base64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url; null for anything else. */
export function fromBase64url(s: string): Uint8Array | null {
  if (!BASE64URL.test(s) || s.length % 4 === 1) return null;
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return fromBinary(atob(std + "=".repeat((4 - (std.length % 4)) % 4)));
}

export function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(text))));
}
