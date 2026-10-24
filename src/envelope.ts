// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

/**
 * The APNs payload the relay sends. The visible alert is a placeholder in the app's own strings;
 * the app's notification service extension opens `s` with the phone's key and replaces it. The
 * relay cannot read `s`. The envelope carries no sound: if the extension does not run, the
 * placeholder arrives silently, so nothing the relay sends on its own can ring the phone; the
 * extension adds the sound for a message it opened.
 */

/** APNs' limit for a remote notification payload, in bytes. */
export const APNS_PAYLOAD_MAX_BYTES = 4096;

/** `thread-id` and `apns-collapse-id` are HMAC-SHA256 values in hex: 64 characters. */
export const ID_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The exact size of every sealed message, so every push has one length. It is the largest size
 * whose envelope stays within `APNS_PAYLOAD_MAX_BYTES`; `envelope.test.ts` proves both halves.
 * The channel pads to it (`PUSH_SEALED_BYTES` in `@openduo/ambient-protocol`).
 */
export const SEALED_BYTES = 2934;

export function envelope(thread: string, sealedBase64: string): string {
  return JSON.stringify({
    aps: {
      alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_PLACEHOLDER" },
      "mutable-content": 1,
      "thread-id": thread
    },
    s: sealedBase64
  });
}
