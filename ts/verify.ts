// Phase 2 chain-walk verifier — TypeScript facade.
//
// Wraps the NAPI-RS FFI surface (`verifyHandshakeRequestJson` /
// `intersectCapabilitiesJson`) into ergonomic helpers that take JS-native
// types and return discriminated unions. The verifier itself runs entirely
// in the canonical Rust core — this module is a thin shim that handles
// JSON serialization on the way in and result parsing on the way out, so
// TypeScript callers see identical semantics to Python and Rust callers
// (ADR-0006).

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const native = require("../index.cjs") as {
  verifyHandshakeRequestJson: (
    requestJson: string,
    keys: Record<string, Buffer>,
    receiverDid: string,
    nowRfc3339: string,
    revokedPrincipals?: string[],
    revokedDelegations?: string[],
  ) => string;
  intersectCapabilitiesJson: (delegatedJson: string, requestedJson: string) => string;
};

/** Discriminated union for verifier outcomes. Mirrors `_common.json` errorCode. */
export type VerifyResult =
  | {
      result: "accept";
      capability: string;
      effective_constraints: Record<string, unknown>;
    }
  | {
      result: "reject";
      error_code: string;
      rejected_at_step: string;
      detail: string;
      rejected_delegation_id: string | null;
    };

/** Optional knobs for `verifyHandshakeRequest`. */
export interface VerifyOptions {
  /** DID strings whose principals are revoked at the verifier's clock. */
  revokedPrincipals?: string[];
  /** DelegationToken ids that have been revoked. */
  revokedDelegations?: string[];
}

/**
 * Verify a signed `HandshakeRequest`.
 *
 * `request` may be a parsed object or a JSON string; we always reserialize
 * via `JSON.stringify` so the FFI hop is unambiguous. `keys` maps DID
 * strings to raw 32-byte Ed25519 public keys (the shape `ed25519KeypairFromSeed`
 * returns). `nowRfc3339` is the verifier's wall clock — used for freshness
 * window + per-link expiry checks.
 */
export function verifyHandshakeRequest(
  request: object | string,
  keys: Record<string, Buffer>,
  receiverDid: string,
  nowRfc3339: string,
  options: VerifyOptions = {},
): VerifyResult {
  const requestJson = typeof request === "string" ? request : JSON.stringify(request);
  const payload = native.verifyHandshakeRequestJson(
    requestJson,
    keys,
    receiverDid,
    nowRfc3339,
    options.revokedPrincipals ?? [],
    options.revokedDelegations ?? [],
  );
  return JSON.parse(payload) as VerifyResult;
}

/** Intersect two capability constraint sets. */
export function intersectCapabilities(
  delegated: Record<string, unknown>,
  requested: Record<string, unknown>,
): { ok: true; effective: Record<string, unknown> } | { ok: false; error_code: "scope_exceeded"; key: string; reason: string } {
  const payload = native.intersectCapabilitiesJson(JSON.stringify(delegated), JSON.stringify(requested));
  return JSON.parse(payload);
}
