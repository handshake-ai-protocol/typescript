// Phase 2 chain-walk verifier — TypeScript facade.
//
// Wraps the NAPI-RS FFI surface (`verifyHandshakeRequestJson` /
// `intersectCapabilitiesJson`) into ergonomic helpers that take JS-native
// types and return discriminated unions. The verifier itself runs entirely
// in the canonical Rust core — this module is a thin shim that handles
// JSON serialization on the way in and result parsing on the way out, so
// TypeScript callers see identical semantics to Python and Rust callers
// (ADR-0006).
//
// SECURITY — multi-instance deployments: the Rust core's built-in nonce
// tracking is process-local. In a load-balanced service with multiple pods or
// workers, a valid signed request can be replayed against a different worker
// within the freshness window (~60 s) because each process tracks seen nonces
// independently. Pass `options.nonceStore` to add a synchronous cross-instance
// replay check on top of the Rust-core verification. For async nonce stores
// or the full fail-closed middleware pattern, use `expressHandshake` from
// `handshake/middleware/express`.

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

/**
 * Synchronous nonce store interface for cross-instance replay protection at
 * the base verifier level. Only synchronous `checkAndRecord` is supported
 * here; for async stores use the Express middleware instead.
 *
 * Implementors must be thread-safe / concurrency-safe for the deployment's
 * execution model.
 */
export interface SyncNonceStore {
  /**
   * Return `true` if `nonce` was already seen (replay detected), else
   * record it and return `false`.
   */
  checkAndRecord(nonce: string): boolean;
}

/** Optional knobs for `verifyHandshakeRequest`. */
export interface VerifyOptions {
  /** DID strings whose principals are revoked at the verifier's clock. */
  revokedPrincipals?: string[];
  /** DelegationToken ids that have been revoked. */
  revokedDelegations?: string[];
  /**
   * Optional cross-instance replay guard. When supplied, after the Rust-core
   * verification succeeds the nonce is checked against this store. This is the
   * only way to get distributed replay protection for direct verifier callers
   * in multi-instance deployments — the Rust core's built-in nonce tracking
   * is process-local. Only synchronous stores are accepted here; for async
   * stores use the Express middleware (`expressHandshake` with `nonceStore`).
   */
  nonceStore?: SyncNonceStore;
}

/**
 * Verify a signed `HandshakeRequest`.
 *
 * `request` may be a parsed object or a JSON string; we always reserialize
 * via `JSON.stringify` so the FFI hop is unambiguous. `keys` maps DID
 * strings to raw 32-byte Ed25519 public keys (the shape `ed25519KeypairFromSeed`
 * returns). `nowRfc3339` is the verifier's wall clock — used for freshness
 * window + per-link expiry checks.
 *
 * When `options.nonceStore` is supplied, the nonce is also checked against
 * the external store after the Rust-core verification succeeds, providing
 * distributed replay protection for multi-instance deployments.
 */
export function verifyHandshakeRequest(
  request: object | string,
  keys: Record<string, Buffer>,
  receiverDid: string,
  nowRfc3339: string,
  options: VerifyOptions = {},
): VerifyResult {
  const requestObj: Record<string, unknown> =
    typeof request === "string"
      ? (JSON.parse(request) as Record<string, unknown>)
      : (request as Record<string, unknown>);
  const requestJson = typeof request === "string" ? request : JSON.stringify(request);

  const payload = native.verifyHandshakeRequestJson(
    requestJson,
    keys,
    receiverDid,
    nowRfc3339,
    options.revokedPrincipals ?? [],
    options.revokedDelegations ?? [],
  );
  const result = JSON.parse(payload) as VerifyResult;

  // Cross-instance replay check via the injectable nonce store.
  // This supplements the process-local check inside the Rust core, providing
  // distributed replay protection in multi-pod / multi-worker deployments.
  if (result.result === "accept" && options.nonceStore != null) {
    const nonce = typeof requestObj["nonce"] === "string" ? requestObj["nonce"] : null;
    if (nonce !== null && options.nonceStore.checkAndRecord(nonce)) {
      return {
        result: "reject",
        error_code: "replay_detected",
        rejected_at_step: "nonce_check",
        detail: "nonce already consumed (replay)",
        rejected_delegation_id: null,
      };
    }
  }

  return result;
}

/** Intersect two capability constraint sets. */
export function intersectCapabilities(
  delegated: Record<string, unknown>,
  requested: Record<string, unknown>,
): { ok: true; effective: Record<string, unknown> } | { ok: false; error_code: "scope_exceeded"; key: string; reason: string } {
  const payload = native.intersectCapabilitiesJson(JSON.stringify(delegated), JSON.stringify(requested));
  return JSON.parse(payload);
}
