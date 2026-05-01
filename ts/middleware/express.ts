// Express middleware — verifies the inbound HandshakeRequest header and
// emits a Receipt once the route handler resolves.
//
// Header convention mirrors the Python middleware:
//   `Handshake-Request: <base64url(canonical-json)>`
//
// On every request the middleware:
//   1. Reads + base64url-decodes + JSON-parses the header.
//   2. Runs the full Phase 2 chain-walk verifier (`verifyHandshakeRequest`)
//      under the supplied `keys` resolver and `receiverDid`.
//   3. Rejects with HTTP 400 (malformed) or 403 (verification failed) before
//      the wrapped handler runs.
//
// SECURITY: `keys` must be supplied at construction time. A nil resolver is
// treated as a server misconfiguration and every request is rejected with
// HTTP 500. This is fail-closed by design — the previous decode-only
// behaviour was an auth bypass.

import type { IncomingMessage, ServerResponse } from "node:http";

import { Handshake, type HandshakeContext, type RecordReceiptOptions } from "../client.js";
import { HandshakeRequest } from "../models.js";
import { verifyHandshakeRequest } from "../verify.js";

export const HANDSHAKE_HEADER = "handshake-request";

export interface ExpressLikeRequest extends IncomingMessage {
  headers: IncomingMessage["headers"];
  handshake?: {
    request: Record<string, unknown>;
    receiptId?: string;
  };
}

export type ExpressNextFn = (err?: unknown) => void;

/**
 * Injectable nonce store for cross-instance replay protection.
 *
 * Production deployments should back this with a shared store (Redis,
 * Postgres, etc.) so that a nonce consumed by one pod/worker/process
 * is rejected by all others within the freshness window.
 *
 * The built-in in-process store used by the Rust verifier core is only
 * safe for single-instance deployments; this interface allows callers to
 * supply a durable or distributed alternative.
 *
 * `checkAndRecord` must be safe to call from concurrent request handlers.
 * Return a Promise if the backend requires async I/O.
 */
export interface NonceStore {
  /**
   * Return `true` if `nonce` was already seen (replay detected), else
   * record it and return `false`.
   */
  checkAndRecord(nonce: string): boolean | Promise<boolean>;
}

/**
 * Default in-process nonce store (process-local; not suitable for
 * multi-instance deployments).
 *
 * **Limitations:**
 * - **Memory growth:** nonces are stored in a `Set` indefinitely for the
 *   lifetime of the process. Under sustained traffic this grows without bound.
 *   For long-lived services use a TTL-aware backend (e.g. Redis `SET EX`) or
 *   implement eviction in a custom `NonceStore`.
 * - **Single process only:** each instance keeps an independent store, so a
 *   nonce consumed on one pod/worker is not known to others. Cross-instance
 *   replay protection requires a shared backend.
 *
 * Use only for single-instance services, short-lived processes, or tests.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Set<string>();

  checkAndRecord(nonce: string): boolean {
    if (this.seen.has(nonce)) return true;
    this.seen.add(nonce);
    return false;
  }
}

export interface ExpressHandshakeOptions {
  /** Receipt-emitting Handshake client (signs as THIS service). */
  handshake: Handshake;
  /** Map of issuer DID → 32-byte raw Ed25519 public key. REQUIRED. */
  keys: Record<string, Buffer>;
  /** DID of THIS service. The verifier rejects envelopes whose `aud`
   * doesn't match. */
  receiverDid: string;
  /** Verifier wall-clock. Defaults to () => new Date().toISOString(). */
  now?: () => string;
  /** Revoked principals at the verifier's clock. */
  revokedPrincipals?: string[];
  /** Revoked DelegationToken ids. */
  revokedDelegations?: string[];
  resolveAction?: (req: ExpressLikeRequest) => string;
  resolveCapabilityName?: (req: ExpressLikeRequest) => string;
  emitReceipt?: boolean;
  /**
   * Injectable nonce store for cross-instance replay protection.
   *
   * When not supplied the middleware relies solely on the process-local
   * nonce tracking built into the Rust verifier core, which is **not**
   * safe in multi-instance deployments (different pods/workers each have
   * their own independent store).  Supply a shared backend (Redis,
   * Postgres, …) so that a nonce consumed on one instance is rejected
   * everywhere within the freshness window.
   */
  nonceStore?: NonceStore;
}

function readHeader(req: ExpressLikeRequest, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

function decodeRequest(headerValue: string): Record<string, unknown> {
  const json = Buffer.from(headerValue, "base64url").toString("utf8");
  const parsed = JSON.parse(json) as Record<string, unknown>;
  HandshakeRequest.parse(parsed);
  return parsed;
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

/**
 * Returns an Express-style middleware (req, res, next).
 *
 * The middleware:
 *   1. Parses + schema-validates the `Handshake-Request` header.
 *   2. Cryptographically verifies it (chain walk + signature + audience +
 *      freshness + replay) under the configured `keys` and `receiverDid`.
 *   3. If a `nonceStore` is supplied, performs an additional cross-instance
 *      replay check before calling `next()`.
 *   4. Mounts `req.handshake = { request }` so handlers can read it.
 *   5. After the response finishes (`res.on("finish")`), opens a HandshakeContext
 *      and records a Receipt summarising status + path. Failures are swallowed
 *      so the response path is never blocked.
 */
export function expressHandshake(opts: ExpressHandshakeOptions) {
  const hs = opts.handshake;
  const emitReceipt = opts.emitReceipt ?? true;
  const resolveAction = opts.resolveAction ?? ((req) => `${req.method ?? "GET"} ${req.url ?? "/"}`);
  const resolveCapability = opts.resolveCapabilityName ?? (() => "http.server.handle");
  const now = opts.now ?? (() => new Date().toISOString());
  const nonceStore = opts.nonceStore ?? null;

  return function middleware(
    req: ExpressLikeRequest,
    res: ServerResponse,
    next: ExpressNextFn,
  ): void {
    // Fail-closed: missing key resolver or receiverDid is a server
    // misconfiguration, not a client error.
    if (!opts.keys) {
      writeJson(res, 500, { error: "handshake middleware misconfigured: keys resolver is required" });
      return;
    }
    if (!opts.receiverDid) {
      writeJson(res, 500, { error: "handshake middleware misconfigured: receiverDid is required" });
      return;
    }

    const headerValue = readHeader(req, HANDSHAKE_HEADER);
    if (!headerValue) {
      writeJson(res, 400, { error: "missing Handshake-Request header" });
      return;
    }

    let request: Record<string, unknown>;
    try {
      request = decodeRequest(headerValue);
    } catch (err) {
      writeJson(res, 400, { error: "invalid Handshake-Request", detail: String(err) });
      return;
    }

    const verifyResult = verifyHandshakeRequest(request, opts.keys, opts.receiverDid, now(), {
      revokedPrincipals: opts.revokedPrincipals,
      revokedDelegations: opts.revokedDelegations,
    });
    if (verifyResult.result !== "accept") {
      writeJson(res, 403, {
        error: "handshake_rejected",
        error_code: verifyResult.error_code,
        rejected_at_step: verifyResult.rejected_at_step,
        detail: verifyResult.detail,
        ...(verifyResult.rejected_delegation_id !== null
          ? { rejected_delegation_id: verifyResult.rejected_delegation_id }
          : {}),
      });
      return;
    }

    // Cross-instance replay check using the injectable nonce store.
    if (nonceStore !== null) {
      const nonce = typeof request["nonce"] === "string" ? request["nonce"] : null;
      if (nonce !== null) {
        const replayResult = nonceStore.checkAndRecord(nonce);
        if (replayResult instanceof Promise) {
          // Async nonce store: bridge the promise into the middleware flow.
          replayResult.then((isReplay) => {
            if (isReplay) {
              writeJson(res, 403, {
                error: "handshake_rejected",
                error_code: "replay_detected",
                rejected_at_step: "nonce_check",
                detail: "nonce already consumed (replay)",
                rejected_delegation_id: null,
              });
              return;
            }
            finishRequest(req, res, next, request, hs, emitReceipt, resolveAction, resolveCapability);
          }).catch((_err: unknown) => {
            writeJson(res, 500, { error: "internal server error" });
          });
          return;
        }
        if (replayResult) {
          writeJson(res, 403, {
            error: "handshake_rejected",
            error_code: "replay_detected",
            rejected_at_step: "nonce_check",
            detail: "nonce already consumed (replay)",
            rejected_delegation_id: null,
          });
          return;
        }
      }
    }

    finishRequest(req, res, next, request, hs, emitReceipt, resolveAction, resolveCapability);
  };
}

function finishRequest(
  req: ExpressLikeRequest,
  res: ServerResponse,
  next: ExpressNextFn,
  request: Record<string, unknown>,
  hs: Handshake,
  emitReceipt: boolean,
  resolveAction: (req: ExpressLikeRequest) => string,
  resolveCapability: (req: ExpressLikeRequest) => string,
): void {
  req.handshake = { request };

  if (emitReceipt) {
    res.on("finish", () => {
      // Best-effort post-response receipt; never throws into the request
      // lifecycle.
      void (async () => {
        try {
          const cap = (request["capability"] ?? {}) as { name?: string };
          const ctx: HandshakeContext = hs.handshake({
            aud: typeof request["iss"] === "string" ? (request["iss"] as string) : "did:hsk:unknown",
            capability: { name: cap.name ?? resolveCapability(req) },
            delegationChain: [],
          });
          const receiptOpts: RecordReceiptOptions = {
            action: resolveAction(req),
            result: res.statusCode < 400 ? "ok" : "error",
            resultPayload: { status: res.statusCode, path: req.url },
            resultSummary: { transport: "express", status: res.statusCode },
          };
          const out = await hs.recordReceipt(ctx, receiptOpts);
          if (req.handshake) req.handshake.receiptId = out.receiptId;
        } catch {
          // intentionally swallowed
        }
      })();
    });
  }

  next();
}
