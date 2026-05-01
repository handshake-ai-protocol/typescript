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
 *   3. Mounts `req.handshake = { request }` so handlers can read it.
 *   4. After the response finishes (`res.on("finish")`), opens a HandshakeContext
 *      and records a Receipt summarising status + path. Failures are swallowed
 *      so the response path is never blocked.
 */
export function expressHandshake(opts: ExpressHandshakeOptions) {
  const hs = opts.handshake;
  const emitReceipt = opts.emitReceipt ?? true;
  const resolveAction = opts.resolveAction ?? ((req) => `${req.method ?? "GET"} ${req.url ?? "/"}`);
  const resolveCapability = opts.resolveCapabilityName ?? (() => "http.server.handle");
  const now = opts.now ?? (() => new Date().toISOString());

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
  };
}
