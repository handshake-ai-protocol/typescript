// MCP (Model Context Protocol) handshake adapter.
//
// Wire-binding: the signed HandshakeRequest envelope is base64url-encoded
// and stored at `payload._meta.handshake.request_b64u`. The receipt id
// rides back at `payload._meta.handshake.receipt_id`.

import type { HandshakeContext } from "../client.js";

export function encodeRequest(ctx: HandshakeContext): string {
  return Buffer.from(JSON.stringify(ctx.request)).toString("base64url");
}

export function decodeRequest(b64u: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(b64u, "base64url").toString("utf8")) as Record<string, unknown>;
}

export function attach<T extends Record<string, unknown>>(
  payload: T,
  ctx: HandshakeContext,
): T & { _meta: Record<string, unknown> } {
  const meta = ((payload as { _meta?: Record<string, unknown> })._meta ?? {}) as Record<string, unknown>;
  meta["handshake"] = {
    request_b64u: encodeRequest(ctx),
    spec_version: (ctx.request as Record<string, unknown>)["version"],
  };
  return { ...payload, _meta: meta };
}

export function extract(payload: Record<string, unknown>): Record<string, unknown> | null {
  const meta = (payload["_meta"] ?? {}) as Record<string, unknown>;
  const hs = (meta["handshake"] ?? {}) as Record<string, unknown>;
  const b64u = hs["request_b64u"];
  return typeof b64u === "string" ? decodeRequest(b64u) : null;
}

export function stampReceiptId<T extends Record<string, unknown>>(
  payload: T,
  receiptId: string,
): T {
  const meta = ((payload as { _meta?: Record<string, unknown> })._meta ?? {}) as Record<string, unknown>;
  const hs = (meta["handshake"] ?? {}) as Record<string, unknown>;
  hs["receipt_id"] = receiptId;
  meta["handshake"] = hs;
  (payload as { _meta?: Record<string, unknown> })._meta = meta;
  return payload;
}
