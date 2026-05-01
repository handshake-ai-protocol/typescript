// A2A (Agent-to-Agent) handshake adapter.
//
// Wire-binding: the signed HandshakeRequest is attached to the JSON-RPC
// envelope as `metadata.handshake.request`. Receipt id rides back at
// `metadata.handshake.receipt_id`.

import type { HandshakeContext } from "../client.js";

export interface A2AEnvelope {
  jsonrpc?: string;
  method?: string;
  params?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export function attach(envelope: A2AEnvelope, ctx: HandshakeContext): A2AEnvelope {
  const metadata = (envelope.metadata ?? {}) as Record<string, unknown>;
  metadata["handshake"] = {
    request: ctx.request,
    spec_version: (ctx.request as Record<string, unknown>)["version"],
  };
  return { ...envelope, metadata };
}

export function extract(envelope: A2AEnvelope): Record<string, unknown> | null {
  const metadata = (envelope.metadata ?? {}) as Record<string, unknown>;
  const hs = (metadata["handshake"] ?? {}) as Record<string, unknown>;
  const req = hs["request"];
  return req && typeof req === "object" ? (req as Record<string, unknown>) : null;
}

export function stampReceiptId(envelope: A2AEnvelope, receiptId: string): A2AEnvelope {
  const metadata = (envelope.metadata ?? {}) as Record<string, unknown>;
  const hs = (metadata["handshake"] ?? {}) as Record<string, unknown>;
  hs["receipt_id"] = receiptId;
  metadata["handshake"] = hs;
  envelope.metadata = metadata;
  return envelope;
}
