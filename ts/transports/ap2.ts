// AP2 (Agent Payments Protocol) handshake adapter.
//
// Wire-binding: AP2 IntentMandates carry the signed HandshakeRequest under
// `mandate.handshake_request`. The settled receipt id is stamped onto
// `mandate.handshake_receipt_id` after execution.

import type { HandshakeContext } from "../client.js";

export interface AP2Mandate {
  mandate_type?: string;
  intent?: Record<string, unknown>;
  handshake_request?: Record<string, unknown>;
  handshake_receipt_id?: string;
  [key: string]: unknown;
}

export function attach(mandate: AP2Mandate, ctx: HandshakeContext): AP2Mandate {
  return { ...mandate, handshake_request: ctx.request };
}

export function extract(mandate: AP2Mandate): Record<string, unknown> | null {
  const req = mandate.handshake_request;
  return req && typeof req === "object" ? (req as Record<string, unknown>) : null;
}

export function stampReceiptId(mandate: AP2Mandate, receiptId: string): AP2Mandate {
  mandate.handshake_receipt_id = receiptId;
  return mandate;
}
