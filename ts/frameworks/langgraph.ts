// LangGraph.js wrapper — `wrapNode(fn, ...)` audits each graph step.

import { Handshake } from "../client.js";
import { Capability } from "../models.js";

export type GraphState = Record<string, unknown> & { _handshake_receipts?: string[] };

export interface WrapNodeOptions {
  handshake: Handshake;
  action: string;
  toolDid: string;
  capability?: Capability;
}

const DEFAULT_CAPABILITY = Capability.parse({ name: "ai.langgraph.node" });

export function wrapNode<S extends GraphState>(
  fn: (state: S) => Promise<Partial<S>> | Partial<S>,
  opts: WrapNodeOptions,
): (state: S) => Promise<Partial<S> & { _handshake_receipts: string[] }> {
  const cap = opts.capability ?? DEFAULT_CAPABILITY;
  return async (state: S) => {
    const token = opts.handshake.delegate({
      sub: opts.handshake.kms.did,
      aud: opts.toolDid,
      capability: cap,
    });
    const ctx = opts.handshake.handshake({
      aud: opts.toolDid,
      capability: cap,
      delegationChain: [token],
    });

    const upstream = state._handshake_receipts ?? [];
    const patch = (await fn(state)) ?? {};

    const out = await opts.handshake.recordReceipt(ctx, {
      action: opts.action,
      result: "ok",
      resultPayload: { patch },
      resultSummary: { framework: "langgraph", node: opts.action },
      upstreamReceipts: upstream,
    });

    return {
      ...patch,
      _handshake_receipts: [...upstream, out.receiptId],
    } as Partial<S> & { _handshake_receipts: string[] };
  };
}
