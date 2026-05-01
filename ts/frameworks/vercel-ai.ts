// Vercel AI SDK wrapper — `wrapGenerateText({handshake, ...})`.
//
// Exposes a `wrappedGenerateText(opts) → {text, receiptId}` that mirrors the
// Vercel AI `generateText` contract on the call site but emits a Receipt
// for every invocation. MOCK by default.

import { Handshake } from "../client.js";
import { Capability } from "../models.js";

export interface VercelAiWrapOptions {
  handshake: Handshake;
  modelDid?: string;
  capability?: Capability;
  inner?: (opts: { prompt: string; model?: string }) => Promise<{ text: string }>;
}

export interface VercelAiCallOptions {
  prompt: string;
  model?: string;
  upstreamReceipts?: string[];
}

const DEFAULT_CAPABILITY = Capability.parse({ name: "ai.vercel.generate_text" });

export function wrapGenerateText(opts: VercelAiWrapOptions) {
  const hs = opts.handshake;
  const modelDid = opts.modelDid ?? "did:hsk:model.vercel.unspecified";
  const cap = opts.capability ?? DEFAULT_CAPABILITY;
  const inner = opts.inner ?? null;

  return async function wrapped(call: VercelAiCallOptions): Promise<{ text: string; receiptId: string; mock: boolean }> {
    const token = hs.delegate({ sub: hs.kms.did, aud: modelDid, capability: cap });
    const ctx = hs.handshake({ aud: modelDid, capability: cap, delegationChain: [token] });

    let text: string;
    let mock = false;
    if (inner === null) {
      text = `[handshake-mock vercel-ai] ${call.prompt.slice(0, 80)}`;
      mock = true;
    } else {
      const r = await inner({ prompt: call.prompt, model: call.model });
      text = r.text;
    }

    const out = await hs.recordReceipt(ctx, {
      action: "vercel_ai.generate_text",
      result: "ok",
      resultPayload: { prompt: call.prompt, text },
      resultSummary: { framework: "vercel_ai", model_did: modelDid, mock },
      upstreamReceipts: call.upstreamReceipts,
    });
    return { text, receiptId: out.receiptId, mock };
  };
}
