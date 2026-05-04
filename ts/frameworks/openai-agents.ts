// SPDX-License-Identifier: MIT
// OpenAI Agents SDK wrapper.
//
// `wrap({handshake, modelDid})` returns a runner with `.run(prompt)` that
// brackets each call with handshake + receipt. MOCK by default.

import { Handshake } from "../client.js";
import { Capability } from "../models.js";

export interface OpenAIAgentsWrapOptions {
  handshake: Handshake;
  modelDid?: string;
  capability?: Capability;
  innerRun?: (prompt: string) => Promise<{ text: string }>;
}

export interface OpenAIAgentsRunOutput {
  text: string;
  receiptId: string;
}

const DEFAULT_CAPABILITY = Capability.parse({ name: "ai.agents.run" });

export class OpenAIAgentsHandshakeRunner {
  readonly isMock: boolean;
  private readonly hs: Handshake;
  private readonly modelDid: string;
  private readonly capability: Capability;
  private readonly innerRun: ((prompt: string) => Promise<{ text: string }>) | null;

  constructor(opts: OpenAIAgentsWrapOptions) {
    this.hs = opts.handshake;
    this.modelDid = opts.modelDid ?? "did:hsk:model.openai.gpt-4o";
    this.capability = opts.capability ?? DEFAULT_CAPABILITY;
    this.innerRun = opts.innerRun ?? null;
    this.isMock = this.innerRun === null;
  }

  async run(prompt: string, opts?: { upstreamReceipts?: string[] }): Promise<OpenAIAgentsRunOutput> {
    const token = this.hs.delegate({
      sub: this.hs.kms.did,
      aud: this.modelDid,
      capability: this.capability,
    });
    const ctx = this.hs.handshake({
      aud: this.modelDid,
      capability: this.capability,
      delegationChain: [token],
    });

    let text: string;
    if (this.innerRun === null) {
      text = `[handshake-mock openai-agents] result for: ${prompt.slice(0, 60)}`;
    } else {
      const r = await this.innerRun(prompt);
      text = r.text;
    }

    const out = await this.hs.recordReceipt(ctx, {
      action: "openai_agents.run",
      result: "ok",
      resultPayload: { prompt, text },
      resultSummary: { framework: "openai_agents", model_did: this.modelDid, mock: this.isMock },
      upstreamReceipts: opts?.upstreamReceipts,
    });
    return { text, receiptId: out.receiptId };
  }
}

export function wrap(opts: OpenAIAgentsWrapOptions): OpenAIAgentsHandshakeRunner {
  return new OpenAIAgentsHandshakeRunner(opts);
}
