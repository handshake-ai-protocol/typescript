// SPDX-License-Identifier: MIT
// Anthropic SDK wrapper — `wrap(client)` for `@anthropic-ai/sdk`.
//
// Drop-in usage:
//
//   import { Handshake } from "@handshake/handshake";
//   import { wrap } from "@handshake/handshake/frameworks/anthropic";
//   const hs = new Handshake({ kms });
//   const client = wrap(null /* MOCK */, { handshake: hs, modelDid: "did:hsk:claude" });
//   const msg = await client.messages.create({ model: "...", messages: [...] });
//
// MOCK fallback returns a deterministic stub so demos run without an API key.

import { Handshake, type HandshakeContext } from "../client.js";
import { Capability } from "../models.js";

export interface AnthropicWrapOptions {
  handshake: Handshake;
  modelDid?: string;
  capability?: Capability;
}

export interface AnthropicMessageInput {
  model: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens?: number;
  upstream_receipts?: string[];
  [key: string]: unknown;
}

export interface AnthropicMessageOutput {
  id: string;
  model: string;
  role: "assistant";
  stop_reason: string;
  content: Array<{ type: "text"; text: string }>;
  usage: { input_tokens: number; output_tokens: number };
  handshake_receipt_id: string;
}

interface AnthropicMessagesNamespace {
  create(input: AnthropicMessageInput): Promise<{
    id?: string;
    model?: string;
    content: Array<{ type: string; text: string }>;
  }>;
}

interface AnthropicLikeClient {
  messages: AnthropicMessagesNamespace;
}

const DEFAULT_CAPABILITY = Capability.parse({ name: "ai.completions.create" });

export class AnthropicHandshakeClient {
  readonly handshake: Handshake;
  readonly modelDid: string;
  readonly capability: Capability;
  readonly isMock: boolean;
  private readonly inner: AnthropicLikeClient | null;

  constructor(inner: AnthropicLikeClient | null, opts: AnthropicWrapOptions) {
    this.handshake = opts.handshake;
    this.modelDid = opts.modelDid ?? "did:hsk:model.anthropic.claude";
    this.capability = opts.capability ?? DEFAULT_CAPABILITY;
    this.inner = inner;
    this.isMock = inner === null;
  }

  readonly messages = {
    create: async (input: AnthropicMessageInput): Promise<AnthropicMessageOutput> => {
      const token = this.handshake.delegate({
        sub: this.handshake.kms.did,
        aud: this.modelDid,
        capability: this.capability,
      });
      const ctx: HandshakeContext = this.handshake.handshake({
        aud: this.modelDid,
        capability: this.capability,
        delegationChain: [token],
      });

      let response: AnthropicMessageOutput;
      if (this.inner === null) {
        const userPrompt =
          input.messages.find((m) => m.role === "user")?.content ?? "";
        response = {
          id: "msg_mock_handshake",
          model: input.model,
          role: "assistant",
          stop_reason: "end_turn",
          content: [{ type: "text", text: `[handshake-mock claude] echo: ${userPrompt}` }],
          usage: { input_tokens: 7, output_tokens: 11 },
          handshake_receipt_id: "",
        };
      } else {
        const real = await this.inner.messages.create(input);
        const text = real.content[0]?.text ?? "";
        response = {
          id: real.id ?? "msg_unknown",
          model: real.model ?? input.model,
          role: "assistant",
          stop_reason: "end_turn",
          content: [{ type: "text", text }],
          usage: { input_tokens: 0, output_tokens: 0 },
          handshake_receipt_id: "",
        };
      }

      const out = await this.handshake.recordReceipt(ctx, {
        action: "anthropic.messages.create",
        result: "ok",
        resultPayload: { model: input.model, text: response.content[0]?.text },
        resultSummary: { framework: "anthropic", model: input.model, mock: this.isMock },
        upstreamReceipts: input.upstream_receipts,
      });
      response.handshake_receipt_id = out.receiptId;
      return response;
    },
  };
}

export function wrap(
  client: AnthropicLikeClient | null,
  opts: AnthropicWrapOptions,
): AnthropicHandshakeClient {
  return new AnthropicHandshakeClient(client, opts);
}
