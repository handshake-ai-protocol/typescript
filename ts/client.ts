// SPDX-License-Identifier: MIT
// High-level Handshake client — `Handshake`, `HandshakeContext`.
//
// TypeScript mirror of `handshake.client.Handshake` (Python). One per
// producer DID per process; framework wrappers (`./frameworks/*`) consume it
// behind their `wrap()` entry points. The signing path is byte-identical to
// the Python SDK because both lean on the canonical Rust core for JCS +
// Ed25519.

import { canonicalize, SPEC_VERSION } from "./index.js";
import type { KeyManagementProvider } from "./kms.js";
import {
  Capability,
  DelegationToken,
  HandshakeRequest,
  HashAlgorithm,
  HashValue,
  Receipt,
  ReceiptResult,
  SignatureAlgorithm,
} from "./models.js";

import { createHash, randomBytes } from "node:crypto";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function ulid(prefix: string): string {
  const raw = randomBytes(16);
  let n = 0n;
  for (const b of raw) {
    n = (n << 8n) | BigInt(b);
  }
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 0x1fn)] + out;
    n >>= 5n;
  }
  return `${prefix}_${out}`;
}

function nowIso(offsetSeconds = 0): string {
  const d = new Date(Date.now() + offsetSeconds * 1000);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function b64u(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function hashPayload(payload: unknown): HashValue {
  const canon = canonicalize(payload ?? {});
  const digest = createHash("sha256").update(canon).digest("hex");
  return { alg: HashAlgorithm.parse("sha-256"), value: digest };
}

/** Carries a signed HandshakeRequest plus DAG provenance. */
export interface HandshakeContext {
  handshakeId: string;
  request: Record<string, unknown>;
  iss: string;
  sub: string;
  capability: Capability;
  parentReceiptIds: string[];
  metadata: Record<string, unknown>;
  addParent(receiptId: string): void;
}

export class RegistryError extends Error {
  override name = "RegistryError";
}

export interface HandshakeOptions {
  registryUrl?: string;
  kms: KeyManagementProvider;
  registryTimeoutMs?: number;
  offline?: boolean;
  /**
   * Bearer token for receipt-read endpoints (locked down by Registry
   * commit 12cb4f0 "close unauthenticated receipt reads"). Required when
   * calling fetchReceipt / waitForAnchor against a Registry that
   * enforces auth on GET /v1/receipts/{id}; harmless when omitted
   * against a Registry with anonymous reads enabled. Mirrors
   * packages/handshake-py/python/handshake/client.py:Handshake.admin_token.
   */
  adminToken?: string;
}

export interface DelegateOptions {
  sub: string;
  aud: string;
  capability: Capability | { name: string; constraints?: unknown; delegable?: boolean };
  durationSeconds?: number;
  subDelegationDepthRemaining?: number;
  parentDelegationId?: string;
}

export interface HandshakeStartOptions {
  aud: string;
  capability: Capability | { name: string; constraints?: unknown; delegable?: boolean };
  delegationChain: DelegationToken[];
  nonce?: string;
  agentAttestation?: Record<string, unknown>;
}

export interface RecordReceiptOptions {
  action: string;
  result?: "ok" | "error" | "partial";
  resultPayload?: unknown;
  upstreamReceipts?: string[];
  resultSummary?: Record<string, unknown>;
}

export interface RecordReceiptOutcome {
  receiptId: string;
  envelope: Record<string, unknown>;
  leafHash?: string;
  anchor?: { status: string };
}

export class Handshake {
  readonly registryUrl: string;
  readonly kms: KeyManagementProvider;
  readonly registryTimeoutMs: number;
  readonly adminToken?: string;
  offline: boolean;

  constructor(opts: HandshakeOptions) {
    this.registryUrl = (opts.registryUrl ?? "http://localhost:8080").replace(/\/$/, "");
    this.kms = opts.kms;
    this.registryTimeoutMs = opts.registryTimeoutMs ?? 10_000;
    this.offline = opts.offline ?? false;
    this.adminToken = opts.adminToken;
  }

  delegate(opts: DelegateOptions): DelegationToken {
    const cap = Capability.parse(opts.capability);
    const now = nowIso();
    const exp = nowIso(opts.durationSeconds ?? 3600);
    const token: DelegationToken = {
      version: SPEC_VERSION,
      kind: "DelegationToken",
      id: ulid("dt"),
      iss: this.kms.did,
      sub: opts.sub,
      aud: opts.aud,
      iat: now,
      nbf: now,
      exp,
      capabilities: [cap],
      sub_delegation_depth_remaining: opts.subDelegationDepthRemaining ?? 0,
      ...(opts.parentDelegationId ? { parent_delegation_id: opts.parentDelegationId } : {}),
      alg: SignatureAlgorithm.parse(this.kms.algorithm()),
    };
    this.signEnvelope(token);
    return token;
  }

  handshake(opts: HandshakeStartOptions): HandshakeContext {
    const cap = Capability.parse(opts.capability);
    const request: HandshakeRequest = {
      version: SPEC_VERSION,
      kind: "HandshakeRequest",
      id: ulid("hs"),
      iss: this.kms.did,
      aud: opts.aud,
      iat: nowIso(),
      nonce: opts.nonce ?? b64u(randomBytes(24)),
      agent_attestation: opts.agentAttestation ?? { runtime: "handshake-ts", version: SPEC_VERSION },
      capability: cap,
      delegation_chain: opts.delegationChain,
      alg: SignatureAlgorithm.parse(this.kms.algorithm()),
    };
    this.signEnvelope(request);

    const parentIds: string[] = [];
    return {
      handshakeId: request.id,
      request: request as unknown as Record<string, unknown>,
      iss: this.kms.did,
      sub: opts.aud,
      capability: cap,
      parentReceiptIds: parentIds,
      metadata: {},
      addParent(receiptId: string) {
        if (receiptId && !parentIds.includes(receiptId)) {
          parentIds.push(receiptId);
        }
      },
    };
  }

  async recordReceipt(
    ctx: HandshakeContext,
    opts: RecordReceiptOptions,
  ): Promise<RecordReceiptOutcome> {
    const merged: string[] = [...ctx.parentReceiptIds];
    for (const r of opts.upstreamReceipts ?? []) {
      if (!merged.includes(r)) merged.push(r);
    }

    const receipt: Receipt = {
      version: SPEC_VERSION,
      kind: "Receipt",
      id: ulid("rc"),
      handshake_id: ctx.handshakeId,
      iss: this.kms.did,
      sub: ctx.sub,
      action: opts.action,
      executed_at: nowIso(),
      result: ReceiptResult.parse(opts.result ?? "ok"),
      result_hash: hashPayload(opts.resultPayload),
      ...(opts.resultSummary ? { result_summary: opts.resultSummary } : {}),
      ...(merged.length ? { upstream_receipts: merged } : {}),
      alg: SignatureAlgorithm.parse(this.kms.algorithm()),
    };
    this.signEnvelope(receipt);

    const envelope = stripUndefined(receipt);

    if (this.offline) {
      return { receiptId: receipt.id, envelope };
    }

    const resp = await this.fetchJson("POST", "/v1/receipts", envelope);
    if (resp.status !== 202) {
      throw new RegistryError(
        `Registry rejected receipt ${receipt.id}: HTTP ${resp.status} ${JSON.stringify(resp.body)}`,
      );
    }
    return {
      receiptId: receipt.id,
      envelope,
      leafHash: typeof resp.body["leaf_hash"] === "string" ? (resp.body["leaf_hash"] as string) : undefined,
    };
  }

  async fetchReceipt(receiptId: string): Promise<Record<string, unknown>> {
    const resp = await this.fetchJson("GET", `/v1/receipts/${receiptId}`);
    if (resp.status !== 200) {
      throw new RegistryError(`GET ${receiptId} failed: HTTP ${resp.status} ${JSON.stringify(resp.body)}`);
    }
    return resp.body;
  }

  async waitForAnchor(
    receiptId: string,
    opts: { maxWaitMs?: number; pollMs?: number } = {},
  ): Promise<Record<string, unknown>> {
    const maxMs = opts.maxWaitMs ?? 10_000;
    const pollMs = opts.pollMs ?? 500;
    const deadline = Date.now() + maxMs;
    let last: Record<string, unknown> = {};
    while (Date.now() < deadline) {
      last = await this.fetchReceipt(receiptId);
      const anchor = (last["anchor"] ?? {}) as Record<string, unknown>;
      if (anchor["status"] === "anchored") return last;
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new RegistryError(`receipt ${receiptId} not anchored within ${maxMs}ms`);
  }

  // ----- internals --------------------------------------------------------
  private signEnvelope(envelope: { signature?: string | null }): void {
    const stripped = { ...(envelope as Record<string, unknown>) };
    delete stripped["signature"];
    // exclude_none: drop keys whose value is undefined OR null so the canonical
    // form matches the Python SDK byte-for-byte.
    const cleaned = stripUndefined(stripped);
    const message = canonicalize(cleaned);
    const sig = this.kms.sign(message);
    envelope.signature = b64u(sig);
  }

  private async fetchJson(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.registryTimeoutMs);
    try {
      const headers: Record<string, string> = {};
      if (body !== undefined) headers["content-type"] = "application/json";
      // Mirror packages/handshake-py/python/handshake/client.py:_http_get_json
      // bearer plumbing — Registry locked down GET /v1/receipts/{id} in
      // commit 12cb4f0 ("close unauthenticated receipt reads"), so an
      // adminToken-equipped client must send Authorization: Bearer.
      if (this.adminToken) headers["authorization"] = `Bearer ${this.adminToken}`;
      const resp = await fetch(`${this.registryUrl}${path}`, {
        method,
        signal: controller.signal,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await resp.text();
      let parsed: Record<string, unknown> = {};
      if (text) {
        try {
          parsed = JSON.parse(text) as Record<string, unknown>;
        } catch {
          parsed = { raw: text };
        }
      }
      return { status: resp.status, body: parsed };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Recursively drop entries whose value is `undefined` or `null`. */
function stripUndefined<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((v) => stripUndefined(v)) as unknown as T;
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === undefined || v === null) continue;
      out[k] = stripUndefined(v);
    }
    return out as unknown as T;
  }
  return value;
}
