// SPDX-License-Identifier: MIT
// Zod schemas mirroring the v0.2.3 JSON Schemas.
//
// Each schema's runtime parse + serialize must reproduce the bytes the
// Rust/Go cores produce from the same raw JSON. A planned conformance step
// compares each schema's `zod-to-json-schema` output against the on-disk
// JSON Schema file — drift fails CI.

import { z } from "zod";

export const SignatureAlgorithm = z.enum([
  "EdDSA",
  "ML-DSA-65",
  "Hybrid-EdDSA-MLDSA65",
]);
export type SignatureAlgorithm = z.infer<typeof SignatureAlgorithm>;

export const HashAlgorithm = z.enum(["sha-256", "sha3-256"]);
export type HashAlgorithm = z.infer<typeof HashAlgorithm>;

export const HashValue = z
  .object({
    alg: HashAlgorithm,
    value: z.string(),
  })
  .strict();
export type HashValue = z.infer<typeof HashValue>;

export const Capability = z
  .object({
    name: z.string(),
    constraints: z.unknown().optional(),
    delegable: z.boolean().optional(),
  })
  .strict();
export type Capability = z.infer<typeof Capability>;

export const DelegationToken = z
  .object({
    version: z.string(),
    kind: z.literal("DelegationToken"),
    id: z.string(),
    iss: z.string(),
    sub: z.string(),
    aud: z.string(),
    iat: z.string(),
    nbf: z.string(),
    exp: z.string(),
    capabilities: z.array(Capability).min(1),
    sub_delegation_depth_remaining: z.number().int().nonnegative(),
    parent_delegation_id: z.string().optional(),
    alg: SignatureAlgorithm,
    signature: z.string().optional(),
  })
  .strict();
export type DelegationToken = z.infer<typeof DelegationToken>;

export const HandshakeRequest = z
  .object({
    version: z.string(),
    kind: z.literal("HandshakeRequest"),
    id: z.string(),
    iss: z.string(),
    aud: z.string(),
    iat: z.string(),
    nonce: z.string(),
    agent_attestation: z.unknown(),
    capability: Capability,
    delegation_chain: z.array(DelegationToken),
    alg: SignatureAlgorithm,
    signature: z.string().optional(),
  })
  .strict();
export type HandshakeRequest = z.infer<typeof HandshakeRequest>;

export const ReceiptResult = z.enum(["ok", "error", "partial"]);
export type ReceiptResult = z.infer<typeof ReceiptResult>;

export const Receipt = z
  .object({
    version: z.string(),
    kind: z.literal("Receipt"),
    id: z.string(),
    handshake_id: z.string(),
    iss: z.string(),
    sub: z.string(),
    action: z.string(),
    executed_at: z.string(),
    result: ReceiptResult,
    result_hash: HashValue,
    result_summary: z.unknown().optional(),
    upstream_receipts: z.array(z.string()).optional(),
    registry_anchor: z.unknown().optional(),
    alg: SignatureAlgorithm,
    signature: z.string().optional(),
  })
  .strict();
export type Receipt = z.infer<typeof Receipt>;
