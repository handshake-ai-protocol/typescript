// Handshake protocol — TypeScript SDK façade.
//
// Re-exports the NAPI-RS native primitives (built from src/lib.rs) and
// surfaces ergonomic helpers + the Zod schema-native models. The native
// addon is loaded from the package root (`../index.cjs` after build).
//
// Architecture: docs/decisions/0006-rust-core-authoritative.md

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// The NAPI-RS toolchain emits `index.cjs` at the package root with platform-
// specific .node sidecars. This is the canonical way to load it from an ESM
// TypeScript build.
const native = require("../index.cjs") as {
  SPEC_VERSION: string;
  canonicalize: (jsonText: string) => Buffer;
  sha256: (data: Buffer) => Buffer;
  sha256Hex: (data: Buffer) => string;
  ed25519KeypairFromSeed: (seed: Buffer) => { seed: Buffer; publicKey: Buffer };
  ed25519Sign: (seed: Buffer, message: Buffer) => Buffer;
  ed25519Verify: (publicKey: Buffer, signature: Buffer, message: Buffer) => boolean;
  mldsa65KeypairFromSeed: (seed: Buffer) => { privateKey: Buffer; publicKey: Buffer };
  mldsa65Sign: (seed: Buffer, message: Buffer) => Buffer;
  mldsa65Verify: (publicKey: Buffer, signature: Buffer, message: Buffer) => boolean;
};

export const SPEC_VERSION = native.SPEC_VERSION;

export const sha256 = native.sha256;
export const sha256Hex = native.sha256Hex;
export const ed25519KeypairFromSeed = native.ed25519KeypairFromSeed;
export const ed25519Sign = native.ed25519Sign;
export const ed25519Verify = native.ed25519Verify;
export const mldsa65KeypairFromSeed = native.mldsa65KeypairFromSeed;
export const mldsa65Sign = native.mldsa65Sign;
export const mldsa65Verify = native.mldsa65Verify;

/**
 * Return the RFC 8785 canonical UTF-8 byte representation of `value`.
 *
 * Always JSON-encodes `value` first (via `JSON.stringify`), then hands the
 * text to the Rust JCS implementation, which enforces the RFC's key
 * ordering, IEEE-754 number form, and string escaping rules. To canonicalize
 * raw JSON text instead, decode it with `JSON.parse` first and pass the
 * result here.
 */
export function canonicalize(value: unknown): Buffer {
  const text = JSON.stringify(value);
  if (typeof text !== "string") {
    // Covers `undefined` and circular structures — `JSON.stringify` returns
    // `undefined` for the former and throws for the latter.
    throw new TypeError("canonicalize: value is not JSON-serializable");
  }
  return native.canonicalize(text);
}

export * as models from "./models.js";
export * as verify from "./verify.js";
export { verifyHandshakeRequest, intersectCapabilities } from "./verify.js";
export type { VerifyResult, VerifyOptions } from "./verify.js";
