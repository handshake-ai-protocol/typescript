// Signing-key management — `KeyManagementProvider` interface + backends.
//
// Mirrors `handshake.kms` in the Python SDK: a swappable signing-key Protocol
// so framework wrappers can hold a software key in dev and an HSM in prod
// behind the same interface. The signing surface is intentionally narrow
// (`sign(message)`, `publicKey()`) to keep HSM bindings minimal.
//
// Architecture: docs/decisions/0011-kms-in-sdk.md.

import { ed25519KeypairFromSeed, ed25519Sign } from "./index.js";

import { randomBytes } from "node:crypto";

export class KmsError extends Error {
  override name = "KmsError";
}

/** Algorithms a `KeyManagementProvider` may report. */
export type SignatureAlgorithm = "EdDSA" | "ML-DSA-65" | "Hybrid-EdDSA-MLDSA65";

/**
 * Holds a Handshake producer's private key and signs envelopes.
 *
 * Implementations MUST guarantee:
 *   * `publicKey()` returns the raw public key bytes (32 for Ed25519).
 *   * `sign(message)` produces a signature byte-for-byte verifiable under
 *     the corresponding public key by `ed25519Verify`.
 *   * Raw private key bytes never leave the provider.
 */
export interface KeyManagementProvider {
  readonly name: string;
  readonly did: string;
  algorithm(): SignatureAlgorithm;
  publicKey(): Buffer;
  sign(message: Buffer): Buffer;
}

/** In-process libsodium signer. Default for tests, dev, and CI. */
export class SoftwareKMS implements KeyManagementProvider {
  readonly name = "software";
  readonly did: string;
  private readonly _seed: Buffer;
  private readonly _public: Buffer;
  private readonly _algorithm: SignatureAlgorithm;

  private constructor(did: string, seed: Buffer, algorithm: SignatureAlgorithm) {
    if (algorithm !== "EdDSA") {
      throw new KmsError(
        `SoftwareKMS only supports EdDSA in Phase 4 (got ${algorithm})`,
      );
    }
    if (seed.length !== 32) {
      throw new KmsError(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
    }
    const kp = ed25519KeypairFromSeed(seed);
    this.did = did;
    this._seed = kp.seed;
    this._public = kp.publicKey;
    this._algorithm = algorithm;
  }

  static generate(opts: { did: string }): SoftwareKMS {
    return new SoftwareKMS(opts.did, randomBytes(32), "EdDSA");
  }

  static fromSeed(opts: { did: string; seed: Buffer }): SoftwareKMS {
    return new SoftwareKMS(opts.did, opts.seed, "EdDSA");
  }

  algorithm(): SignatureAlgorithm {
    return this._algorithm;
  }

  publicKey(): Buffer {
    return Buffer.from(this._public);
  }

  sign(message: Buffer): Buffer {
    return ed25519Sign(this._seed, message);
  }
}

/** AWS CloudHSM (PKCS#11) — STUB. See docs/decisions/0011-kms-in-sdk.md. */
export class CloudHSMPKCS11 implements KeyManagementProvider {
  readonly name = "aws-cloudhsm";
  readonly did: string;
  constructor(_opts: { did: string; slotId: number; keyLabel: string }) {
    this.did = _opts.did;
    throw new KmsError(
      "CloudHSMPKCS11 is a Phase 4 stub — wire a real PKCS#11 backend before constructing.",
    );
  }
  algorithm(): SignatureAlgorithm {
    throw new KmsError("stub");
  }
  publicKey(): Buffer {
    throw new KmsError("stub");
  }
  sign(_message: Buffer): Buffer {
    throw new KmsError("stub");
  }
}

/** Azure Key Vault — STUB. */
export class AzureKeyVaultHSM implements KeyManagementProvider {
  readonly name = "azure-keyvault-hsm";
  readonly did: string;
  constructor(_opts: { did: string; vaultUrl: string; keyName: string }) {
    this.did = _opts.did;
    throw new KmsError("AzureKeyVaultHSM is a Phase 4 stub.");
  }
  algorithm(): SignatureAlgorithm {
    throw new KmsError("stub");
  }
  publicKey(): Buffer {
    throw new KmsError("stub");
  }
  sign(_message: Buffer): Buffer {
    throw new KmsError("stub");
  }
}

/** GCP Cloud HSM — STUB. */
export class GCPCloudHSM implements KeyManagementProvider {
  readonly name = "gcp-cloud-hsm";
  readonly did: string;
  constructor(_opts: { did: string; keyName: string }) {
    this.did = _opts.did;
    throw new KmsError("GCPCloudHSM is a Phase 4 stub.");
  }
  algorithm(): SignatureAlgorithm {
    throw new KmsError("stub");
  }
  publicKey(): Buffer {
    throw new KmsError("stub");
  }
  sign(_message: Buffer): Buffer {
    throw new KmsError("stub");
  }
}
