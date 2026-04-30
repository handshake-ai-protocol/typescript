//! NAPI-RS FFI shim — Node.js bindings for the canonical Rust Handshake core.
//!
//! Every cryptographic function here forwards directly into the `handshake`
//! crate (sibling path-dep on `packages/handshake-rs`). Node callers cannot
//! observe a different result than Rust callers, by construction; that is the
//! whole point of the FFI architecture (ADR-0006).
//!
//! `napi build` (invoked by `pnpm run build:native`) emits:
//!   * `index.cjs` + `index.d.ts` at the package root (the loader),
//!   * `handshake.<platform>-<arch>-<libc>.node` (the native addon).
//! The TypeScript façade in `ts/index.ts` does `createRequire("../index.cjs")`.

#![deny(clippy::all)]

use handshake::{hash, jcs, mldsa, sign};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Spec version this build implements (mirrors `handshake::SPEC_VERSION`).
#[napi]
pub const SPEC_VERSION: &str = handshake::SPEC_VERSION;

/// JCS-canonicalize a JSON document supplied as a UTF-8 string.
///
/// We require pre-serialized JSON text rather than `napi::Unknown` so the FFI
/// surface is unambiguous and the Node caller sees the same behavior the
/// Python caller does. The TypeScript façade calls `JSON.stringify` first.
#[napi]
pub fn canonicalize(json_text: String) -> Result<Buffer> {
    let value: serde_json::Value = serde_json::from_str(&json_text)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid JSON: {e}")))?;
    let bytes = jcs::canonicalize(&value)
        .map_err(|e| Error::new(Status::GenericFailure, format!("canonicalize: {e}")))?;
    Ok(bytes.into())
}

/// Raw 32-byte SHA-256 digest of `data`.
#[napi]
pub fn sha256(data: Buffer) -> Buffer {
    hash::sha256(&data).to_vec().into()
}

/// Lowercase-hex SHA-256 digest of `data`.
#[napi]
pub fn sha256_hex(data: Buffer) -> String {
    hash::sha256_hex(&data)
}

fn seed_array(seed: &Buffer) -> Result<[u8; 32]> {
    let bytes: &[u8] = seed.as_ref();
    bytes.try_into().map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("expected 32-byte seed, got {} bytes", bytes.len()),
        )
    })
}

/// Plain object returned by `ed25519KeypairFromSeed`. NAPI-RS materializes
/// this as `{ seed: Buffer, publicKey: Buffer }` on the JS side.
#[napi(object)]
pub struct Ed25519Keypair {
    pub seed: Buffer,
    pub public_key: Buffer,
}

/// Ed25519 keypair from a 32-byte seed (RFC 8032 §5.1.5). The seed is
/// round-tripped so callers don't need to hold the original buffer.
#[napi]
pub fn ed25519_keypair_from_seed(seed: Buffer) -> Result<Ed25519Keypair> {
    let seed_arr = seed_array(&seed)?;
    let kp = sign::Keypair::from_seed(&seed_arr);
    Ok(Ed25519Keypair {
        seed: kp.seed().to_vec().into(),
        public_key: kp.public_key().to_vec().into(),
    })
}

/// Ed25519 sign — returns the raw 64-byte signature.
#[napi]
pub fn ed25519_sign(seed: Buffer, message: Buffer) -> Result<Buffer> {
    let seed_arr = seed_array(&seed)?;
    let kp = sign::Keypair::from_seed(&seed_arr);
    Ok(kp.sign(&message).to_vec().into())
}

/// Ed25519 verify. Returns `true` on a valid signature, `false` otherwise.
/// Wrong-length keys / signatures throw (caller bug, not forgery).
#[napi]
pub fn ed25519_verify(public_key: Buffer, signature: Buffer, message: Buffer) -> Result<bool> {
    if public_key.len() != 32 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("expected 32-byte public key, got {}", public_key.len()),
        ));
    }
    if signature.len() != 64 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("expected 64-byte signature, got {}", signature.len()),
        ));
    }
    Ok(sign::verify(&public_key, &signature, &message).is_ok())
}

/// Plain object returned by `mldsa65KeypairFromSeed`. NAPI-RS materializes
/// this as `{ privateKey: Buffer, publicKey: Buffer }` on the JS side.
#[napi(object)]
pub struct MlDsa65Keypair {
    pub private_key: Buffer,
    pub public_key: Buffer,
}

/// ML-DSA-65 (FIPS 204) keypair from a 32-byte seed.
#[napi]
pub fn mldsa65_keypair_from_seed(seed: Buffer) -> Result<MlDsa65Keypair> {
    let seed_arr = seed_array(&seed)?;
    let kp = mldsa::Keypair::from_seed(&seed_arr);
    Ok(MlDsa65Keypair {
        private_key: kp.private_key().into(),
        public_key: kp.public_key().into(),
    })
}

/// ML-DSA-65 deterministic sign — returns the raw 3309-byte signature.
///
/// We accept the seed (not the pre-derived private key) so the FFI surface is
/// uniform with the Ed25519 helpers and matches the Python and Go runners.
/// Determinism is enforced by the FIPS 204 §5.5 deterministic variant inside
/// `Keypair::sign`.
#[napi]
pub fn mldsa65_sign(seed: Buffer, message: Buffer) -> Result<Buffer> {
    let seed_arr = seed_array(&seed)?;
    let kp = mldsa::Keypair::from_seed(&seed_arr);
    Ok(kp.sign(&message).into())
}

/// ML-DSA-65 verify. Returns `true` on a valid signature, `false` otherwise.
/// Wrong-length keys / signatures throw (caller bug, not forgery).
#[napi]
pub fn mldsa65_verify(public_key: Buffer, signature: Buffer, message: Buffer) -> Result<bool> {
    if public_key.len() != mldsa::PUBLIC_KEY_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "expected {}-byte ML-DSA-65 public key, got {}",
                mldsa::PUBLIC_KEY_LEN,
                public_key.len()
            ),
        ));
    }
    if signature.len() != mldsa::SIGNATURE_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "expected {}-byte ML-DSA-65 signature, got {}",
                mldsa::SIGNATURE_LEN,
                signature.len()
            ),
        ));
    }
    match mldsa::verify(&public_key, &signature, &message) {
        Ok(()) => Ok(true),
        Err(handshake::Error::SignatureInvalid(_)) => Ok(false),
        Err(other) => Err(Error::new(Status::GenericFailure, other.to_string())),
    }
}
