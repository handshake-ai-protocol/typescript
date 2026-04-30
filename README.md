# @handshake/handshake (TypeScript)

TypeScript SDK for the Handshake protocol. **Thin NAPI-RS wrapper** over the
canonical Rust core (`packages/handshake-rs`). The cryptographic surface
delegates byte-for-byte to Rust, so this SDK cannot drift from the reference
implementation.

## Build

```bash
pnpm install
pnpm --filter @handshake/handshake run build
```

`build` runs two steps:

1. `napi build` compiles the Rust `cdylib` from `src/lib.rs` into a platform-
   specific `.node` addon plus a `index.cjs` loader and `index.d.ts` types.
2. `tsc` compiles the TypeScript façade in `ts/` to `dist/`, re-exporting the
   native primitives and surfacing the Zod schema-native models.

## Use

```ts
import { canonicalize, sha256Hex, models } from "@handshake/handshake";

canonicalize({ b: 2, a: 1 });       // <Buffer 7b 22 61 22 ...> ('{"a":1,"b":2}')
sha256Hex(Buffer.from("hello"));    // '2cf24dba...'

const dt = models.DelegationToken.parse({...});
```

## Architecture

See `docs/decisions/0006-rust-core-authoritative.md` for why TypeScript ships as
an FFI shim rather than a parallel pure-TypeScript implementation. Conformance
against the Rust+Go cores is enforced by `tests/conformance/` — every
primitive exposed here is byte-tested for equality with the other cores.
