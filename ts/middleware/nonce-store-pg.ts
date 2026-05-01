/**
 * PostgreSQL-backed `NonceStore` (Phase 10 follow-up #10).
 *
 * Implements the `NonceStore` interface from `./express.ts` using a
 * single-statement upsert on a dedicated `handshake_nonces` table.
 *
 * Schema (created by Registry migration `0004_handshake_nonces.py`):
 *
 *     handshake_nonces (
 *         nonce       TEXT PRIMARY KEY,
 *         expires_at  TIMESTAMPTZ NOT NULL
 *     );
 *
 * # Why a single statement matters
 *
 * The naive sequence "SELECT then INSERT if not present" is racy across
 * processes — two concurrent workers can both observe a missing row and
 * both then INSERT, with one losing on the unique constraint and the
 * other succeeding. We use:
 *
 *     INSERT INTO handshake_nonces (nonce, expires_at) VALUES ($1, $2)
 *         ON CONFLICT (nonce) DO NOTHING
 *         RETURNING 1
 *
 * Returns 1 row if first sight, 0 rows if replay — atomic at the SQL
 * level, correct under any concurrency.
 *
 * # No `pg` dependency
 *
 * To keep this SDK zero-cost for users who don't need PG, we accept a
 * structural `PgQueryable` shape rather than depending on `pg`. Both
 * `pg.Pool` and `pg.Client` satisfy it; so do most other Postgres
 * drivers. Wire-up:
 *
 *     import { Pool } from "pg";
 *     import { PostgresNonceStore } from "@handshake/handshake/middleware/nonce-store-pg";
 *
 *     const nonceStore = new PostgresNonceStore({
 *       client: new Pool({ connectionString: process.env.DATABASE_URL }),
 *       ttlSeconds: 300,
 *     });
 *     app.use(handshakeMiddleware({ nonceStore, ... }));
 */
import type { NonceStore } from "./express.js";

/**
 * Minimal structural shape of a Postgres connection. Both `pg.Pool` and
 * `pg.Client` (and most alternatives) implement this. We only need to
 * `query()`; transactions are not required because the upsert is a
 * single statement.
 */
export interface PgQueryable {
  query(
    sql: string,
    params?: ReadonlyArray<unknown>,
  ): Promise<{ rows: ReadonlyArray<unknown> }>;
}

export interface PostgresNonceStoreOptions {
  /** A `pg.Pool`, `pg.Client`, or any other client matching `PgQueryable`. */
  client: PgQueryable;
  /**
   * How long each nonce is retained. Should match the verifier's
   * freshness window. Default 300 s (5 min).
   */
  ttlSeconds?: number;
  /**
   * Override the table name. Default `handshake_nonces` matches Registry
   * migration 0004. Validated against the same regex used elsewhere
   * for SQL identifier interpolation.
   */
  table?: string;
  /**
   * Probability (0.0–1.0) that a given call also runs an opportunistic
   * `DELETE WHERE expires_at < NOW()`. Default 0.01 → roughly one
   * prune per 100 inserts. Set to 0.0 to disable (e.g. when an
   * external cron handles pruning).
   */
  pruneProbability?: number;
}

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

export class PostgresNonceStore implements NonceStore {
  private readonly client: PgQueryable;
  private readonly ttlSeconds: number;
  private readonly table: string;
  private readonly pruneProbability: number;

  constructor(opts: PostgresNonceStoreOptions) {
    const table = opts.table ?? "handshake_nonces";
    if (!IDENT_RE.test(table)) {
      throw new Error(`table=${JSON.stringify(table)} is not a valid PostgreSQL identifier`);
    }
    const ttlSeconds = opts.ttlSeconds ?? 300;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new Error("ttlSeconds must be positive");
    }
    const pruneProbability = opts.pruneProbability ?? 0.01;
    if (!(pruneProbability >= 0.0 && pruneProbability <= 1.0)) {
      throw new Error("pruneProbability must be in [0.0, 1.0]");
    }
    this.client = opts.client;
    this.table = table;
    this.ttlSeconds = ttlSeconds;
    this.pruneProbability = pruneProbability;
  }

  /**
   * Returns `true` if `nonce` was already seen (replay), else records
   * it and returns `false`. Promise resolves once the upsert is
   * durable on the connection's WAL.
   */
  async checkAndRecord(nonce: string): Promise<boolean> {
    if (typeof nonce !== "string" || nonce.length === 0) {
      // Defensive: empty / non-string nonces are meaningless and
      // would let an attacker bypass replay detection. Surface as
      // a replay so the caller rejects the request.
      return true;
    }
    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1000);

    // table is regex-validated in the constructor; nonce + expiresAt
    // flow through bound parameters.
    const sql =
      `INSERT INTO ${this.table} (nonce, expires_at) VALUES ($1, $2) ` +
      `ON CONFLICT (nonce) DO NOTHING RETURNING 1`;

    const result = await this.client.query(sql, [nonce, expiresAt]);
    const replay = result.rows.length === 0;

    // Best-effort prune. Never let a transient DB error break replay
    // protection on the hot path.
    if (this.pruneProbability > 0 && Math.random() < this.pruneProbability) {
      try {
        await this.client.query(
          `DELETE FROM ${this.table} WHERE expires_at < NOW()`,
        );
      } catch {
        // swallow — pruning is best-effort
      }
    }

    return replay;
  }
}
