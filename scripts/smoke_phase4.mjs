// End-to-end smoke for the TS SDK against a live Phase-3 Registry.
//
// Boots an admin tenant + producer DID, signs a HandshakeRequest via the
// SDK, and posts a Receipt for each framework wrapper (Anthropic mock,
// OpenAI Agents mock, Vercel AI mock). Asserts the receipts come back
// anchored. Used by `make phase4` and the architect review.

import { createHash, randomBytes } from "node:crypto";

import { Handshake, SoftwareKMS } from "../dist/index.js";
import { wrap as wrapAnthropic } from "../dist/frameworks/anthropic.js";
import { wrap as wrapOpenAIAgents } from "../dist/frameworks/openai-agents.js";
import { wrapGenerateText } from "../dist/frameworks/vercel-ai.js";
import { wrapNode } from "../dist/frameworks/langgraph.js";

const REGISTRY = process.env.HANDSHAKE_REGISTRY ?? "http://localhost:8080";
const REPL_ID = process.env.REPL_ID;
if (!REPL_ID) {
  console.error("REPL_ID is required to derive the admin token.");
  process.exit(2);
}
const adminToken = createHash("sha256").update(`handshake-admin::${REPL_ID}`).digest("hex");

async function adminPost(path, body) {
  const r = await fetch(`${REGISTRY}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify(body),
  });
  if (r.status >= 300) {
    throw new Error(`${path} → ${r.status} ${await r.text()}`);
  }
  return await r.json();
}

function b64u(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

const suffix = randomBytes(4).toString("hex");
const slug = `ts-phase4-${Date.now()}-${suffix}`;
await adminPost("/v1/admin/tenants", {
  slug,
  display_name: `TS Phase 4 smoke · ${suffix}`,
  region: "us-east",
  controller_did: `did:hsk:ts-phase4-controller-${suffix}`,
});

const seed = randomBytes(32);
const kms = SoftwareKMS.fromSeed({ did: `did:hsk:ts-phase4-${suffix}`, seed });
await adminPost("/v1/admin/dids", {
  tenant_slug: slug,
  did: kms.did,
  role: "service",
  did_document: { "@context": ["https://www.w3.org/ns/did/v1"], id: kms.did },
  primary_ed25519_pubkey_b64u: b64u(kms.publicKey()),
});

const hs = new Handshake({ registryUrl: REGISTRY, kms });

console.log("→ anthropic mock");
const ant = wrapAnthropic(null, { handshake: hs });
const antOut = await ant.messages.create({ model: "claude-mock", messages: [{ role: "user", content: "ping" }] });
console.log("  receipt", antOut.handshake_receipt_id);

console.log("→ openai-agents mock");
const oa = wrapOpenAIAgents({ handshake: hs });
const oaOut = await oa.run("mock prompt", { upstreamReceipts: [antOut.handshake_receipt_id] });
console.log("  receipt", oaOut.receiptId);

console.log("→ vercel-ai mock");
const va = wrapGenerateText({ handshake: hs });
const vaOut = await va({ prompt: "summarise", upstreamReceipts: [oaOut.receiptId] });
console.log("  receipt", vaOut.receiptId);

console.log("→ langgraph wrapNode");
const node = wrapNode(async (state) => ({ summary: `len=${state.input.length}` }), {
  handshake: hs,
  action: "lg.summarise",
  toolDid: "did:hsk:tool.lg.summariser",
});
const lg = await node({ input: "abc", _handshake_receipts: [vaOut.receiptId] });
const lgReceipt = lg._handshake_receipts.at(-1);
console.log("  receipt", lgReceipt);

console.log("→ awaiting anchors");
for (const id of [antOut.handshake_receipt_id, oaOut.receiptId, vaOut.receiptId, lgReceipt]) {
  await hs.waitForAnchor(id, { maxWaitMs: 15_000, pollMs: 400 });
  console.log("  anchored", id);
}

console.log("OK ts phase4 smoke green");
