// Check the built WebAssembly itself, since `cargo test` runs the native build.
//
//   node prover/smoke.mjs <veilproof_prover.wasm> <keys-dir> <expected-vk-sha256>
//
// The commitment vector and the key digest are what tie this module to the CLI
// and to the circuit registered on-chain. A proof that verifies on testnet is
// checked separately, by scripts/e2e-testnet.mjs in veilproof-registry.

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const [wasmPath, keysDir, expectedDigest] = process.argv.slice(2);
assert(expectedDigest, "usage: smoke.mjs <prover.wasm> <keys-dir> <expected-vk-sha256>");

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const vp = instance.exports;

function put(data) {
  const ptr = vp.vp_alloc(data.length);
  new Uint8Array(vp.memory.buffer, ptr, data.length).set(data);
  return ptr;
}

function call(request) {
  const input = Buffer.from(JSON.stringify(request));
  vp.vp_call(put(input), input.length);
  const output = new Uint8Array(vp.memory.buffer, vp.vp_result_ptr(), vp.vp_result_len());
  return JSON.parse(Buffer.from(output).toString());
}

const SECRET_7 = "07".padStart(64, "0");
// `veilproof-commit` prints this for the same secret.
const COMMITMENT_7 = "2638fc9895bccfff80310d2912ac6763a6eaac711baea3b98a0bb366776c3741";
const HOLDER = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";
const SEED = "01".repeat(32);

assert.equal(call({ op: "commitment", secret: SECRET_7 }).commitment, COMMITMENT_7);
assert.match(call({ op: "prove", leaves: [], secret: SECRET_7, holder: HOLDER, seed: SEED }).error, /keys/);

const pk = readFileSync(join(keysDir, "pk.bin"));
const vk = readFileSync(join(keysDir, "vk.bin"));
assert.equal(vp.vp_load_keys(put(pk), pk.length, put(vk), vk.length), 1, "keys rejected");
assert.equal(call({ op: "vk_digest" }).digest, expectedDigest);

const { root } = call({ op: "root", leaves: [COMMITMENT_7] });
const started = performance.now();
const proved = call({
  op: "prove",
  leaves: [COMMITMENT_7],
  secret: SECRET_7,
  holder: HOLDER,
  seed: SEED,
});
assert.equal(proved.error, undefined);
assert.equal(proved.root, root);
assert.equal(proved.proof.a.length, 128);
assert.equal(proved.proof.b.length, 256);
assert.equal(proved.proof.c.length, 128);

// A secret outside the tree must not produce anything.
const outsider = call({
  op: "prove",
  leaves: [COMMITMENT_7],
  secret: "08".padStart(64, "0"),
  holder: HOLDER,
  seed: SEED,
});
assert.match(outsider.error, /not in the tree/);

console.log(`ok: proved in ${Math.round(performance.now() - started)} ms`);
