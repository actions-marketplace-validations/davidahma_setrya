import assert from "node:assert/strict";
import {readFile, readdir} from "node:fs/promises";
import {basename, join} from "node:path";
import {parseArgs} from "node:util";
import vm from "node:vm";
import {webcrypto} from "node:crypto";

const {positionals, values} = parseArgs({
  allowPositionals: true, options: {vectors: {type: "string"}, signed: {type: "string"}, root: {type: "string"}}
});
const [verifier, output] = positionals;
assert.equal(positionals.length, 2, "Pass the rendered HTML and detached assessment fixture directory.");
const html = await readFile(verifier, "utf8");
const elements = new Map();
const elementsFor = id => {
  if (!elements.has(id)) elements.set(id, {handlers: {}, addEventListener(event, handler) {
    this.handlers[event] = handler;
  }});
  return elements.get(id);
};
const scope = vm.createContext({
  TextDecoder, TextEncoder, Uint8Array, atob, crypto: webcrypto, performance, console,
  Blob, DecompressionStream, Response, URL, setTimeout, clearTimeout,
  document: {getElementById: elementsFor},
});
for (const [, tags, content] of html.matchAll(/<script([^>]*)>([\s\S]+?)<\/script>/g)) {
  const id = /\bid="([^"]+)"/.exec(tags)?.[1];
  if (id) elementsFor(id).textContent = content;
  else vm.runInContext(content, scope);
}

const simulatedFile = (name, bytes) => ({name, size: bytes.length, arrayBuffer: async () => bytes});
const file = async path => simulatedFile(basename(path), await readFile(path));
const filesAt = async directory => Promise.all((await readdir(directory)).map(name => file(join(directory, name))));
const adjust = (files, name, map) => Promise.all(files.map(async input => input.name === name
  ? simulatedFile(name, await map(await input.arrayBuffer())) : input));
const key = await file(join(output, "synthetic-issuer.pub"));
const detached = [["assessment", "## support"], ["exchange", "PASS · OPEN_ITEMS"]];
if ((await readdir(output)).includes("approved")) detached.push(["approved", "## support"]);

for (const [folder, expected] of detached) {
  const files = await filesAt(join(output, folder));
  assert.ok((await scope.verifyBundle(files, key)).detail.includes(expected));
  const filename = folder === "exchange" ? "erasure-evidence.json" : "summary.md";
  const changed = await adjust(files, filename, () => Buffer.from("changed"));
  await assert.rejects(scope.verifyBundle(changed, key), {code: "EVIDENCE_DIGEST_MISMATCH"});
}

if (values.vectors) {
  const matrix = JSON.parse(await readFile(join(values.vectors, "cases.json"), "utf8"));
  for (const test of matrix) {
    const trust = await file(join(values.vectors, test.wrongKey ? "wrong.pub" : "issuer.pub"));
    const files = await filesAt(join(values.vectors, test.name));
    const pins = {ticket: test.ticket, frame: test.frame, commit: test.appCommit,
      deployment: test.deployment && simulatedFile("deploy.json", Buffer.from(JSON.stringify(test.deployment)))};
    if (test.code) {
      await assert.rejects(scope.verifyBundle(files, trust, pins), {code: test.code}, test.name);
    } else {
      const result = await scope.verifyBundle(files, trust, pins);
      assert.ok(result.detail.includes("Issuer's result: " + test.verdict), test.name);
      assert.equal(result.checks["Verdict replayed"], "not checked", test.name);
    }
  }
  assert.throws(() => scope.parseJSON('{"case":1,"\\u0063ase"' + " ".repeat(1000) + ":2}", "INVALID_MANIFEST"),
    {code: "DUPLICATE_JSON_KEY"});
  console.log("Browser and CLI exchange checks matched " + matrix.length + " fixture outcomes within their advertised scope.");
}

if (values.signed || values.root) {
  assert.ok(values.signed && values.root, "Pass both the signed exchange directory and independently provisioned root.");
  const trust = await file(values.root);
  const policy = {kind: "sigstore-bundle", trust,
    identity: "https://github.com/davidahma/setrya/.github/workflows/erasure.yml@refs/heads/main",
    issuer: "https://token.actions.githubusercontent.com"};
  const expected = {
    passed: "PASS · READY_FOR_REVIEW", residual: "FAIL · RESIDUAL_FOUND",
    unavailable: "NOT TESTED · OPEN_ITEMS", "open-items": "PASS · OPEN_ITEMS"
  };
  const independent = JSON.parse(await readFile(join(values.signed, "ticket-pins.json"), "utf8"));
  for (const [lane, verdict] of Object.entries(expected)) {
    const files = await filesAt(join(values.signed, lane));
    const record = independent[lane];
    const result = await scope.verifyBundle(files, undefined, {policy, ticket: record?.ticket_id, frame: record?.frame_sha256});
    assert.ok(result.detail.includes("Issuer's result: " + verdict), lane);
    assert.equal(result.checks["Signer and signature"], "passed", lane);
    assert.equal(result.checks["Verdict replayed"], "not checked", lane);
  }
  const signed = await filesAt(join(values.signed, "passed"));
  const wrongRoot = new File([JSON.stringify({...JSON.parse(await readFile(values.root, "utf8")),
    certificateAuthorities: []})], "wrong-root.json");
  await assert.rejects(scope.verifyBundle(signed, undefined, {policy: {...policy, trust: wrongRoot}}),
    {code: "WRONG_SIGNER"});
  await assert.rejects(scope.verifyBundle(signed, undefined, {policy: {...policy, issuer: "https://wrong.invalid"}}),
    {code: "WRONG_SIGNER"});
  await assert.rejects(scope.verifyBundle(signed, undefined, {policy: {...policy, identity: policy.identity + "-wrong"}}),
    {code: "WRONG_SIGNER"});
  const badLog = await adjust(signed, "exchange.sig", bytes => {
    const bundle = JSON.parse(bytes);
    delete bundle.verificationMaterial.tlogEntries[0].inclusionProof;
    return Buffer.from(JSON.stringify(bundle));
  });
  await assert.rejects(scope.verifyBundle(badLog, undefined, {policy}), {code: "WRONG_SIGNER"});
  const changed = await adjust(signed, "exchange.json", bytes => Buffer.concat([bytes, Buffer.from("\n")]));
  await assert.rejects(scope.verifyBundle(changed, undefined, {policy}), {code: "WRONG_SIGNER"});
  console.log("Checked four public keyless exchanges with offline signer and log proof verification.");
}

for (const id of ["bundle", "key", "policy", "ticket", "frame", "deployment", "commit", "identity", "issuer", "trust"]) {
  elementsFor("result").textContent = "Verified";
  elementsFor("detail").textContent = "Old result";
  elementsFor("checks").textContent = "Previous checks";
  elementsFor(id).handlers.change();
  assert.equal(elementsFor("result").textContent, "");
  assert.equal(elementsFor("detail").textContent, "");
  assert.equal(elementsFor("checks").textContent, "");
}
console.log("Verified detached assessment and exchange, rejected modified companions and cleared stale results.");
