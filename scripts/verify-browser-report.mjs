import assert from "node:assert/strict";
import {readFile, readdir} from "node:fs/promises";
import {basename, join} from "node:path";
import vm from "node:vm";
import {webcrypto} from "node:crypto";

const [verifier, output] = process.argv.slice(2);
const html = await readFile(verifier, "utf8");
const content = html.match(/<script>([\s\S]+?)<\/script>/)[1];
const elements = new Map();
const scope = vm.createContext({
  TextDecoder, Uint8Array, atob, crypto: webcrypto,
  document: {getElementById(id) {
    if (!elements.has(id)) elements.set(id, {handlers: {}, addEventListener(event, handler) {
      this.handlers[event] = handler;
    }});
    return elements.get(id);
  }},
});
vm.runInContext(content, scope);
const simulatedFile = (name, bytes) => ({name, size: bytes.length, arrayBuffer: async () => bytes});
const file = async path => simulatedFile(basename(path), await readFile(path));
const key = await file(join(output, "synthetic-issuer.pub"));
for (const [folder, expected] of [["assessment", "## support"], ["exchange", "PASS · OPEN_ITEMS"]]) {
  const directory = join(output, folder);
  const files = await Promise.all((await readdir(directory)).map(name => file(join(directory, name))));
  assert.ok((await scope.verifyBundle(files, key)).includes(expected));
  const filename = folder === "assessment" ? "summary.md" : "erasure-evidence.json";
  const changed = files.map(input => input.name === filename ? simulatedFile(filename, Buffer.from("changed")) : input);
  await assert.rejects(scope.verifyBundle(changed, key), /differs from its signed digest/);
}
for (const id of ["bundle", "key"]) {
  elements.get("result").textContent = "Verified";
  elements.get("detail").textContent = "Old result";
  elements.get(id).handlers.change();
  assert.strictEqual(elements.get("result").textContent, "");
  assert.strictEqual(elements.get("detail").textContent, "");
}
console.log("Web Crypto verified the Cosign assessment and receipt, rejected modified companions and cleared stale results.");
